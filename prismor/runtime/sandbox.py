"""Prismor sandbox: run allowed shell commands under the OS's own sandbox.

The policy engine decides whether a command may run. The sandbox decides what
that command, and every process it starts, can touch while it runs: which
files it can write, which credential stores it can see, and where it can
connect. The kernel enforces it — Seatbelt (``sandbox-exec``) on macOS,
bubblewrap on Linux (``sandbox_native``) — so a package's postinstall script is
held to the same limits as the command the agent typed. Elsewhere the runner
says so and runs unconfined.

Nothing about how the agent is launched changes. Hook-dispatch rewrites each
allowed shell call into ``prismor sandbox run``, with the original command on
fd 3 so it never sits in a process's argv. Every limit comes from the same
``.prismor/policy.yaml``: ``settings.sandbox`` for files and network mode,
``settings.egress`` for which hosts the ``proxy`` network mode lets through.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import shlex
import signal
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from prismor.runtime.sandbox_native import _parents

DEFAULT_SANDBOX_CONFIG: Dict[str, Any] = {
    "enabled": False,
    "mode": "enforce",
    "network": "proxy",
    "workspace_mount": "rw",
    "writable": [],
    "hide": [],
    "direct_ports": [22],
}

_NETWORKS = ("none", "proxy", "open")
# Docker-era network names, still found in compiled modes and older policies.
_LEGACY_NETWORKS = {"allowlist": "proxy", "bridge": "open", "host": "open"}
# Docker-only keys: accepted so old policies still load, otherwise ignored.
LEGACY_KEYS = ("backend", "image", "workdir", "read_only_root", "tmpfs",
               "env_allowlist", "resource_limits")

# A ring is a pre-reviewed (network, workspace_mount) pair. Explicit fields in
# the config still win over the ring's defaults.
_RING_PRESETS: Dict[str, Dict[str, str]] = {
    "0": {"network": "none", "workspace_mount": "ro"},
    "1": {"network": "none", "workspace_mount": "rw"},
    "2": {"network": "proxy", "workspace_mount": "rw"},
    "3": {"network": "open", "workspace_mount": "rw"},
}
_RING_LABELS = {
    "0": "read-only, no network",
    "1": "workspace-write, no network",
    "2": "workspace-write, network through the egress allowlist",
    "3": "workspace-write, open network",
}

# Credential stores no normal build, test or install reads as a file.
# `.env` and `~/.ssh` stay readable by default (dev servers and `git push`
# need them); `settings.sandbox.hide` adds them back per workspace.
_HIDDEN_HOME = (".aws", ".azure", ".config/gcloud", ".kube", ".docker", ".netrc",
                ".pypirc", ".prismor/secrets", ".prismor/receipt_signing_key.pem",
                ".prismor/pause.key", ".prismor/identity.json")
# Writes here would run later outside the sandbox (git hooks, agent and editor
# config, shell startup files) or change Prismor itself. Read-only even when
# they sit inside a writable directory.
# .git/config: core.hooksPath / core.fsmonitor move hook execution out of .git/hooks.
_PROTECTED_ROOT = (".prismor", ".git/hooks", ".git/config", ".claude", ".codex", ".cursor", ".gemini",
                   ".vscode", ".github/hooks", ".mcp.json")
_PROTECTED_HOME = (".prismor", ".ssh", ".gnupg", ".claude", ".codex", ".cursor", ".gemini",
                   ".zshrc", ".zshenv", ".zprofile", ".zlogin", ".bashrc", ".bash_profile",
                   ".profile", ".gitconfig", ".config/git", "Library/LaunchAgents")
# Package-manager caches: installs and builds fail without them.
_WRITABLE_HOME = (".cache", "Library/Caches", ".npm", ".yarn", ".pnpm-store", "Library/pnpm",
                  ".bun/install/cache", ".cargo/registry", ".cargo/git",
                  "go/pkg/mod", ".gradle/caches", ".m2/repository")
# A container daemon runs whatever it is asked to, outside any sandbox.
_DAEMON_SOCKETS = ("/var/run/docker.sock", "~/.docker/run/docker.sock",
                   "~/.colima/default/docker.sock", "~/.orbstack/run/docker.sock")

# Simple `prismor <cmd>` calls run unconfined (through this same install):
# they read and write ~/.prismor, which the sandbox protects. `supplychain`
# and `cloak run` start other programs, so they are not on this list.
_EXEMPT_PRISMOR = frozenset({"status", "check", "query", "session", "doctor", "trail", "egress",
                             "deps", "help", "version", "--version", "-V", "-h", "--help"})
_PURE_CD = re.compile(r"\s*cd(?:\s+[^\s;&|<>`$(){}\\'\"*?]+)?\s*")
_SHELLS = ("bash", "zsh", "sh", "dash", "ksh")
_RUNNER_MODULE = "prismor.runtime.immunity_cli"
_DELIM_RE = r"__PRISMOR_SANDBOX_[0-9a-f]{8}__"


# ── config ─────────────────────────────────────────────────────────────────

def ring_names() -> List[str]:
    return sorted(_RING_PRESETS, key=int)


def ring_label(ring: Optional[str]) -> Optional[str]:
    return _RING_LABELS.get(str(ring)) if ring is not None else None


def effective_config(raw: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """``settings.sandbox`` with defaults, ring presets and legacy names applied."""
    raw = dict(raw or {})
    ring = str(raw["ring"]) if raw.get("ring") is not None else None
    if ring not in _RING_PRESETS:
        ring = None
    cfg: Dict[str, Any] = {**DEFAULT_SANDBOX_CONFIG, **(_RING_PRESETS.get(ring or "", {}))}
    cfg.update({k: v for k, v in raw.items() if k not in LEGACY_KEYS})
    cfg["ring"] = ring
    cfg["enabled"] = bool(cfg.get("enabled"))
    cfg["mode"] = "observe" if str(cfg.get("mode")).lower() == "observe" else "enforce"
    net = str(cfg.get("network") or "proxy").lower()
    net = _LEGACY_NETWORKS.get(net, net)
    cfg["network"] = net if net in _NETWORKS else "none"   # unknown: the strictest
    cfg["workspace_mount"] = "ro" if str(cfg.get("workspace_mount")).lower() == "ro" else "rw"
    for key in ("writable", "hide"):
        cfg[key] = [str(p) for p in cfg.get(key) or [] if isinstance(p, (str, Path)) and str(p)]
    ports = cfg.get("direct_ports")
    cfg["direct_ports"] = [int(p) for p in (ports if isinstance(ports, list) else [])
                           if str(p).isdigit() and 0 < int(p) < 65536]
    cfg["legacy_keys"] = sorted(k for k in raw if k in LEGACY_KEYS)
    return cfg


def enforcing(cfg: Dict[str, Any]) -> bool:
    return bool(cfg.get("enabled")) and cfg.get("mode") == "enforce"


def supported() -> bool:
    """macOS (Seatbelt) and Linux (bubblewrap): elsewhere the hook does not rewrite at all."""
    return sys.platform == "darwin" or sys.platform.startswith("linux")


# ── profile ────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Profile:
    """What one sandboxed command may touch. Paths are real (symlinks resolved)."""
    writable: Tuple[str, ...]
    protected: Tuple[str, ...]   # never writable, even inside a writable path
    hidden: Tuple[str, ...]      # neither readable nor writable
    sockets: Tuple[str, ...]     # unix sockets the command may not connect to
    network: str                 # none | proxy | open
    direct_ports: Tuple[int, ...]
    parents: Tuple[str, ...] = ()  # dirs above a protected path: no rename or rmdir


def _real(path: Any) -> str:
    return os.path.realpath(os.path.expanduser(str(path)))


def _uniq(paths: Iterable[str]) -> Tuple[str, ...]:
    return tuple(dict.fromkeys(p for p in paths if p and p != "/"))


def _tmp_dirs() -> List[str]:
    dirs = ["/private/tmp", "/private/var/folders"]
    if os.environ.get("TMPDIR"):
        dirs.append(_real(os.environ["TMPDIR"]))
    return dirs


def _secrets_dir() -> str:
    try:
        from prismor.runtime.cloaking.secrets_store import secrets_dir
        return _real(secrets_dir())
    except Exception:
        return _real("~/.prismor/secrets")


def build_profile(config: Dict[str, Any], root: Path, *, home: Optional[Path] = None) -> Profile:
    cfg = effective_config(config)
    home = Path(home or Path.home())
    root_s = _real(root)

    def _at(base: str, rel: str) -> str:
        return _real(rel if rel.startswith(("/", "~")) else os.path.join(base, rel))

    writable = _tmp_dirs()
    if cfg["workspace_mount"] == "rw":
        writable += [root_s] + [_real(home / p) for p in _WRITABLE_HOME]
    writable += [_at(root_s, p) for p in cfg["writable"]]
    rels = _protected_rels(root_s)
    protected = [_real(os.path.join(root_s, p)) for p in rels]
    protected += [_real(home / p) for p in _PROTECTED_HOME]
    hidden = [_real(home / p) for p in _HIDDEN_HOME] + [_secrets_dir()]
    hidden += [_at(root_s, p) for p in cfg["hide"]]
    sockets = [_real(s.replace("~", str(home), 1)) for s in _DAEMON_SOCKETS]
    return Profile(writable=_uniq(writable), protected=_uniq(protected), hidden=_uniq(hidden),
                   sockets=_uniq(sockets), network=cfg["network"],
                   direct_ports=tuple(cfg["direct_ports"]),
                   parents=_uniq(_real(d) for d in _parents(root_s, rels)))


def _protected_rels(root_s: str) -> List[str]:
    # ponytail: before `git init`, .git/* is left open so init can write it; a
    # repo created inside the run can carry hooks. Guard it at init when that matters.
    has_git = os.path.isdir(os.path.join(root_s, ".git"))
    return [r for r in _PROTECTED_ROOT if has_git or not r.startswith(".git/")]


def _sb(path: str) -> str:
    return '"' + path.replace("\\", "\\\\").replace('"', '\\"') + '"'


def seatbelt_profile(p: Profile) -> str:
    """The SBPL text for ``sandbox-exec -p``. Later rules override earlier ones."""
    out = ["(version 1)", "(allow default)", "(deny file-write*)",
           "(allow file-write* (subpath \"/dev\")" + "".join(f" (subpath {_sb(w)})" for w in p.writable) + ")"]
    if p.protected:
        out.append("(deny file-write*" + "".join(f" (subpath {_sb(x)})" for x in p.protected) + ")")
    if p.parents:
        # `mv .git .g; edit .g/hooks; mv .g .git` moves a protected path away
        # from the name above. unlink covers rename and rmdir of the dir node.
        out.append("(deny file-write-unlink" + "".join(f" (literal {_sb(x)})" for x in p.parents) + ")")
    if p.hidden:
        out.append("(deny file-read* file-write*" + "".join(f" (subpath {_sb(h)})" for h in p.hidden) + ")")
    if p.network != "open":
        out.append("(deny network*)")
    if p.network == "proxy":
        out += ['(allow network-outbound (remote ip "localhost:*"))',
                '(allow network-bind network-inbound (local ip "*:*"))',
                "(allow network-outbound (remote unix-socket))"]
        out += [f'(allow network-outbound (remote tcp "*:{port}"))' for port in p.direct_ports]
    if p.network != "none" and p.sockets:
        out.append("(deny network-outbound"
                   + "".join(f" (remote unix-socket (path-literal {_sb(s)}))" for s in p.sockets) + ")")
    return "\n".join(out) + "\n"


# ── engine ─────────────────────────────────────────────────────────────────

_SANDBOX_EXEC = "/usr/bin/sandbox-exec"


@lru_cache(maxsize=1)
def backend_status() -> Dict[str, Any]:
    """Whether Seatbelt can start here."""
    if not supported():
        return {"available": False, "engine": None,
                "error": f"macOS and Linux only, this host runs {sys.platform}"}
    if sys.platform != "darwin":
        from prismor.runtime import sandbox_native
        st = sandbox_native.status()
        return {"available": bool(st.get("ready")), "engine": "bubblewrap",
                "path": st.get("path"), "error": st.get("error")}
    if not os.path.exists(_SANDBOX_EXEC):
        return {"available": False, "engine": "seatbelt", "error": "sandbox-exec not found"}
    try:
        r = subprocess.run([_SANDBOX_EXEC, "-p", "(version 1)(allow default)", "/usr/bin/true"],
                           capture_output=True, text=True, timeout=5, check=False)
        err = None if r.returncode == 0 else ((r.stderr or r.stdout).strip() or f"exit {r.returncode}")
    except (OSError, subprocess.TimeoutExpired) as exc:
        err = str(exc)
    return {"available": err is None, "engine": "seatbelt", "path": _SANDBOX_EXEC, "error": err}


def _inside_sandbox() -> bool:
    """True when this process already runs under a Seatbelt sandbox (ours or an agent's)."""
    if not supported():
        return False
    try:
        import ctypes
        check = ctypes.CDLL("/usr/lib/libSystem.B.dylib").sandbox_check
        check.restype = ctypes.c_int
        check.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int]
        return check(os.getpid(), None, 0) == 1
    except Exception:
        return False


def _shell() -> str:
    sh = os.environ.get("SHELL") or ""
    if os.path.basename(sh) in _SHELLS and os.access(sh, os.X_OK):
        return sh
    return "/bin/bash" if os.path.exists("/bin/bash") else "/bin/sh"


def _command_fd(command: str) -> int:
    """An inheritable fd holding ``command``: a pipe, or an unlinked temp file if large."""
    data = command.encode("utf-8")
    if len(data) <= 8192:
        r, w = os.pipe()
        os.write(w, data)
        os.close(w)
        fd = r
    else:
        fd, path = tempfile.mkstemp(prefix="prismor-sandbox-")
        os.unlink(path)
        os.write(fd, data)
        os.lseek(fd, 0, os.SEEK_SET)
    os.set_inheritable(fd, True)
    return fd


def _shim(fd: int) -> str:
    # The command reaches the shell through a file descriptor, never argv, so
    # a resolved secret is not visible to `ps` from inside the sandbox. The
    # trailing newline lets a final heredoc delimiter or `\` line end cleanly.
    return f'__prismor_c=$(/bin/cat <&{fd}); exec {fd}<&-; eval "$__prismor_c\n"'


def is_exempt(command: str) -> bool:
    """A bare `prismor <read-only subcommand>` — no shell syntax, no other program."""
    text = command.strip()
    if not text or any(c in text for c in "\n`$\\"):
        return False
    try:
        lex = shlex.shlex(text, posix=True, punctuation_chars=True)
        lex.whitespace_split = True
        words = list(lex)
    except ValueError:
        return False
    if any(w and all(c in "();<>|&" for c in w) for w in words):
        return False
    return bool(words) and words[0] == "prismor" and (len(words) == 1 or words[1] in _EXEMPT_PRISMOR)


# ── run ────────────────────────────────────────────────────────────────────

def _note(text: str) -> None:
    sys.stderr.write(f"[prismor] sandbox: {text}\n")
    sys.stderr.flush()


def _windows_bash() -> Optional[str]:
    """Git Bash, which runs agents' Bash commands on Windows. System32\\bash.exe is the WSL launcher."""
    import shutil
    bash = os.environ.get("CLAUDE_CODE_GIT_BASH_PATH") or shutil.which("bash")
    if bash and "system32" not in bash.lower() and os.path.exists(bash):
        return bash
    git = shutil.which("git")  # ...\Git\cmd\git.exe -> ...\Git\bin\bash.exe
    if git:
        cand = os.path.join(os.path.dirname(os.path.dirname(git)), "bin", "bash.exe")
        if os.path.exists(cand):
            return cand
    return None


def _exec_unconfined(command: str) -> int:
    if is_exempt(command):
        argv: Optional[List[str]] = [sys.executable, "-m", _RUNNER_MODULE] + shlex.split(command)[1:]
    elif sys.platform == "win32":
        bash = _windows_bash()
        argv = [bash, "-c", command] if bash else None
    else:
        argv = [_shell(), "-c", command]
    if sys.platform == "win32":
        # No POSIX shell path and no real exec here: os.execv spawns a child and
        # exits without its exit code. Run it and pass the code through.
        if argv is None:
            return subprocess.call(command, shell=True)  # nosec B602 - the agent's own allowed command, as typed
        return subprocess.call(argv)
    os.execv(argv[0], argv)
    return 127  # pragma: no cover - execv does not return


def read_command_fd(fd: int = 3) -> str:
    """The command the hook rewrite passed as a heredoc on ``fd``."""
    try:
        with os.fdopen(fd, "r", encoding="utf-8") as f:
            text = f.read()
    except OSError:
        return ""
    return text[:-1] if text.endswith("\n") else text


def run(command: str, *, root: Path, config: Dict[str, Any], engine: Any = None,
        wait: bool = False) -> int:
    """Run ``command`` under the sandbox ``config`` describes and return its exit code.

    Without a proxy to keep alive this process becomes the sandbox (exec), unless
    ``wait`` asks for the exit code back.
    """
    if is_exempt(command) or _inside_sandbox():
        return _exec_unconfined(command)
    status = backend_status()
    if not status["available"]:
        # Containment is a layer on top of policy. Every rule has already run on
        # this command, so a missing engine means "not contained", not "not
        # screened" — refusing here would stop every shell command on the host.
        _note(f"not available here ({status.get('error')}); running unconfined. Policy still applies.")
        return _exec_unconfined(command)

    if sys.platform != "darwin":
        return _run_bwrap(command, root, config)
    profile = build_profile(config, root)
    fd = _command_fd(command)
    argv = [status["path"], "-p", seatbelt_profile(profile), _shell(), "-c", _shim(fd)]
    env = dict(os.environ, PRISMOR_SANDBOX="1")

    if profile.network != "proxy" and not wait:
        os.execve(argv[0], argv, env)

    proxy = None
    if profile.network == "proxy":
        from prismor.runtime.sandbox_proxy import EgressProxy
        proxy = EgressProxy.for_engine(engine, log=_note)
        env.update(proxy.env())
    try:
        child = subprocess.Popen(argv, env=env, pass_fds=(fd,))
    except OSError as exc:
        if proxy:
            proxy.close()
        _note(f"could not start ({exc}); running unconfined. Policy still applies.")
        return _exec_unconfined(command)
    os.close(fd)
    signal.signal(signal.SIGINT, signal.SIG_IGN)   # the child handles ^C itself
    for sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, lambda s, _f: child.send_signal(s))
    try:
        return child.wait()
    finally:
        if proxy:
            proxy.close()


_BWRAP_NETWORK = {"none": "none", "proxy": "allowlist", "open": "bridge"}


def _run_bwrap(command: str, root: Path, config: Dict[str, Any]) -> int:
    """Linux: the same limits, enforced by bubblewrap in ``sandbox_native``.

    ponytail: egress is screened by sandbox_native's per-host policy check, not
    the egress allowlist the macOS proxy reads, and ``direct_ports`` have no
    effect (the network namespace has loopback only). Unify the proxies when
    the two need to agree host for host.
    """
    from prismor.runtime import sandbox_native
    cfg = effective_config(config)
    root_s = _real(root)

    def _at(rel: str) -> str:
        return _real(rel if rel.startswith(("/", "~")) else os.path.join(root_s, rel))

    native = {"mode": cfg["mode"], "workspace_mount": cfg["workspace_mount"],
              "protect": _protected_rels(root_s),
              "network": _BWRAP_NETWORK[cfg["network"]],
              "allow_write": [_at(p) for p in cfg["writable"]],
              # daemon sockets: a bind of /dev/null over one stops connect()
              "deny_read": ([_real(Path.home() / p) for p in _HIDDEN_HOME] + [_secrets_dir()]
                            + [_real(s) for s in _DAEMON_SOCKETS] + [_at(p) for p in cfg["hide"]])}
    return sandbox_native.run(command, workspace=root, cfg=native)


# ── hook rewrite ───────────────────────────────────────────────────────────

def project_root(payload: Dict[str, Any], fallback: Path) -> Path:
    """The git root above the agent's cwd (or the cwd), else ``fallback``."""
    cwd = payload.get("cwd") if isinstance(payload, dict) else None
    if not isinstance(cwd, str) or not cwd:
        return Path(fallback)
    here = Path(cwd)
    for d in (here, *here.parents):
        if (d / ".git").exists():
            return d
    return here


def runner(root: Path) -> str:
    """The shell words that start ``prismor sandbox run`` for ``root``."""
    return (f"{shlex.quote(sys.executable)} -m {_RUNNER_MODULE} sandbox "
            f"--workspace {shlex.quote(str(root))} run")


def wrap_command(command: str, root: Path) -> str:
    """``command`` as a heredoc on fd 3 of the sandbox runner. Readable, nothing encoded."""
    delim = f"__PRISMOR_SANDBOX_{secrets.token_hex(4)}__"
    while delim in command:
        delim = f"__PRISMOR_SANDBOX_{secrets.token_hex(4)}__"
    return f"{runner(root)} 3<<'{delim}'\n{command}\n{delim}"


def unwrap_command(command: str) -> str:
    """The agent's command, if ``command`` is this install's sandbox rewrite of it.

    Only this interpreter's runner is recognised: a look-alike that starts a
    different program comes back unchanged and is judged as written.
    """
    head = f"{shlex.quote(sys.executable)} -m {_RUNNER_MODULE} sandbox --workspace "
    if not command or not command.startswith(head):
        return command
    m = re.match(r"(?:'[^']*'|[^\s'])+ run 3<<'(" + _DELIM_RE + r")'\n(.*)\n\1\s*\Z",
                 command[len(head):], re.S)
    return m.group(2) if m else command


def claude_updated_input(payload: Dict[str, Any], *, root: Path) -> Optional[Dict[str, Any]]:
    """Claude hook JSON that runs this Bash call under the sandbox."""
    if payload.get("tool_name") != "Bash" or not isinstance(payload.get("tool_input"), dict):
        return None
    command = str(payload["tool_input"].get("command") or "")
    if not command.strip() or _PURE_CD.fullmatch(command):
        return None   # a bare `cd` touches nothing, and must change the tool shell's cwd
    new_input = dict(payload["tool_input"], command=wrap_command(command, root))
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "updatedInput": new_input}}


# ── cloak hand-off ─────────────────────────────────────────────────────────
#
# Claude Code runs PreToolUse hooks in parallel, and when two of them rewrite
# the same call the one that finishes last wins. The cloak hook (decloak.sh)
# rewrites every Bash call once a secret is registered, so a second rewrite
# here would randomly drop either the sandbox or the output scrubbing. When
# decloak.sh is installed it does the sandbox wrap too, from this index, and
# puts the runner INSIDE its scrub wrapper: placeholders resolve and output is
# scrubbed outside the sandbox, where the vault is readable.

def _index_path() -> Path:
    return Path(os.environ.get("PRISMOR_HOME") or Path.home() / ".prismor") / "sandbox" / "active.tsv"


def _settings_files(project: str) -> List[Path]:
    return [Path.home() / ".claude" / "settings.json",
            Path(project) / ".claude" / "settings.json",
            Path(project) / ".claude" / "settings.local.json"]


def decloak_wraps(project: str) -> bool:
    """Whether a decloak.sh that knows the sandbox index is installed for ``project``."""
    for path in _settings_files(project):
        try:
            hooks = json.loads(path.read_text(encoding="utf-8")).get("hooks") or {}
        except (OSError, ValueError, AttributeError):
            continue
        for entry in hooks.get("PreToolUse") or []:
            for hook in (entry or {}).get("hooks") or []:
                cmd = str((hook or {}).get("command") or "")
                if "decloak.sh" not in cmd:
                    continue
                script = cmd.strip().strip('"').strip("'")
                try:
                    if "sandbox/active.tsv" in Path(script).read_text(encoding="utf-8"):
                        return True
                except OSError:
                    continue
    return False


def set_index_entry(project: str, runner_cmd: Optional[str]) -> None:
    """Record (or with None, drop) the runner decloak.sh should use for ``project``."""
    if not project or any(c in project + (runner_cmd or "") for c in "\t\n"):
        return
    path = _index_path()
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        lines = []
    keep = [ln for ln in lines if ln.split("\t", 1)[0] != project]
    if runner_cmd:
        keep.append(f"{project}\t{runner_cmd}")
    if keep == lines:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(f".{os.getpid()}.tmp")
    tmp.write_text("".join(f"{ln}\n" for ln in keep), encoding="utf-8")
    os.replace(tmp, path)


def hand_off_to_decloak(root: Path, active: bool) -> bool:
    """Keep the index in step with policy; True when decloak.sh will do the wrap."""
    project = os.environ.get("CLAUDE_PROJECT_DIR") or ""
    owns = bool(active and project and decloak_wraps(project))
    set_index_entry(project, runner(root) if owns else None)
    return owns


# ── CLI helpers ────────────────────────────────────────────────────────────

def set_enabled(workspace: Path, enabled: bool) -> Path:
    """Flip ``settings.sandbox.enabled`` (and to enforce, on ``on``) in place.

    Only those fields are touched, so the ring, network and paths a mode or a
    person chose survive an off/on round trip.
    """
    from prismor.runtime.egress_cli import _load_policy_file, _policy_path, _save_policy_file

    data = _load_policy_file(workspace)
    settings = data.get("settings")
    if not isinstance(settings, dict):
        settings = data["settings"] = {}
    block = settings.get("sandbox")
    if not isinstance(block, dict):
        block = settings["sandbox"] = {}
    block["enabled"] = bool(enabled)
    if enabled:
        block["mode"] = "enforce"
    _save_policy_file(workspace, data)
    return _policy_path(workspace)


def status_report(config: Dict[str, Any], *, egress_enabled: bool = False) -> Dict[str, Any]:
    cfg = effective_config(config)
    engine = backend_status()
    on = engine["available"]
    net = cfg["network"]
    net_state = "open" if net == "open" else ("enforced" if on else "unavailable")
    return {
        "enabled": cfg["enabled"],
        "mode": cfg["mode"],
        "ring": cfg["ring"],
        "ring_label": ring_label(cfg["ring"]),
        "network": net,
        "workspace_mount": cfg["workspace_mount"],
        "writable": cfg["writable"],
        "hide": cfg["hide"],
        "direct_ports": cfg["direct_ports"] if net == "proxy" else [],
        "engine": engine,
        "controls": {
            "files": "enforced" if on else "unavailable",
            "credentials": "enforced" if on else "unavailable",
            "network": net_state,
        },
        "egress_allowlist": bool(egress_enabled),
        "legacy_keys": cfg["legacy_keys"],
    }


def describe(cfg: Dict[str, Any]) -> str:
    """One line for `mode show` and `sandbox try`."""
    cfg = effective_config(cfg)
    writes = "tmp only" if cfg["workspace_mount"] == "ro" else "project, tmp, package caches"
    net = {"none": "no network", "proxy": "network through the egress allowlist",
           "open": "open network"}[cfg["network"]]
    return f"writes: {writes} · credential stores hidden · {net}"
