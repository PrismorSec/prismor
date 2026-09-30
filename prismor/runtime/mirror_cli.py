"""`prismor mirror` — turn the mirrored built-ins on and off, and see what
state they are in.

Subcommands:
    on  [--mode enforce|observe]
        Register the mirror as an MCP server for Claude Code and disable the
        native tools it replaces (Bash/Read/Write/Edit/Glob/Grep, plus the other
        file-writers MultiEdit/NotebookEdit). Takes effect on the next session.
    off
        Undo exactly what `on` did: remove the server entry, remove the deny
        entries it added (nothing else in the file is touched), and hand the
        built-ins back to the agent. Takes effect on the next session.
    status
        Where the mirror is configured, whether it is governing, passing
        through or paused, its tool roster, and any live gateway processes.
    passthrough on|off
        Runtime switch (no restart): `on` makes the mirror execute its tools
        exactly as the natives would — no blocks, no redaction — while still
        logging. Same switch as the dashboard's mirror card. Prefer
        `prismor pause` for "stop interfering for a while": it covers hooks and
        the gateway together and auto-resumes.

Why a dedicated command
-----------------------
The first live deployment of the mirror was wired by hand: a deny-list added
to `.claude/settings.json`, a server added to `.mcp.json`, and the same again
in Claude Desktop. When the mirror then blocked something the human wanted, the
only ways out were `prismor pause` (which the gateway did not honour at the
time) or editing those files back — from inside a session whose own tool calls
were being screened by the very rules that forbid editing them. The escape
hatch has to be a command the human runs from their own terminal, and it has
to know precisely what to undo. That is this module.

Everything here rewrites config files the developer owns, so the rules are:
never touch a key we did not add, back up before the first write, refuse
rather than guess on an unrecognised shape.
"""
from __future__ import annotations

import ast
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from prismor.runtime import mirror

#: Agents `prismor mirror on` can wire up end to end today. The gateway itself
#: is host-agnostic, so this is a statement about the CONFIG wiring only — and
#: about what has been verified by driving a real session, since a half-wired
#: host leaves the agent with no tools at all. `prismor setup` reads this to
#: decide which agents may be offered the mirror as a choice.
INSTALLABLE_AGENTS: Tuple[str, ...] = ("claude", "codex", "opencode", "claude-desktop")

# ── output helpers (match cli.py's ANSI style, no deps) ──────────────────────
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[37m"
_RED = "\033[0;31m"
_GREEN = "\033[0;32m"
_YELLOW = "\033[1;33m"


def _c(text: str, color: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"{color}{text}{_RESET}"


# ── where things live ────────────────────────────────────────────────────────

def _claude_paths(workspace: Path) -> Tuple[Path, Path, str]:
    """(mcp config path, settings path, top-level key holding the server block).

    Project scope only, deliberately. A machine-wide or agent-wide mirror is the
    control plane's job — the console already pushes device mode, agent kill
    switches and pause that way, and those decisions belong to whoever
    administers the fleet, not to a CLI run inside one checkout. That leaves
    this command with exactly one honest scope: the project you are standing in.

    There is also a mechanical reason not to offer a user scope here: the
    user-level MCP config lives in ``~/.claude.json``, which the running host
    owns and rewrites wholesale — an edit made there was silently clobbered by
    the next ``claude`` invocation during testing.
    """
    return workspace / ".mcp.json", workspace / ".claude" / "settings.json", "mcpServers"


def _local_settings_path(workspace: Path) -> Path:
    """The human's own, machine-local settings for this project — where Claude
    Code records which of the project's declared MCP servers they trust.
    Gitignored by convention, which is what makes it the right place: the
    approval is this person's, on this machine, not something the repo carries."""
    return Path(workspace) / ".claude" / "settings.local.json"


def _approve_project_server(workspace: Path, server: str) -> Tuple[bool, str]:
    """Record that ``server`` is approved for ``workspace``.

    A server declared in a project's ``.mcp.json`` does not load until a human
    approves it — and, deliberately, a project file cannot vouch for itself, so
    putting ``enableAllProjectMcpServers`` in the shared ``settings.json`` does
    nothing. Without this step `on` is a trap: the native tools are denied
    immediately (the deny-list IS honoured from shared settings) while their
    replacement never loads, and the agent starts with no file or shell tools
    and no explanation. Verified on a real Claude Code 2.1.210 session: with
    the approval the mirror reports ``connected`` and serves all six built-ins;
    without it the model opens by asking the user to grant filesystem
    permissions it can never be granted.

    Written as ``enabledMcpjsonServers: [server]`` — this one server — never
    ``enableAllProjectMcpServers``, which would auto-trust every server any
    repo in this project declares.

    Note this does NOT touch ``~/.claude.json``. That file is owned by the
    running host, which rewrites it wholesale; an edit there is silently
    clobbered by the next ``claude`` invocation (observed).
    """
    path = _local_settings_path(workspace)
    try:
        data = _load_json(path)
    except Exception as exc:
        return False, f"could not read {path}: {exc}"
    disabled = data.get("disabledMcpjsonServers")
    if isinstance(disabled, list) and server in disabled:
        # An explicit "no" from the human outranks us; say so rather than
        # silently flipping their decision.
        return False, f"{server} is in disabledMcpjsonServers in {path.name} — remove it there first"
    enabled = data.get("enabledMcpjsonServers")
    if not isinstance(enabled, list):
        enabled = []
    if server in enabled:
        return True, "already approved"
    _backup_once(path)
    data["enabledMcpjsonServers"] = enabled + [server]
    try:
        _write_json(path, data)
    except Exception as exc:
        return False, f"could not write {path}: {exc}"
    return True, "approved"


def _unapprove_project_server(workspace: Path, server: str) -> bool:
    """Drop the approval `on` added. Returns True if something changed."""
    path = _local_settings_path(workspace)
    try:
        data = _load_json(path)
    except Exception:
        return False
    enabled = data.get("enabledMcpjsonServers")
    if not isinstance(enabled, list) or server not in enabled:
        return False
    rest = [x for x in enabled if x != server]
    if rest:
        data["enabledMcpjsonServers"] = rest
    else:
        data.pop("enabledMcpjsonServers", None)
    try:
        if data:
            _write_json(path, data)
        elif path.exists():
            path.unlink()  # we created it and it is now empty
    except Exception:
        return False
    return True


def _record_path(workspace: Path) -> Path:
    """The install record, alongside the roster/override config."""
    return workspace / ".prismor" / "mirror.json"


def _load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a JSON object at the top level")
    return data


def _write_json(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def _backup_once(path: Path) -> Optional[Path]:
    """Keep the pre-mirror original alongside, once. A second `on` must not
    overwrite the backup with an already-modified file."""
    if not path.exists():
        return None
    bak = Path(str(path) + ".pre-mirror.bak")
    if not bak.exists():
        bak.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
    return bak


def _read_record(workspace: Path) -> Optional[Dict[str, Any]]:
    try:
        data = _load_json(_record_path(workspace))
    except Exception:
        return None
    rec = data.get("install")
    return rec if isinstance(rec, dict) else None


def _write_record(workspace: Path, rec: Optional[Dict[str, Any]]) -> None:
    path = _record_path(workspace)
    try:
        data = _load_json(path)
    except Exception:
        data = {}
    if rec is None:
        if "install" not in data:
            return  # nothing to remove; do not create an empty file
        data.pop("install", None)
    else:
        data["install"] = rec
    _write_json(path, data)


# ── the server entry ─────────────────────────────────────────────────────────

def _server_entry(workspace: Path, mode: str) -> Dict[str, Any]:
    """The MCP server block for the mirror.

    Same shape as the hook dispatcher (`hooks._dispatcher_command`): the current
    interpreter, `-m`, PYTHONPATH pinned to this install. The `prismor` console
    script is not assumed to be on PATH inside the agent's launch environment,
    and a pipx-installed `prismor` may not even be the one that owns this code.
    Project scope pins `--workspace` so policy resolves to this project no
    matter what cwd the host launches the server with; user scope leaves it to
    the gateway's cwd inference, since one entry serves every project.
    """
    repo_root = Path(mirror.__file__).resolve().parent.parent.parent
    args = ["-m", "prismor.runtime.immunity_cli", "mcp-gateway", "--mirror",
            "--mode", mode]
    args += ["--workspace", str(workspace)]
    env = {"PYTHONPATH": str(repo_root)}
    # Pin a relocated Prismor home into the entry: otherwise the pause marker
    # the gateway consults would not be the one `prismor pause` writes, and the
    # already-screened marker would not be the one hook-dispatch reads (every
    # mirrored call screened and logged twice). See store.relocated_home_env.
    from prismor.runtime.store import relocated_home_env
    env.update(relocated_home_env())
    return {
        "command": sys.executable or "python3",
        "args": args,
        "env": env,
    }


def _preflight(entry: Dict[str, Any], timeout: float = 25.0) -> Tuple[bool, str]:
    """Actually start the server and ask it for its tools before we rely on it.

    `on` denies the host's native Bash/Read/Write. If the server it points at
    cannot start — wrong interpreter, PYTHONPATH that does not resolve, a
    syntax error in a half-installed checkout — the agent boots with no file or
    shell tools at all and no explanation, which is a far worse failure than
    not installing. So we speak the handshake ourselves first and only write
    the deny-list once a real tools/list has come back.
    """
    import subprocess
    env = dict(os.environ, **{k: str(v) for k, v in (entry.get("env") or {}).items()})
    env.pop("PRISMOR_WORKSPACE", None)
    try:
        proc = subprocess.Popen(
            [entry["command"], *entry["args"]],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=env, text=True, bufsize=1)
    except OSError as exc:
        return False, f"cannot run {entry['command']}: {exc}"
    try:
        hello = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                 "params": {"protocolVersion": "2025-03-26", "capabilities": {},
                            "clientInfo": {"name": "prismor-preflight", "version": "1"}}}
        stdin = "\n".join([json.dumps(hello),
                           json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
                           json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})]) + "\n"
        out, err = proc.communicate(stdin, timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        return False, f"server did not answer tools/list within {timeout:.0f}s"
    except Exception as exc:
        proc.kill()
        return False, str(exc)
    for line in out.splitlines():
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        if msg.get("id") == 2 and isinstance(msg.get("result"), dict):
            names = [t.get("name") for t in msg["result"].get("tools") or []]
            served = [n for n in names if n in mirror.mirror_tool_names()]
            if served:
                return True, ", ".join(served)
            return False, "server started but serves none of the mirrored built-ins"
    tail = " / ".join([l for l in (err or "").splitlines() if l.strip()][-2:])
    return False, tail or "server exited without answering tools/list"


def _shim_pythonpath(cmd: str) -> str:
    """The sys.path entry a hook-dispatch shim inserts, or "" if unreadable."""
    import re
    # Quoted form first: the installer always quotes the shim, and the path
    # routinely contains a space (%USERPROFILE% often does).
    m = re.search(r'"([^"]*hook-dispatch\.py)"', cmd) or re.search(r'(\S*hook-dispatch\.py)', cmd)
    if not m:
        return ""
    try:
        text = Path(m.group(1)).read_text(encoding="utf-8")
    except OSError:
        return ""
    ins = re.search(r"sys\.path\.insert\(0,\s*(.+?)\)\s*$", text, re.M)
    if not ins:
        return ""
    try:
        # The shim writes a repr, so Windows paths arrive backslash-escaped.
        return str(ast.literal_eval(ins.group(1)))
    except (ValueError, SyntaxError):
        return ""


def _hook_installs(workspace: Path) -> List[Tuple[Path, str, str]]:
    """(settings file, PYTHONPATH, PRISMOR_HOME) for every Prismor hook wired
    into Claude Code that could screen this workspace's calls."""
    import re
    out: List[Tuple[Path, str, str]] = []
    home = Path.home()
    for path in (home / ".claude" / "settings.json",
                 home / ".claude" / "settings.local.json",
                 Path(workspace) / ".claude" / "settings.json",
                 Path(workspace) / ".claude" / "settings.local.json"):
        try:
            data = _load_json(path)
        except Exception:
            continue
        hooks = data.get("hooks")
        if not isinstance(hooks, dict):
            continue
        for entries in hooks.values():
            for entry in entries if isinstance(entries, list) else []:
                for hook in (entry.get("hooks") or []) if isinstance(entry, dict) else []:
                    cmd = str(hook.get("command") or "")
                    if "hook-dispatch" not in cmd:
                        continue
                    pp = re.search(r'PYTHONPATH="?([^"\s]+)"?', cmd)
                    ph = re.search(r'PRISMOR_HOME="?([^"\s]+)"?', cmd)
                    # Current installs point at a generated shim instead of
                    # carrying a PYTHONPATH= prefix (the prefix is not valid on
                    # cmd.exe). The path it inserts lives inside that file.
                    pythonpath = pp.group(1) if pp else _shim_pythonpath(cmd)
                    rec = (path, pythonpath, ph.group(1) if ph else "")
                    if rec not in out:
                        out.append(rec)
    return out


def _package_dir(pythonpath: str) -> Optional[Path]:
    """Where the ``prismor`` package actually lives for a given PYTHONPATH.

    The same installation is spelled two ways in the wild: the hook installer
    writes the directory CONTAINING the package for a source checkout, but an
    older installed build wrote the package directory itself
    (``.../site-packages/prismor``). Comparing the raw strings reports every
    ordinary pipx install as a version mismatch — a warning that always fires
    is one nobody reads, so resolve both to the package and compare that.
    """
    if not pythonpath:
        return None
    try:
        base = Path(pythonpath).expanduser().resolve()
    except OSError:
        return None
    # `base` first: an installed tree can contain a nested prismor/prismor/
    # (a real packaging artifact on this machine), so checking base/"prismor"
    # first resolves .../site-packages/prismor to .../site-packages/prismor/
    # prismor and reports a mismatch against itself.
    for candidate in (base, base / "prismor"):
        if (candidate / "runtime").is_dir():
            return candidate
    return base


def _coherence_warnings(workspace: Path, entry: Dict[str, Any]) -> List[str]:
    """Flag a split-brain install: the hook layer running a DIFFERENT Prismor
    than the one behind the mirror.

    Both layers see a mirrored call — the gateway as ``Bash``, the hook as
    ``mcp__prismor-tools__Bash`` — and they only stay consistent because they
    share code: the gateway drops a marker the hook reads (so the call is
    screened once, not twice), and the hook maps the mirrored name back to its
    native tag (so a session scope judges it as the tool it really is). Point
    them at two different checkouts and both agreements break: the same call is
    screened twice, a session scope denies the MCP-shaped name the gateway just
    allowed, and the agent is stuck behind one layer's block that the other
    layer's `prismor pause` does not lift.

    Observed on a real box: a stale hook checkout with no mirror.py and no
    native-alias mapping denied every mirrored Bash/Read/Glob with "not in
    scope for this session" while the gateway was allowing them — the agent
    gave up and asked the human for filesystem permissions it could not be
    granted.
    """
    warnings: List[str] = []
    pad = "\n            "
    mirror_path = str((entry.get("env") or {}).get("PYTHONPATH") or "")
    mirror_home = str((entry.get("env") or {}).get("PRISMOR_HOME")
                      or os.environ.get("PRISMOR_HOME")
                      or (Path.home() / ".prismor"))
    for path, hook_pp, hook_home in _hook_installs(workspace):
        hook_pkg, mirror_pkg = _package_dir(hook_pp), _package_dir(mirror_path)
        if hook_pkg and mirror_pkg and hook_pkg != mirror_pkg:
            warnings.append(
                "the Claude Code hook in {p} runs Prismor from{pad}  {a}{pad}"
                "but the mirror serves from{pad}  {b}{pad}"
                "Two versions screening one call can disagree — a scope that denies{pad}"
                "mcp__{srv}__Bash while the gateway allows Bash leaves the agent stuck,{pad}"
                "and `prismor pause` may reach only one of them.{pad}"
                "Fix: re-run `prismor install-hooks` from this install.".format(
                    p=path, a=hook_pp, b=mirror_path,
                    srv=mirror.MIRROR_SERVER_NAME, pad=pad))
        effective_home = hook_home or str(Path.home() / ".prismor")
        if Path(effective_home) != Path(mirror_home):
            warnings.append(
                "the hook in {p} uses PRISMOR_HOME={a}{pad}"
                "but the mirror uses {b}. They will not share the already-screened{pad}"
                "marker (every mirrored call screened and logged twice) nor the pause{pad}"
                "marker (`prismor pause` reaching only one of them).".format(
                    p=path, a=effective_home, b=mirror_home, pad=pad))
    return warnings


def _effective_allow_entries(workspace: Path) -> List[str]:
    """Every permissions.allow entry that applies to this workspace, across the
    user and project settings files Claude Code merges."""
    out: List[str] = []
    home = Path.home()
    for path in (home / ".claude" / "settings.json",
                 home / ".claude" / "settings.local.json",
                 Path(workspace) / ".claude" / "settings.json",
                 Path(workspace) / ".claude" / "settings.local.json"):
        try:
            data = _load_json(path)
        except Exception:
            continue
        perms = data.get("permissions")
        allow = perms.get("allow") if isinstance(perms, dict) else None
        for item in allow if isinstance(allow, list) else []:
            if str(item) not in out:
                out.append(str(item))
    return out


def _mirrored_allow_entries(workspace: Path, force: bool) -> List[str]:
    """Which mirrored tools to pre-allow, carrying over the human's posture.

    Claude Code gates MCP tools behind the same permission prompt as any other
    tool, and the mirrored built-ins arrive under new names
    (``mcp__prismor-tools__Bash``), so every allow rule the human had for
    ``Bash`` stops applying the moment the mirror is on. Left alone that turns a
    working setup into either six approval prompts or — headless, where nothing
    can prompt — a dead session: observed on a real `claude -p` run, where the
    model reported "Claude requested permissions to use
    mcp__prismor-tools__Bash, but you haven't granted it yet" and gave up.

    So translate, don't grant: a native that was already allowed gets its
    mirrored twin allowed, and a native that was not stays un-allowed and keeps
    prompting exactly as before. The agent's authority is unchanged — the same
    actions, now screened by policy before they run. ``force`` (--allow-tools)
    is for headless installs that need every mirrored tool usable outright.
    """
    existing = _effective_allow_entries(workspace)
    entries: List[str] = []
    for tool in mirror.mirror_tool_names():
        prefixed = f"mcp__{mirror.MIRROR_SERVER_NAME}__{tool}"
        if prefixed in existing:
            continue
        # "Bash" allows the tool outright; "Bash(ls:*)" only allows one pattern
        # and has no meaning once the tool is served over MCP, so it is not
        # carried over — the human keeps their prompt for anything narrower.
        if force or tool in existing:
            entries.append(prefixed)
    return entries


# ── on / off ─────────────────────────────────────────────────────────────────

def _announce_workspace(workspace: Path) -> None:
    """Say which project is about to be rewired, and why it was chosen.

    The CLI resolves the workspace from --workspace, then $PRISMOR_WORKSPACE,
    then cwd. Claude Code exports PRISMOR_WORKSPACE from a project's
    settings.json into every shell it spawns, so `cd /tmp/sandbox && prismor
    mirror on` run from inside such a session silently rewires the REAL project
    — which is how this command locked its own author's session the first time
    it was tried. Printing the source makes that visible before it matters."""
    src = "--workspace"
    try:
        env_ws = os.environ.get("PRISMOR_WORKSPACE")
        cwd = Path.cwd().resolve()
        if workspace.resolve() == cwd:
            src = "current directory"
        elif env_ws and Path(env_ws).resolve() == workspace.resolve():
            src = "$PRISMOR_WORKSPACE — not the current directory; pass --workspace to override"
    except Exception:
        pass
    print(f"  {_c('workspace', _DIM)} {workspace}  {_c('(' + src + ')', _DIM)}")


def mirror_on(workspace: Path, *, mode: str = "enforce",
              agent: str = "claude", allow_tools: bool = False) -> int:
    if agent == "codex":
        _announce_workspace(workspace)
        return mirror_on_codex(workspace, mode=mode)
    if agent == "opencode":
        _announce_workspace(workspace)
        return mirror_on_opencode(workspace, mode=mode)
    if agent == "claude-desktop":
        _announce_workspace(workspace)
        return mirror_on_claude_desktop(workspace, mode=mode)
    if agent not in INSTALLABLE_AGENTS:
        print(_c(f"prismor mirror on: agent '{agent}' is not wired yet.", _RED))
        print(_c(f"  Wired today: {', '.join(INSTALLABLE_AGENTS)}. For anything else, run "
                 "`prismor mcp-gateway --mirror` as an MCP server and disable the host's own "
                 "Bash/Read/Write tools yourself — see docs/governance-surfaces.md.", _DIM))
        return 2
    _announce_workspace(workspace)
    mcp_path, settings_path, key = _claude_paths(workspace)
    existing = _read_record(workspace)
    entry = _server_entry(workspace, mode)

    # 0. Prove the server works BEFORE anything is denied (see _preflight).
    print(f"  {_c('checking', _DIM)}  starting the mirror server once to verify it serves tools...")
    ok, detail = _preflight(entry)
    if not ok:
        print(_c(f"  prismor mirror on: the mirror server failed to start — {detail}", _RED))
        print(_c("  Nothing was changed. The agent keeps its native tools.", _DIM))
        print(_c(f"  Try it by hand:  {entry['command']} {' '.join(entry['args'])}", _DIM))
        return 1
    print(f"  {_c('ok', _GREEN)}        serves: {detail}")
    for warn in _coherence_warnings(workspace, entry):
        print(f"  {_c('warning', _YELLOW)}   {warn}")

    # 1. MCP server entry.
    try:
        mcp = _load_json(mcp_path)
    except Exception as exc:
        print(_c(f"prismor mirror on: cannot read {mcp_path}: {exc}", _RED))
        return 1
    servers = mcp.get(key)
    if servers is None:
        servers = mcp[key] = {}
    if not isinstance(servers, dict):
        print(_c(f"prismor mirror on: {mcp_path} has an unrecognised '{key}' block — not touching it.", _RED))
        return 1
    _backup_once(mcp_path)
    servers[mirror.MIRROR_SERVER_NAME] = entry
    _write_json(mcp_path, mcp)

    # 2. Disable the natives. Only add what is missing, and remember exactly
    #    which entries were ours so `off` removes those and nothing else.
    try:
        settings = _load_json(settings_path)
    except Exception as exc:
        print(_c(f"prismor mirror on: cannot read {settings_path}: {exc}", _RED))
        return 1
    perms = settings.get("permissions")
    if perms is None:
        perms = settings["permissions"] = {}
    if not isinstance(perms, dict):
        print(_c(f"prismor mirror on: {settings_path} has an unrecognised 'permissions' block — not touching it.", _RED))
        return 1
    deny = perms.get("deny")
    if deny is None:
        deny = perms["deny"] = []
    if not isinstance(deny, list):
        print(_c(f"prismor mirror on: {settings_path} permissions.deny is not a list — not touching it.", _RED))
        return 1
    _backup_once(settings_path)
    already = set(str(x) for x in deny)
    added = [t for t in mirror.NATIVE_TOOLS_TO_DISABLE if t not in already]
    deny.extend(added)
    _write_json(settings_path, settings)

    # 2b. Carry the human's existing allow posture onto the new tool names.
    #
    # This goes in settings.local.json, NOT the shared settings.json next to
    # the deny above. A project's shared settings can RESTRICT but cannot
    # GRANT: Claude Code honours a deny from a repo file (a repo may tighten
    # itself) and ignores an allow (a repo may not widen its own authority) —
    # the same asymmetry that makes enableAllProjectMcpServers useless there.
    # Verified the hard way on a live session: with the allow rules in
    # settings.json every mirrored call came back "Claude requested
    # permissions ... but you haven't granted it yet"; moving the identical
    # list to settings.local.json made them run.
    #
    # The split is also the right one to keep: the deny is committed with the
    # project (everyone working here gets the mirror), the grant is per
    # developer, per machine, and gitignored.
    allow_added = _mirrored_allow_entries(workspace, allow_tools)
    if allow_added:
        lpath = _local_settings_path(workspace)
        try:
            local = _load_json(lpath)
        except Exception as exc:
            print(_c(f"prismor mirror on: cannot read {lpath}: {exc}", _RED))
            return 1
        lperms = local.get("permissions")
        if not isinstance(lperms, dict):
            lperms = local["permissions"] = {}
        lallow = lperms.get("allow")
        if not isinstance(lallow, list):
            lallow = lperms["allow"] = []
        lallow.extend(allow_added)
        _backup_once(lpath)
        _write_json(lpath, local)

    # 3. Tell Claude Code this server is approved for this project, or the
    #    host will leave it "Pending approval" and the agent gets no tools.
    approved, approve_note = _approve_project_server(workspace, mirror.MIRROR_SERVER_NAME)
    if not approved:
        print(_c(f"  warning   could not auto-approve the server: {approve_note}", _YELLOW))
        print(_c("            Run `claude` once in this project and approve "
                 f"{mirror.MIRROR_SERVER_NAME}, or the agent starts with no tools.", _DIM))

    # 4. Governing, and the record `off` will need.
    mirror.set_mirror_config(workspace, override=True)
    prior_added = list((existing or {}).get("deny_added") or [])
    _write_record(workspace, {
        "agent": agent, "scope": "project", "mode": mode,
        "server": mirror.MIRROR_SERVER_NAME,
        "mcp_path": str(mcp_path), "settings_path": str(settings_path),
        # Union with a previous install's additions: a re-run must not forget
        # the entries the first run added just because they now pre-exist.
        "deny_added": sorted(set(prior_added) | set(added)),
        "allow_added": sorted(set((existing or {}).get("allow_added") or []) | set(allow_added)),
        "approved_in_claude_state": bool(approved and approve_note == "approved"),
        "at": time.time(),
    })

    print(f"  {_c('Prismor mirror is on', _GREEN)} (this project, {mode} mode)")
    print(f"  {_c('server', _DIM)}    {mcp_path}  →  {mirror.MIRROR_SERVER_NAME}")
    print(f"  {_c('natives', _DIM)}   {settings_path}  →  denied: "
          + ", ".join(mirror.NATIVE_TOOLS_TO_DISABLE))
    if approved:
        print(f"  {_c('approved', _DIM)}  {_local_settings_path(workspace)}  →  "
              f"{mirror.MIRROR_SERVER_NAME} trusted in this project")
    if allow_added:
        print(f"  {_c('allowed', _DIM)}   {_local_settings_path(workspace).name}  →  tool permissions carried over: "
              + ", ".join(a.rsplit("__", 1)[-1] for a in allow_added))
    else:
        print(f"  {_c('note', _DIM)}      the mirrored tools are not pre-allowed — Claude Code will ask "
              f"once per tool.\n            Headless runs cannot answer that: use "
              f"{_c('prismor mirror on --allow-tools', _BOLD)}.")
    print()
    print(f"  {_c('Start a new Claude Code session for it to take effect.', _BOLD)}")
    print(f"  {_c('If it gets in your way:', _DIM)}  prismor pause          (lifts enforcement 24h, no restart)")
    print(f"  {_c('To go back to native tools:', _DIM)}  prismor mirror off     (next session)")
    return 0


def mirror_off(workspace: Path, *, agent: str = "claude") -> int:
    if agent == "codex":
        return mirror_off_codex(workspace)
    if agent == "opencode":
        _announce_workspace(workspace)
        return mirror_off_opencode(workspace)
    if agent == "claude-desktop":
        return mirror_off_claude_desktop(workspace)
    _announce_workspace(workspace)
    done = 0
    for sc in ("project",):
        rec = _read_record(workspace)
        mcp_path, settings_path, key = _claude_paths(workspace)
        # No record: nothing was installed by us at this scope. Still remove a
        # hand-added server entry that names our server, since that is the
        # obvious intent — but never guess at deny entries.
        server = (rec or {}).get("server") or mirror.MIRROR_SERVER_NAME
        removed_server = False
        try:
            mcp = _load_json(Path((rec or {}).get("mcp_path") or mcp_path))
            servers = mcp.get(key)
            if isinstance(servers, dict) and server in servers:
                del servers[server]
                _write_json(Path((rec or {}).get("mcp_path") or mcp_path), mcp)
                removed_server = True
        except Exception as exc:
            print(_c(f"prismor mirror off: could not update {mcp_path}: {exc}", _RED))
            return 1

        removed_deny: List[str] = []
        extra_notes: List[str] = []
        if rec:
            spath = Path(rec.get("settings_path") or settings_path)
            try:
                settings = _load_json(spath)
                perms = settings.get("permissions")
                deny = perms.get("deny") if isinstance(perms, dict) else None
                changed = False
                if isinstance(deny, list):
                    ours = set(rec.get("deny_added") or [])
                    kept = [x for x in deny if str(x) not in ours]
                    removed_deny = [str(x) for x in deny if str(x) in ours]
                    if removed_deny:
                        perms["deny"] = kept
                        if not kept:
                            del perms["deny"]
                        changed = True
                if changed:
                    if isinstance(perms, dict) and not perms:
                        del settings["permissions"]
                    _write_json(spath, settings)
            except Exception as exc:
                print(_c(f"prismor mirror off: could not update {spath}: {exc}", _RED))
                return 1
            ours_allow = set(rec.get("allow_added") or [])
            if ours_allow:
                lpath = _local_settings_path(workspace)
                try:
                    local = _load_json(lpath)
                    lperms = local.get("permissions")
                    lallow = lperms.get("allow") if isinstance(lperms, dict) else None
                    if isinstance(lallow, list):
                        kept = [x for x in lallow if str(x) not in ours_allow]
                        if len(kept) != len(lallow):
                            if kept:
                                lperms["allow"] = kept
                            else:
                                del lperms["allow"]
                            if not lperms:
                                del local["permissions"]
                            extra_notes.append("tool permissions removed from settings.local.json")
                            if local:
                                _write_json(lpath, local)
                            elif lpath.exists():
                                lpath.unlink()
                except Exception:
                    pass
            if rec.get("approved_in_claude_state"):
                if _unapprove_project_server(workspace, server):
                    extra_notes.append(f"server approval for {server} removed from settings.local.json")
            _write_record(workspace, None)

        if removed_server or removed_deny or rec:
            done += 1
            print(f"  {_c('Prismor mirror is off', _GREEN)} (this project)")
            if removed_server:
                print(f"  {_c('server', _DIM)}    removed {server} from {mcp_path}")
            if removed_deny:
                print(f"  {_c('natives', _DIM)}   restored in {settings_path}: " + ", ".join(removed_deny))
            for note in extra_notes:
                print(f"  {_c('cleaned', _DIM)}   {note}")
    if not done:
        print("  Prismor mirror was not configured for Claude Code here — nothing to undo.")
        print(_c("  (If you wired it by hand, remove the server from .mcp.json and the deny "
                 "entries from .claude/settings.json yourself.)", _DIM))
        return 0
    print()
    print(f"  {_c('Start a new Claude Code session — the agent uses its native tools again.', _BOLD)}")
    print(_c("  Any session started before this keeps the mirror until it ends.", _DIM))
    return 0


# ── Codex ────────────────────────────────────────────────────────────────────
#
# Wired through Codex's own CLI (`codex mcp add/remove`, `codex features
# enable/disable`) rather than by editing config.toml. That file is the user's,
# it is TOML with comments and dozens of unrelated settings, and Codex ships a
# supported writer for exactly these two things — hand-editing it to save a
# subprocess would be trading a real risk for nothing.
#
# Two properties differ from Claude Code and both are stated at install time
# rather than discovered later:
#
#   * MACHINE SCOPE. Codex reads MCP servers and `[features]` only from the
#     user-level config (verified: a project-scoped .codex/config.toml is
#     ignored for features). So mirroring Codex governs every project on this
#     machine. There is no project-scoped variant to offer.
#   * THE SANDBOX, not approvals, gates mirrored calls. A mirrored tool runs
#     inside Prismor, outside Codex's OS sandbox, so Codex cancels it under a
#     restrictive sandbox with "user cancelled MCP tool call" — and
#     `approval_policy="never"` does NOT change that. Verified on
#     codex-cli 0.145.0.

_CODEX_NATIVE_FEATURES = ("shell_tool", "unified_exec")


def _codex(*args: str) -> Tuple[bool, str]:
    """Run a `codex` subcommand. Returns (ok, output)."""
    import subprocess
    try:
        proc = subprocess.run(["codex", *args], capture_output=True, text=True, timeout=60)
    except FileNotFoundError:
        return False, "codex is not on PATH"
    except Exception as exc:
        return False, str(exc)
    out = ((proc.stdout or "") + (proc.stderr or "")).strip()
    return proc.returncode == 0, out


def _codex_record_path() -> Path:
    """Machine-level record for a machine-level install, so `mirror off` works
    from any directory rather than only the one that ran `on`."""
    from prismor.runtime.pause import prismor_home
    return prismor_home() / "mirror-install-codex.json"


def mirror_on_codex(workspace: Path, *, mode: str = "enforce") -> int:
    entry = _server_entry(workspace, mode)
    print(f"  {_c('host', _DIM)}      Codex  {_c('(machine-wide — Codex reads MCP servers and features', _DIM)}")
    print(f"  {_c('', _DIM)}          {_c('only from your user config, so this covers every project)', _DIM)}")

    print(f"  {_c('checking', _DIM)}  starting the mirror server once to verify it serves tools...")
    ok, detail = _preflight(entry)
    if not ok:
        print(_c(f"  prismor mirror on: the mirror server failed to start — {detail}", _RED))
        print(_c("  Nothing was changed. Codex keeps its native tools.", _DIM))
        return 1
    print(f"  {_c('ok', _GREEN)}        serves: {detail}")

    args = ["mcp", "add", mirror.MIRROR_SERVER_NAME]
    for key, value in (entry.get("env") or {}).items():
        args += ["--env", f"{key}={value}"]
    args += ["--", entry["command"], *entry["args"]]
    ok, out = _codex(*args)
    if not ok:
        print(_c(f"  prismor mirror on: `codex mcp add` failed — {out[:200]}", _RED))
        return 1
    print(f"  {_c('server', _DIM)}    codex mcp add {mirror.MIRROR_SERVER_NAME}")

    disabled = []
    for feature in _CODEX_NATIVE_FEATURES:
        ok, out = _codex("features", "disable", feature)
        if ok:
            disabled.append(feature)
        else:
            print(_c(f"  warning   could not disable {feature}: {out[:120]}", _YELLOW))
    if disabled:
        print(f"  {_c('natives', _DIM)}   disabled: {', '.join(disabled)}")
    if "unified_exec" not in disabled:
        print(_c("  warning   unified_exec is still on — it is a SECOND shell surface, so the", _YELLOW))
        print(_c("            model can route around the mirror until it is off.", _DIM))

    _write_json(_codex_record_path(), {
        "agent": "codex", "scope": "machine", "mode": mode,
        "server": mirror.MIRROR_SERVER_NAME,
        "features_disabled": disabled,
        "workspace": str(workspace),
        "at": time.time(),
    })
    mirror.set_mirror_config(workspace, override=True)

    print()
    print(f"  {_c('Prismor mirror is on for Codex', _GREEN)} ({mode} mode, machine-wide)")
    print(_c("  Codex gates mirrored calls on its SANDBOX, not its approval policy: a", _DIM))
    print(_c("  mirrored tool runs inside Prismor, outside Codex's sandbox, so a", _DIM))
    print(_c("  restrictive sandbox cancels it. If calls come back cancelled, run Codex", _DIM))
    print(f"  {_c('with a sandbox mode that permits them, e.g.', _DIM)} {_c('codex -s danger-full-access', _BOLD)}{_c('.', _DIM)}")
    print(_c("  (approval_policy=\"never\" does NOT cover MCP tool calls.)", _DIM))
    print()
    print(f"  {_c('Start a new Codex session for it to take effect.', _BOLD)}")
    print(f"  {_c('If it gets in your way:', _DIM)}  prismor pause")
    print(f"  {_c('To go back to native tools:', _DIM)}  prismor mirror off --agent codex")
    return 0


def mirror_off_codex(workspace: Path) -> int:
    rec = None
    try:
        rec = _load_json(_codex_record_path()) or None
    except Exception:
        rec = None
    server = (rec or {}).get("server") or mirror.MIRROR_SERVER_NAME

    ok, out = _codex("mcp", "remove", server)
    if ok:
        print(f"  {_c('server', _DIM)}    codex mcp remove {server}")
    else:
        print(_c(f"  note      `codex mcp remove {server}`: {out[:140]}", _DIM))

    # Re-enable only what we turned off. A feature the user had already disabled
    # for their own reasons is not ours to switch back on.
    restored = []
    for feature in ((rec or {}).get("features_disabled") or []):
        ok, out = _codex("features", "enable", feature)
        if ok:
            restored.append(feature)
    if restored:
        print(f"  {_c('natives', _DIM)}   re-enabled: {', '.join(restored)}")
    elif rec is None:
        print(_c("  note      no install record found — nothing to re-enable. If Codex is", _DIM))
        print(_c("            still missing its shell tools: codex features enable shell_tool", _DIM))

    try:
        p = _codex_record_path()
        if p.exists():
            p.unlink()
    except OSError:
        pass
    print()
    print(f"  {_c('Prismor mirror is off for Codex.', _GREEN)} "
          f"{_c('Start a new Codex session.', _BOLD)}")
    return 0


# ── OpenCode ─────────────────────────────────────────────────────────────────
#
# The most valuable host to mirror: OpenCode has no hook protocol, so MCP is the
# only interposition point that exists for it — without this Prismor cannot see
# an OpenCode session at all.
#
# Everything lives in one project-scoped `opencode.json`, and there is no trust
# gate: the project file both declares the server and grants it, so `on` is a
# single file edit. Note the MCP block is keyed directly under `mcp` — NOT
# `mcp.servers`, which published guidance says and OpenCode 1.18 rejects.
#
# Native tool names are lowercase and `tools: {name: false}` removes them from
# the agent's toolkit (OpenCode also derives a matching `permission: deny` from
# it, visible in `opencode debug config`).

# webfetch is in this list but NOT in NATIVE_TOOLS_TO_DISABLE for Claude Code:
# OpenCode has no hooks, so its native fetch is completely unwatched and the
# mirrored one is strictly better; Claude Code already screens its own WebFetch
# through hooks and its version summarises the page, so denying it there would
# trade a richer tool for no extra coverage.
_OPENCODE_NATIVE_TOOLS = ("bash", "read", "write", "edit", "grep", "glob", "webfetch")


def _opencode_config_path(workspace: Path) -> Path:
    return Path(workspace) / "opencode.json"


def mirror_on_opencode(workspace: Path, *, mode: str = "enforce") -> int:
    entry = _server_entry(workspace, mode)
    path = _opencode_config_path(workspace)

    print(f"  {_c('checking', _DIM)}  starting the mirror server once to verify it serves tools...")
    ok, detail = _preflight(entry)
    if not ok:
        print(_c(f"  prismor mirror on: the mirror server failed to start — {detail}", _RED))
        print(_c("  Nothing was changed. OpenCode keeps its native tools.", _DIM))
        return 1
    print(f"  {_c('ok', _GREEN)}        serves: {detail}")

    try:
        cfg = _load_json(path)
    except Exception as exc:
        print(_c(f"prismor mirror on: cannot read {path}: {exc}", _RED))
        return 1
    mcp = cfg.get("mcp")
    if mcp is None:
        mcp = cfg["mcp"] = {}
    if not isinstance(mcp, dict):
        print(_c(f"prismor mirror on: {path} has an unrecognised 'mcp' block — not touching it.", _RED))
        return 1
    tools = cfg.get("tools")
    if tools is None:
        tools = cfg["tools"] = {}
    if not isinstance(tools, dict):
        print(_c(f"prismor mirror on: {path} has an unrecognised 'tools' block — not touching it.", _RED))
        return 1

    _backup_once(path)
    cfg.setdefault("$schema", "https://opencode.ai/config.json")
    mcp[mirror.MIRROR_SERVER_NAME] = {
        "type": "local",
        "command": [entry["command"], *entry["args"]],
        "enabled": True,
        "environment": dict(entry.get("env") or {}),
    }
    disabled = []
    for tool in _OPENCODE_NATIVE_TOOLS:
        if tools.get(tool) is not False:
            tools[tool] = False
            disabled.append(tool)
    _write_json(path, cfg)

    _write_record(workspace, {
        "agent": "opencode", "scope": "project", "mode": mode,
        "server": mirror.MIRROR_SERVER_NAME,
        "config_path": str(path),
        "tools_disabled": disabled,
        "at": time.time(),
    })
    mirror.set_mirror_config(workspace, override=True)

    print(f"  {_c('Prismor mirror is on for OpenCode', _GREEN)} (this project, {mode} mode)")
    print(f"  {_c('server', _DIM)}    {path}  →  mcp.{mirror.MIRROR_SERVER_NAME}")
    if disabled:
        print(f"  {_c('natives', _DIM)}   disabled: {', '.join(disabled)}")
    print()
    print(f"  {_c('Start a new OpenCode session for it to take effect.', _BOLD)}")
    print(f"  {_c('Verify with', _DIM)} {_c('opencode mcp list', _BOLD)} "
          f"{_c('(expect: prismor-tools connected).', _DIM)}")
    print(f"  {_c('If it gets in your way:', _DIM)}  prismor pause")
    print(f"  {_c('To go back to native tools:', _DIM)}  prismor mirror off --agent opencode")
    return 0


def mirror_off_opencode(workspace: Path) -> int:
    rec = _read_record(workspace) or {}
    path = Path(rec.get("config_path") or _opencode_config_path(workspace))
    server = rec.get("server") or mirror.MIRROR_SERVER_NAME
    try:
        cfg = _load_json(path)
    except Exception as exc:
        print(_c(f"prismor mirror off: cannot read {path}: {exc}", _RED))
        return 1

    changed = False
    mcp = cfg.get("mcp")
    if isinstance(mcp, dict) and server in mcp:
        del mcp[server]
        if not mcp:
            del cfg["mcp"]
        changed = True
        print(f"  {_c('server', _DIM)}    removed mcp.{server} from {path}")

    tools = cfg.get("tools")
    # Re-enable only what `on` turned off; a tool the developer had already
    # disabled themselves is not ours to switch back on.
    restored = []
    if isinstance(tools, dict):
        for tool in (rec.get("tools_disabled") or []):
            if tools.get(tool) is False:
                del tools[tool]
                restored.append(tool)
        if not tools:
            cfg.pop("tools", None)
    if restored:
        changed = True
        print(f"  {_c('natives', _DIM)}   restored: {', '.join(restored)}")

    if changed:
        if list(cfg.keys()) == ["$schema"]:
            cfg = {}
        if cfg:
            _write_json(path, cfg)
        elif path.exists():
            path.unlink()
        _write_record(workspace, None)
    else:
        print("  Prismor mirror was not configured for OpenCode here — nothing to undo.")
        return 0
    print()
    print(f"  {_c('Start a new OpenCode session — it uses its native tools again.', _BOLD)}")
    return 0


# ── Claude Desktop ─────────────────────────────────────────────────────
#
# The desktop app, not Claude Code. One machine-wide config file
# (`claude_desktop_config.json`, `mcpServers` — the same shape `_server_entry`
# already produces), and no trust gate to satisfy: a server added there loads on
# the next app restart.
#
# IMPORTANT and unlike every other host here: this ADDS a governed toolset, it
# does not REPLACE the natives. The desktop app has no permissions.deny and no
# feature switches — its own tools (web search, file access, the cowork/VM
# sandbox) stay exactly as they were and are not screened. So `on` says that out
# loud rather than letting the install imply a coverage it does not have.


def _claude_desktop_config_path() -> Path:
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
    if os.name == "nt":
        base = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
        return Path(base) / "Claude" / "claude_desktop_config.json"
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "Claude" / "claude_desktop_config.json"


def _claude_desktop_record_path() -> Path:
    """Machine-level record for a machine-level install, so `off` works from
    any directory rather than only the one that ran `on`."""
    from prismor.runtime.pause import prismor_home
    return prismor_home() / "mirror-install-claude-desktop.json"


def mirror_on_claude_desktop(workspace: Path, *, mode: str = "enforce") -> int:
    path = _claude_desktop_config_path()
    entry = _server_entry(workspace, mode)
    print(f"  {_c('host', _DIM)}      Claude Desktop  {_c('(machine-wide — one config for the app)', _DIM)}")

    print(f"  {_c('checking', _DIM)}  starting the mirror server once to verify it serves tools...")
    ok, detail = _preflight(entry)
    if not ok:
        print(_c(f"  prismor mirror on: the mirror server failed to start — {detail}", _RED))
        print(_c("  Nothing was changed.", _DIM))
        return 1
    print(f"  {_c('ok', _GREEN)}        serves: {detail}")

    try:
        cfg = _load_json(path)
    except Exception as exc:
        print(_c(f"prismor mirror on: cannot read {path}: {exc}", _RED))
        return 1
    servers = cfg.get("mcpServers")
    if servers is None:
        servers = cfg["mcpServers"] = {}
    if not isinstance(servers, dict):
        print(_c(f"prismor mirror on: {path} has an unrecognised 'mcpServers' block — not touching it.", _RED))
        return 1

    _backup_once(path)
    servers[mirror.MIRROR_SERVER_NAME] = entry
    _write_json(path, cfg)

    _write_json(_claude_desktop_record_path(), {
        "agent": "claude-desktop", "scope": "machine", "mode": mode,
        "server": mirror.MIRROR_SERVER_NAME,
        "config_path": str(path),
        "workspace": str(workspace),
        "at": time.time(),
    })
    mirror.set_mirror_config(workspace, override=True)

    print(f"  {_c('Prismor mirror is on for Claude Desktop', _GREEN)} ({mode} mode, machine-wide)")
    print(f"  {_c('server', _DIM)}    {path}  →  mcpServers.{mirror.MIRROR_SERVER_NAME}")
    print(f"  {_c('policy', _DIM)}    resolved for {workspace}")
    print()
    print(_c("  This ADDS governed tools; it does not disable the app's own. Claude", _YELLOW))
    print(_c("  Desktop has no deny-list or feature switch for its built-in tools, so", _DIM))
    print(_c("  its native file/search/sandbox tools stay available and unscreened —", _DIM))
    print(_c("  the model can still reach for them instead of the mirrored ones.", _DIM))
    print()
    print(f"  {_c('Quit and reopen Claude Desktop for it to take effect.', _BOLD)}")
    print(f"  {_c('If it gets in your way:', _DIM)}  prismor pause")
    print(f"  {_c('To remove it:', _DIM)}  prismor mirror off --agent claude-desktop")
    return 0


def mirror_off_claude_desktop(workspace: Path) -> int:
    try:
        rec = _load_json(_claude_desktop_record_path())
    except Exception:
        rec = {}
    path = Path(rec.get("config_path") or _claude_desktop_config_path())
    server = rec.get("server") or mirror.MIRROR_SERVER_NAME
    try:
        cfg = _load_json(path)
    except Exception as exc:
        print(_c(f"prismor mirror off: cannot read {path}: {exc}", _RED))
        return 1

    servers = cfg.get("mcpServers")
    if not isinstance(servers, dict) or server not in servers:
        print("  Prismor mirror was not configured for Claude Desktop — nothing to undo.")
        return 0
    del servers[server]
    if not servers:
        del cfg["mcpServers"]
    _write_json(path, cfg)
    print(f"  {_c('server', _DIM)}    removed mcpServers.{server} from {path}")
    try:
        p = _claude_desktop_record_path()
        if p.exists():
            p.unlink()
    except OSError:
        pass
    print()
    print(f"  {_c('Prismor mirror is off for Claude Desktop.', _GREEN)} "
          f"{_c('Quit and reopen the app.', _BOLD)}")
    return 0


# ── runtime switch ───────────────────────────────────────────────────────────

def mirror_passthrough(workspace: Path, on: bool) -> int:
    cfg = mirror.set_mirror_config(workspace, override=not on)
    if on:
        print(f"  {_c('Mirror is passing through', _YELLOW)} — built-ins run ungoverned "
              "(logged, not blocked or redacted). No restart needed.")
        print(_c("  Back to governing: prismor mirror passthrough off", _DIM))
    else:
        print(f"  {_c('Mirror is governing', _GREEN)} — policy screens every mirrored call again.")
    return 0 if cfg is not None else 1


# ── status ───────────────────────────────────────────────────────────────────

def _live_gateways(workspace: Path) -> List[Dict[str, Any]]:
    try:
        return [m for m in mirror._live_markers()  # noqa: SLF001 — same package
                if mirror._within(str(m.get("workspace") or ""), str(workspace))
                or mirror._within(str(workspace), str(m.get("workspace") or ""))]
    except Exception:
        return []


def mirror_status(workspace: Path) -> int:
    print(f"  {_c('Prismor mirror', _BOLD)} — {workspace}")

    configured = False
    for sc in ("project",):
        rec = _read_record(workspace)
        mcp_path, _settings_path, key = _claude_paths(workspace)
        try:
            servers = _load_json(mcp_path).get(key) or {}
        except Exception:
            servers = {}
        names = [n for n, cfg in servers.items()
                 if isinstance(cfg, dict) and "--mirror" in [str(a) for a in (cfg.get("args") or [])]]
        if names or rec:
            configured = True
            how = "prismor mirror on" if rec else "by hand"
            mode = (rec or {}).get("mode") or "?"
            print(f"  {_c('Claude Code', _DIM)}   server {', '.join(names) or (rec or {}).get('server')}"
                  f" · {mode} mode · {how}")
            if rec and rec.get("deny_added"):
                print(f"  {_c('natives off', _DIM)}   {', '.join(rec['deny_added'])}")
    if not configured:
        print(f"  {_c('Claude Code', _DIM)}   not configured — `prismor mirror on` to enable")

    try:
        drec = _load_json(_claude_desktop_record_path())
    except Exception:
        drec = {}
    if drec.get("server"):
        configured = True
        print(f"  {_c('Claude Desktop', _DIM)} server {drec['server']} · {drec.get('mode') or '?'} mode"
              f" · machine-wide · natives NOT disabled (the app has no deny-list)")

    state = mirror.passthrough_state(workspace)
    if state is None:
        gov = _c("governing", _GREEN) + " — policy screens every mirrored call"
    elif state["source"] == "pause":
        rec = state.get("pause") or {}
        until = rec.get("until")
        when = (" until " + datetime.fromtimestamp(float(until)).strftime("%H:%M")) if until else ""
        by = " (by your organization)" if rec.get("source") == "org" else ""
        gov = _c(f"PAUSED{when}{by}", _YELLOW) + " — passing through; `prismor resume` to govern again"
    else:
        gov = _c("PASS-THROUGH", _YELLOW) + " — override off; `prismor mirror passthrough off` to govern again"
    print(f"  {_c('governance', _DIM)}    {gov}")

    cfg = mirror.mirror_config(workspace)
    roster = []
    for t in mirror.mirror_tool_names():
        roster.append(t if t not in cfg["disabled_tools"] else _c(f"{t} (off)", _DIM))
    print(f"  {_c('roster', _DIM)}        {' '.join(roster)}")

    for warn in _coherence_warnings(workspace, _server_entry(workspace, "enforce")):
        print(f"  {_c('warning', _YELLOW)}      {warn}")

    live = _live_gateways(workspace)
    if live:
        for m in live:
            print(f"  {_c('live gateway', _DIM)}  pid {m.get('pid')} · {m.get('workspace')}")
    else:
        print(f"  {_c('live gateway', _DIM)}  none — the gateway starts with the next agent session")

    print()
    print(_c("  prismor pause / resume        lift or restore enforcement (24h auto-resume)", _DIM))
    print(_c("  prismor mirror passthrough on|off   run built-ins ungoverned without a restart", _DIM))
    print(_c("  prismor mirror off            hand the built-ins back to the agent (next session)", _DIM))
    return 0


def run(args, workspace: Path) -> int:
    action = getattr(args, "mirror_command", None) or "status"
    if action == "on":
        return mirror_on(workspace, mode=args.mode, agent=args.agent,
                         allow_tools=getattr(args, "allow_tools", False))
    if action == "off":
        return mirror_off(workspace, agent=getattr(args, "agent", "claude"))
    if action == "passthrough":
        return mirror_passthrough(workspace, on=(args.state == "on"))
    return mirror_status(workspace)
