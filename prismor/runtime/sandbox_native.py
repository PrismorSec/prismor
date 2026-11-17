"""Native (no Docker) sandbox backend: Seatbelt on macOS, bubblewrap on Linux.

Hooks see the command an agent asks for, not what that command does once it
runs: the files ``npm install`` scripts touch, the hosts a test suite dials.
This backend runs the allowed command on the host, with the user's own
toolchain, inside an OS sandbox that every child process inherits:

* writes are limited to the workspace, temp dirs and package caches, and
  Prismor's own config and the agent hook files stay read-only;
* credential stores (~/.ssh, ~/.aws, ...) cannot be read;
* outbound traffic goes through a local proxy. Each new host is screened as a
  normal Prismor ``network`` event, so it lands in the session trail and the
  egress policy decides it. With ``network: allowlist`` the kernel only lets
  the command reach loopback, so a tool that ignores the proxy fails closed.

``mode: observe`` keeps the proxy (visibility) but drops the kernel limits,
so builds never break while a team decides what to enforce.

The proxy speaks HTTP, CONNECT and SOCKS5 CONNECT on one port, so tools that
honour ALL_PROXY are screened per host too. On Linux, bubblewrap can only
mount over paths that exist, so a protected path missing before the run is
checked afterwards: if the command created it, it is removed and recorded as
a sandbox finding. Credential injection and pre-run workspace snapshots are
not offered: the first needs TLS interception, the second is costly on large
workspaces.
"""
from __future__ import annotations

import os
import platform
import struct
import select
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

# Read-denied in enforce mode. ``allow_read`` in the sandbox config lifts one.
SECRET_PATHS = [
    "~/.ssh", "~/.aws", "~/.gnupg", "~/.azure", "~/.kube", "~/.config/gcloud",
    "~/.docker/config.json", "~/.netrc", "~/.git-credentials", "~/.npmrc",
    "~/.pypirc", "~/.prismor/secrets", "~/.config/gh", "~/.config/hub", "~/.config/op",
    "~/.claude/.credentials.json", "~/.vault-token", "~/.terraform.d/credentials.tfrc.json",
    "~/.cargo/credentials.toml", "~/.config/containers/auth.json",
]
# Writable in enforce mode besides the workspace and temp dirs.
CACHE_PATHS = ["~/.cache", "~/Library/Caches", "~/.npm", "~/.cargo/registry", "~/.gradle/caches"]
# Inside the workspace, but never writable by a sandboxed command: Prismor's
# policy and the agents' hook wiring. A command must not be able to switch
# off the thing screening it.
PROTECTED_IN_WORKSPACE = [
    ".prismor", ".git/hooks", ".claude/settings.json", ".claude/settings.local.json",
    ".codex", ".cursor/hooks.json", ".github/hooks",
    # core.hooksPath / core.fsmonitor in .git/config moves hook execution to an
    # unprotected dir; .mcp.json and .claude/hooks start code in the next session.
    ".git/config", ".mcp.json", ".claude/hooks",
]


def _parents(ws: str, rel_paths: List[str]) -> List[str]:
    """Dirs between the workspace and each protected path (``.git``, ``.claude``).

    Renaming one of them moves the protected path away from the name the
    profile guards (``mv .git .g; edit .g/hooks; mv .g .git``), so they may
    not be renamed or removed themselves. Writes inside them stay allowed.
    """
    out: List[str] = []
    for rel in rel_paths:
        parts = rel.split("/")[:-1]
        for i in range(1, len(parts) + 1):
            out.append(os.path.join(ws, *parts[:i]))
    return list(dict.fromkeys(out))


def _real(p: str) -> str:
    return os.path.realpath(os.path.expanduser(p))


def _userns_hint() -> str:
    """Ubuntu 23.10+ blocks unprivileged user namespaces unless AppArmor allows bwrap."""
    try:
        restricted = Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns").read_text(encoding="utf-8").strip() == "1"
    except OSError:
        return ""
    if not restricted:
        return ""
    return ("; AppArmor blocks unprivileged user namespaces here "
            "(kernel.apparmor_restrict_unprivileged_userns=1). An admin must add an AppArmor "
            "profile that grants `userns` to /usr/bin/bwrap (see Ubuntu's notes on unprivileged "
            "user namespace restrictions)")


def status() -> Dict[str, Any]:
    system = platform.system()
    if system == "Darwin":
        exe = shutil.which("sandbox-exec") or ("/usr/bin/sandbox-exec" if os.path.exists("/usr/bin/sandbox-exec") else None)
        return {"backend": "native", "engine": "seatbelt", "ready": bool(exe),
                **({} if exe else {"error": "sandbox-exec not found"})}
    if system == "Linux":
        exe = shutil.which("bwrap")
        if not exe:
            return {"backend": "native", "engine": "bubblewrap", "ready": False,
                    "error": "bwrap not found (apt install bubblewrap)"}
        try:
            probe = subprocess.run([exe, "--ro-bind", "/", "/", "--unshare-net", "true"],
                                   capture_output=True, text=True, timeout=5, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {"backend": "native", "engine": "bubblewrap", "ready": False, "error": str(exc)}
        if probe.returncode != 0:
            return {"backend": "native", "engine": "bubblewrap", "ready": False,
                    "error": (probe.stderr or "bwrap failed").strip() + _userns_hint()}
        return {"backend": "native", "engine": "bubblewrap", "ready": True}
    return {"backend": "native", "engine": None, "ready": False,
            "error": f"no native sandbox on {system}"}


# ── policy → paths ────────────────────────────────────────────────────────

def _paths(workspace: Path, cfg: Dict[str, Any]) -> Dict[str, List[str]]:
    ws = _real(str(workspace))
    lifted = {_real(p) for p in cfg.get("allow_read") or []}
    deny_read = [p for p in (_real(x) for x in SECRET_PATHS + list(cfg.get("deny_read") or []))
                 if p not in lifted]
    writable = [] if cfg.get("workspace_mount") == "ro" else [ws]
    writable += [_real("/tmp"), _real(tempfile.gettempdir())]  # nosec B108 - granting the sandbox the host temp dirs, not creating a temp file
    writable += [_real(p) for p in CACHE_PATHS + list(cfg.get("allow_write") or [])]
    # ponytail: no .git yet means a command may `git init` here, which has to
    # write .git/config and .git/hooks, so .git/* is guarded only once the repo
    # exists. A repo created inside the run can carry hooks; pre-creating the
    # guard would need git's own init, add when that matters.
    rels = [r for r in PROTECTED_IN_WORKSPACE
            if not r.startswith(".git/") or os.path.isdir(os.path.join(ws, ".git"))]
    protected = [os.path.join(ws, rel) for rel in rels]
    return {"ws": [ws], "deny_read": deny_read, "writable": list(dict.fromkeys(writable)),
            "protected": protected, "parents": _parents(ws, rels)}


def _sb(path: str) -> str:
    return '"' + path.replace("\\", "\\\\").replace('"', '\\"') + '"'


def seatbelt_profile(workspace: Path, cfg: Dict[str, Any], *, restrict_network: bool) -> str:
    """SBPL profile. Later rules win, so each deny/allow narrows the one above."""
    p = _paths(workspace, cfg)
    lines = ["(version 1)", "(allow default)",
             "(deny file-write*)",
             "(allow file-write* " + " ".join(f"(subpath {_sb(w)})" for w in p["writable"])
             + ' (literal "/dev/null") (literal "/dev/zero") (literal "/dev/dtracehelper")'
             + ' (regex #"^/dev/tty") (subpath "/dev/fd"))']
    lines.append("(deny file-write* " + " ".join(f"(subpath {_sb(x)})" for x in p["protected"]) + ")")
    # unlink covers rename and rmdir of the dir node (.git, .claude, ...);
    # creating it (git init) and writing inside it stay allowed.
    lines.append("(deny file-write-unlink " + " ".join(f"(literal {_sb(x)})" for x in p["parents"]) + ")")
    if p["deny_read"]:
        lines.append("(deny file-read* " + " ".join(f"(subpath {_sb(x)})" for x in p["deny_read"]) + ")")
    if restrict_network:
        # Loopback only: the proxy, local dev servers, test fixtures. No unix
        # sockets either — docker.sock or an ssh-agent socket is a way out.
        lines += ["(deny network*)",
                  '(allow network* (remote ip "localhost:*"))',
                  '(allow network* (local ip "localhost:*"))']
    return "\n".join(lines) + "\n"


def bwrap_argv(workspace: Path, cfg: Dict[str, Any], *, unshare_net: bool,
               extra_binds: List[str] = ()) -> List[str]:
    p = _paths(workspace, cfg)
    # --unshare-pid: no /proc/<pid>/environ of the user's other processes, no
    # signals to them. --new-session: no TIOCSTI typing into the agent's tty.
    argv = [shutil.which("bwrap") or "bwrap", "--die-with-parent", "--new-session", "--unshare-pid",
            "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc"]
    for w in p["writable"] + list(extra_binds):
        if os.path.exists(w):
            argv += ["--bind", w, w]
    # A mount point cannot be renamed (EBUSY), so binding .git/.claude onto
    # themselves stops `mv .git .g` from moving the ro-bound hooks aside.
    bind = "--ro-bind" if cfg.get("workspace_mount") == "ro" else "--bind"
    for d in p["parents"]:
        if os.path.isdir(d):
            argv += [bind, d, d]
    # bwrap can only re-mount paths that exist; missing ones are handled by
    # missing_protected() / revert_created() around the run.
    for x in p["protected"]:
        if os.path.exists(x):
            argv += ["--ro-bind", x, x]
    for x in p["deny_read"]:
        if os.path.isdir(x):
            argv += ["--tmpfs", x]
        elif os.path.exists(x):
            argv += ["--ro-bind", "/dev/null", x]
    if unshare_net:
        argv.append("--unshare-net")
    argv += ["--chdir", p["ws"][0]]
    return argv


def missing_protected(workspace: Path) -> List[str]:
    """Protected paths absent before a Linux run; revert_created() checks them after.

    ``.git/hooks`` only counts when ``.git`` already exists, so ``git init``
    and ``git clone`` inside the sandbox keep their hooks dir.
    """
    ws = _real(str(workspace))
    out = []
    for rel in PROTECTED_IN_WORKSPACE:
        x = os.path.join(ws, rel)
        if os.path.lexists(x):
            continue
        if rel == ".git/hooks" and not os.path.isdir(os.path.join(ws, ".git")):
            continue
        out.append(x)
    return out


def revert_created(paths: List[str]) -> List[str]:
    """Remove the protected paths a command created. Returns what was removed."""
    removed = []
    for x in paths:
        # A parent the command swapped for a symlink would point the removal
        # somewhere else; only touch paths that sit where they claim to.
        if not os.path.lexists(x) or os.path.realpath(os.path.dirname(x)) != os.path.dirname(x):
            continue
        try:
            if os.path.isdir(x) and not os.path.islink(x):
                shutil.rmtree(x)
            else:
                os.unlink(x)
            removed.append(x)
        except OSError as exc:
            sys.stderr.write(f"[prismor] sandbox could not remove {x}: {exc}\n")
    return removed


def report_reverted(paths: List[str], *, workspace: Path, agent: str, session_id: str,
                    command: str) -> None:
    """Record each reverted write as an observe-mode event plus a sandbox finding."""
    from prismor.runtime.runtime import evaluate_tool_call
    from prismor.runtime.store import persist_runtime_findings, read_session_events
    for x in paths:
        sys.stderr.write(f"[prismor] sandbox removed protected path the command created: {x}\n")
        event = {"type": "file_write", "path": x, "agent": agent or "sandbox",
                 "agent_event": "SandboxDenied",
                 "metadata": {"tool_name": "sandbox_denial", "sandboxed_command": command[:500]}}
        if session_id:
            event["session_id"] = session_id
        try:
            evaluate_tool_call(event=event, workspace=workspace, agent=agent or "sandbox",
                               agent_name=agent or "", mode="observe", session_id=session_id,
                               flush_at_exit=False)
            if session_id:
                idx = max(len(read_session_events(workspace, session_id)) - 1, 0)
                persist_runtime_findings(workspace, session_id, [{
                    "id": f"{session_id}:sandbox-protected-write-{idx}",
                    "severity": "HIGH", "category": "sandbox", "ruleId": "sandbox-protected-write",
                    "action": "block", "mode": "enforce",
                    "title": "Sandbox reverted a write to a protected path",
                    "evidence": f"{x} (created by: {command[:200]})",
                }], idx)
        except Exception as exc:
            sys.stderr.write(f"[prismor] sandbox denial report failed: {exc}\n")


# ── egress proxy ──────────────────────────────────────────────────────────

Decide = Callable[[str, int, str], bool]


def _pipe(a: socket.socket, b: socket.socket) -> None:
    socks = [a, b]
    try:
        while True:
            ready, _, _ = select.select(socks, [], [], 300)
            if not ready:
                return
            for s in ready:
                data = s.recv(65536)
                if not data:
                    return
                (b if s is a else a).sendall(data)
    except OSError:
        return
    finally:
        for s in socks:
            try:
                s.close()
            except OSError:
                pass


def _read_head(conn: socket.socket) -> Tuple[bytes, bytes]:
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = conn.recv(65536)
        if not chunk:
            break
        buf += chunk
        if len(buf) > 65536:
            break
    head, _, rest = buf.partition(b"\r\n\r\n")
    return head, rest


def _recv_exact(conn: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise OSError("short read")
        buf += chunk
    return buf


def _handle_socks5(conn: socket.socket, decide: Decide) -> None:
    """SOCKS5, no auth, CONNECT only (RFC 1928). Screened like HTTP CONNECT."""
    try:
        _, nmethods = _recv_exact(conn, 2)
        if 0 not in _recv_exact(conn, nmethods):
            conn.sendall(b"\x05\xff")
            return
        conn.sendall(b"\x05\x00")
        _, cmd, _, atyp = _recv_exact(conn, 4)
        if atyp == 1:
            host = socket.inet_ntop(socket.AF_INET, _recv_exact(conn, 4))
        elif atyp == 4:
            host = socket.inet_ntop(socket.AF_INET6, _recv_exact(conn, 16))
        elif atyp == 3:
            host = _recv_exact(conn, _recv_exact(conn, 1)[0]).decode("idna")
        else:
            conn.sendall(b"\x05\x08\x00\x01" + bytes(6))
            return
        (port,) = struct.unpack("!H", _recv_exact(conn, 2))
        if cmd != 1:  # BIND / UDP ASSOCIATE would bypass per-host screening
            conn.sendall(b"\x05\x07\x00\x01" + bytes(6))
            return
        if not decide(host, port, "https"):
            conn.sendall(b"\x05\x02\x00\x01" + bytes(6))
            return
        try:
            upstream = socket.create_connection((host, port), timeout=30)
        except OSError:
            conn.sendall(b"\x05\x05\x00\x01" + bytes(6))
            return
        upstream.settimeout(None)
        conn.sendall(b"\x05\x00\x00\x01" + bytes(6))
        _pipe(conn, upstream)
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def _handle(conn: socket.socket, decide: Decide) -> None:
    try:
        if conn.recv(1, socket.MSG_PEEK) == b"\x05":
            _handle_socks5(conn, decide)
            return
        head, rest = _read_head(conn)
        first, _, headers = head.partition(b"\r\n")
        parts = first.decode("latin-1").split()
        if len(parts) != 3:
            conn.close()
            return
        method, target, version = parts
        if method.upper() == "CONNECT":
            host, _, port_s = target.rpartition(":")
            host, port, scheme = host.strip("[]"), int(port_s or 443), "https"
        else:
            u = urlsplit(target)
            if not u.hostname:
                conn.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                conn.close()
                return
            host, port, scheme = u.hostname, u.port or 80, u.scheme or "http"
        if not decide(host, port, scheme):
            msg = f"Blocked by Prismor sandbox egress policy: {host}\n".encode()
            conn.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: "
                         + str(len(msg)).encode() + b"\r\nConnection: close\r\n\r\n" + msg)
            conn.close()
            return
        upstream = socket.create_connection((host, port), timeout=30)
        upstream.settimeout(None)
        if method.upper() == "CONNECT":
            conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            if rest:
                upstream.sendall(rest)
        else:
            u = urlsplit(target)
            path = (u.path or "/") + (f"?{u.query}" if u.query else "")
            upstream.sendall(f"{method} {path} {version}\r\n".encode("latin-1") + headers
                             + b"\r\n\r\n" + rest)
        _pipe(conn, upstream)
    except Exception:
        try:
            conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        except OSError:
            pass
        conn.close()


class EgressProxy:
    """HTTP/CONNECT/SOCKS5 proxy on 127.0.0.1 (macOS, shared-net Linux) or a unix socket."""

    def __init__(self, decide: Decide, unix_path: Optional[str] = None) -> None:
        self.decide = decide
        if unix_path:
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.bind(unix_path)
            self.address: Any = unix_path
        else:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.bind(("127.0.0.1", 0))
            self.address = self.sock.getsockname()
        self.sock.listen(64)
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=_handle, args=(conn, self.decide), daemon=True).start()

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


def make_decider(*, workspace: Path, agent: str, session_id: str, mode: str,
                 command: str) -> Decide:
    """Screen each new host:port once per run as a Prismor ``network`` event."""
    cache: Dict[Tuple[str, int], bool] = {}
    lock = threading.Lock()  # ponytail: one evaluation at a time; store writes are not thread-safe

    def decide(host: str, port: int, scheme: str) -> bool:
        key = (host.lower(), port)
        with lock:
            if key in cache:
                return cache[key]
            from prismor.runtime.runtime import evaluate_tool_call
            default = 443 if scheme == "https" else 80
            url = f"{scheme}://{host}" + ("" if port == default else f":{port}")
            event = {
                "type": "network", "url": url, "agent": agent or "sandbox",
                "agent_event": "SandboxEgress",
                "metadata": {"tool_name": "sandbox_egress", "sandboxed_command": command[:500]},
            }
            if session_id:
                event["session_id"] = session_id
            try:
                decision = evaluate_tool_call(event=event, workspace=workspace, agent=agent or "sandbox",
                                              agent_name=agent or "", mode=mode, session_id=session_id,
                                              flush_at_exit=False)
                allowed = bool(decision.allow)
            except Exception as exc:
                # A broken evaluator must not open the network in enforce mode.
                sys.stderr.write(f"[prismor] sandbox egress check failed for {host}: {exc}\n")
                allowed = mode != "enforce"
            if not allowed:
                sys.stderr.write(f"[prismor] sandbox blocked connection to {host}:{port}\n")
            cache[key] = allowed
            return allowed

    return decide


def _proxy_env(port: int) -> Dict[str, str]:
    url = f"http://127.0.0.1:{port}"
    socks = f"socks5h://127.0.0.1:{port}"
    return {"http_proxy": url, "https_proxy": url, "HTTP_PROXY": url, "HTTPS_PROXY": url,
            "all_proxy": socks, "ALL_PROXY": socks,
            "no_proxy": "localhost,127.0.0.1,::1", "NO_PROXY": "localhost,127.0.0.1,::1",
            "NODE_USE_ENV_PROXY": "1", "PRISMOR_SANDBOX": "native"}


# ── run ───────────────────────────────────────────────────────────────────

def run(command: str, *, workspace: Path, cfg: Dict[str, Any], agent: str = "",
        session_id: str = "") -> int:
    st = status()
    if not st["ready"]:
        sys.stderr.write(f"Prismor sandbox unavailable: {st.get('error')}\n")
        return 127
    mode = cfg.get("mode", "observe")
    enforce = mode == "enforce"
    network = cfg.get("network", "none")
    restrict = enforce and network in ("none", "allowlist")
    use_proxy = network != "none"
    timeout = (cfg.get("resource_limits") or {}).get("timeout_seconds") or None
    decide = make_decider(workspace=workspace, agent=agent, session_id=session_id,
                          mode=mode, command=command)
    # Agents' Bash tools run bash; /bin/sh is dash on Debian/Ubuntu, where
    # `[[ ]]` and `source` fail.
    shell = [shutil.which("bash") or "/bin/sh", "-c", command]
    env = dict(os.environ)
    proxy: Optional[EgressProxy] = None
    watch = missing_protected(workspace) if enforce and st["engine"] == "bubblewrap" else []
    tmp = tempfile.mkdtemp(prefix="prismor-sbx-")
    try:
        if st["engine"] == "seatbelt":
            if use_proxy:
                proxy = EgressProxy(decide)
                env.update(_proxy_env(proxy.address[1]))
            if enforce:
                prof = Path(tmp) / "profile.sb"
                prof.write_text(seatbelt_profile(workspace, cfg, restrict_network=restrict), encoding="utf-8")
                argv = ["/usr/bin/sandbox-exec", "-f", str(prof)] + shell
            else:
                argv = shell
        else:
            if restrict and use_proxy:
                # Own network namespace: only loopback exists, so a bridge inside
                # the sandbox carries 127.0.0.1:<port> to the proxy's unix socket.
                sock_path = os.path.join(tmp, "egress.sock")
                proxy = EgressProxy(decide, unix_path=sock_path)
                port = 3128
                env.update(_proxy_env(port))
                pkg_root = str(Path(__file__).resolve().parents[2])
                env["PYTHONPATH"] = pkg_root + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
                inner = [sys.executable, "-m", "prismor.runtime.sandbox_native", "bridge",
                         sock_path, str(port), "--"] + shell
            else:
                if use_proxy:
                    proxy = EgressProxy(decide)
                    env.update(_proxy_env(proxy.address[1]))
                inner = shell
            argv = (bwrap_argv(workspace, cfg, unshare_net=restrict, extra_binds=[tmp]) + inner
                    if enforce else inner)
        proc = subprocess.run(argv, cwd=str(workspace), env=env,
                              timeout=float(timeout) if timeout else None)
        return int(proc.returncode)
    except subprocess.TimeoutExpired:
        sys.stderr.write(f"Prismor sandbox timed out after {timeout} second(s)\n")
        return 124
    except OSError as exc:
        sys.stderr.write(f"Prismor sandbox failed: {exc}\n")
        return 127
    finally:
        if proxy:
            proxy.close()
        shutil.rmtree(tmp, ignore_errors=True)
        reverted = revert_created(watch)
        if reverted:
            report_reverted(reverted, workspace=workspace, agent=agent,
                            session_id=session_id, command=command)


def _bridge(sock_path: str, port: int, cmd: List[str]) -> int:
    """Inside the Linux netns: 127.0.0.1:<port> → the host proxy's unix socket."""
    lsn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsn.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsn.bind(("127.0.0.1", port))
    lsn.listen(64)

    def serve() -> None:
        while True:
            conn, _ = lsn.accept()
            up = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            up.connect(sock_path)
            threading.Thread(target=_pipe, args=(conn, up), daemon=True).start()

    threading.Thread(target=serve, daemon=True).start()
    return subprocess.call(cmd)


if __name__ == "__main__" and len(sys.argv) > 4 and sys.argv[1] == "bridge":
    _sep = sys.argv.index("--")
    raise SystemExit(_bridge(sys.argv[2], int(sys.argv[3]), sys.argv[_sep + 1:]))
