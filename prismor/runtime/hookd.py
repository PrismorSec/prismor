"""prismor/runtime/hookd.py — warm hook daemon (a fork server) and its thin client.

Every agent tool call runs ``prismor hook-dispatch``. Run cold, that is a fresh
interpreter paying for ~0.5s of imports and a freshly parsed/compiled policy
engine before it screens anything, plus synchronous telemetry uploads before the
verdict is returned. This module keeps one interpreter warm per install and
forks it per call:

    agent ──stdin──▶ hook-dispatch (client) ──unix socket──▶ hookd (warm parent)
                                                               │ fork()
                                                               ▼
                                     child: runs the unchanged hook-dispatch code
                                     with the client's argv/env/cwd/umask/stdin,
                                     replies {exit, stdout, stderr}, THEN runs
                                     deferred network work (telemetry).

Why fork per call rather than evaluating inside the long-lived process: the
hook path is thousands of lines written for a one-shot process — module globals,
``sys.exit`` verdicts, ``atexit`` timing, subprocesses inheriting stdout. A
forked child keeps every one of those semantics exactly, cannot leak state into
the next call, and a crash or hang in one call cannot take the daemon down. The
parent only ever imports modules and fills content-keyed caches (the policy
YAML cache is keyed by file hash, ``re``'s by pattern), so a child never sees a
stale value computed for someone else.

Failure is never weaker than today: if the daemon is absent, busy starting,
stale, or dies mid-call, the client returns ``None`` and the caller runs the
SAME code in-process with the stdin it already read. The daemon is an
accelerator, not a second policy engine.

Isolation between installs: the socket name is derived from the interpreter and
the exact ``sys.path`` the client resolved, and the daemon is launched with that
``sys.path`` and without ``site`` processing, so it imports byte-for-byte the
same modules the in-process fallback would. The socket lives in a 0700 run
directory, is 0600, and (on Linux) every peer's uid is checked. The daemon only
ever runs ``hook-dispatch`` — nothing a same-user caller couldn't already run.

Controls:
    PRISMOR_HOOKD=0         never use the daemon (pure in-process, the old path)
    PRISMOR_HOOKD=manual    use a running daemon but never auto-start one
    prismor hookd status|stop|restart

This module must stay cheap to import: the client runs on every tool call, so
only the standard library is imported at module level.
"""
from __future__ import annotations

import json
import os
import socket
import stat
import struct
import sys
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

PROTOCOL_VERSION = 1

_MAX_FRAME = 16 * 1024 * 1024
# A listening local socket accepts in microseconds; if it cannot inside this,
# the daemon is unhealthy and the in-process path is the faster answer.
_CONNECT_TIMEOUT = 0.15
# Must cover a full evaluation (synchronous remote-policy refresh included).
# Past this the client gives up on the daemon and evaluates in-process.
_RESPONSE_TIMEOUT = float(os.environ.get("PRISMOR_HOOKD_TIMEOUT") or 45)
_IDLE_TIMEOUT = float(os.environ.get("PRISMOR_HOOKD_IDLE") or 30 * 60)
# Don't re-launch a daemon more often than this — a daemon that dies at
# start-up must not cost a process spawn on every tool call.
_SPAWN_BACKOFF = 10.0
# How often the parent re-checks whether its code on disk changed.
_FINGERPRINT_INTERVAL = 1.0
# Bounded wait for background threads (e.g. agent registration) in a child
# after its verdict has been delivered.
_CHILD_THREAD_GRACE = 5.0

_SYSPATH_ENV = "PRISMOR_HOOKD_SYSPATH"

# ── Child-side state ─────────────────────────────────────────────────────────

_IN_CHILD = False
_DRAINING = False
_DEFERRED: List[Tuple[Callable[..., Any], tuple, dict]] = []


def run_or_defer(fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    """Run ``fn`` now, or — inside a daemon child — after the verdict is sent.

    For best-effort network work (telemetry, SIEM sinks) that the verdict does
    not depend on. In-process it runs immediately, exactly as before. Deferred,
    it still runs to completion: the child belongs to the daemon, not the
    agent, so it isn't killed when the agent reaps the hook. Deferred calls
    return None and their exceptions are swallowed, which is the contract every
    call site already has ("telemetry never blocks the user").
    """
    if deferring():
        import copy

        # Snapshot now: the hook path keeps mutating findings/events after
        # this call site, and telemetry must describe the call as it was here.
        try:
            args, kwargs = copy.deepcopy((args, kwargs))
        except Exception:
            pass
        _DEFERRED.append((fn, args, kwargs))
        return None
    return fn(*args, **kwargs)


def deferring() -> bool:
    """True inside a daemon child whose verdict has not been sent yet."""
    return _IN_CHILD and not _DRAINING


# ── Paths and identity ───────────────────────────────────────────────────────


def _prismor_home() -> str:
    # Mirrors store.prismor_home() without importing it (client must stay cheap).
    return os.environ.get("PRISMOR_HOME") or os.path.join(os.path.expanduser("~"), ".prismor")


def _run_dir() -> str:
    return os.path.join(_prismor_home(), "run")


def _normalized_sys_path() -> List[str]:
    try:
        cwd = os.getcwd()
    except OSError:
        cwd = ""
    return [p if p else cwd for p in sys.path]


def install_key(sys_path: Optional[List[str]] = None) -> str:
    """Identity of "this exact install": interpreter + import path + protocol."""
    import hashlib

    parts = [str(PROTOCOL_VERSION), sys.executable or "", *(sys_path if sys_path is not None else _normalized_sys_path())]
    return hashlib.sha256("\0".join(parts).encode("utf-8", "surrogateescape")).hexdigest()[:16]


# AF_UNIX paths are capped at 104 bytes on macOS (108 on Linux). A long
# PRISMOR_HOME, or macOS's /var/folders temp dirs, goes past that and bind()
# fails, so the socket then lives in a short owner-only dir keyed to the run dir.
_SUN_PATH_MAX = 100


def _sock_dir() -> str:
    run = _run_dir()
    if len(os.path.join(run, "hookd-0123456789abcdef.sock").encode("utf-8", "surrogateescape")) <= _SUN_PATH_MAX:
        return run
    import hashlib

    tag = hashlib.sha256(run.encode("utf-8", "surrogateescape")).hexdigest()[:12]
    # Short on purpose; _ensure_dir rejects it unless it is ours, 0700 and not a symlink.
    return f"/tmp/prismor-{os.getuid()}-{tag}"  # nosec B108


def _socket_path(key: str) -> str:
    return os.path.join(_sock_dir(), f"hookd-{key}.sock")


def _ensure_dir(path: str) -> bool:
    """Create (or validate) an owner-only directory. False if unusable: not ours,
    or a symlink (someone else may have planted it in /tmp)."""
    try:
        os.makedirs(path, mode=0o700, exist_ok=True)
        st = os.lstat(path)
        if not stat.S_ISDIR(st.st_mode):
            return False
        if hasattr(os, "getuid") and st.st_uid != os.getuid():
            return False
        if st.st_mode & 0o077:
            os.chmod(path, 0o700)
    except OSError:
        return False
    return True


def _ensure_run_dir() -> Optional[str]:
    """Create (or validate) the owner-only run and socket directories. None if unusable."""
    path = _run_dir()
    if not (_ensure_dir(path) and _ensure_dir(_sock_dir())):
        return None
    return path


def _mode() -> str:
    return (os.environ.get("PRISMOR_HOOKD") or "").strip().lower()


def enabled() -> bool:
    if _IN_CHILD:
        return False
    if _mode() in ("0", "off", "false", "no", "disabled"):
        return False
    return hasattr(os, "fork") and hasattr(socket, "AF_UNIX")


# ── Framing: 4-byte big-endian length + body ─────────────────────────────────


def _send_frame(sock: socket.socket, body: bytes) -> None:
    sock.sendall(struct.pack(">I", len(body)) + body)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    chunks = []
    while n:
        chunk = sock.recv(min(n, 1 << 20))
        if not chunk:
            raise ConnectionError("peer closed mid-frame")
        chunks.append(chunk)
        n -= len(chunk)
    return b"".join(chunks)


def _recv_frame(sock: socket.socket) -> bytes:
    (length,) = struct.unpack(">I", _recv_exact(sock, 4))
    if length > _MAX_FRAME:
        raise ConnectionError("frame too large")
    return _recv_exact(sock, length)


def _send_json(sock: socket.socket, obj: Dict[str, Any]) -> None:
    _send_frame(sock, json.dumps(obj).encode("utf-8"))


def _recv_json(sock: socket.socket) -> Dict[str, Any]:
    obj = json.loads(_recv_frame(sock).decode("utf-8"))
    if not isinstance(obj, dict):
        raise ValueError("expected a JSON object")
    return obj


# ── Client ───────────────────────────────────────────────────────────────────


def _connect(key: str, timeout: float = _CONNECT_TIMEOUT) -> Optional[socket.socket]:
    path = _socket_path(key)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect(path)
    except OSError:
        sock.close()
        return None
    return sock


def _restore_stdin(data: bytes, encoding: str, errors: str) -> None:
    import io

    sys.stdin = io.TextIOWrapper(io.BytesIO(data), encoding=encoding, errors=errors)


def dispatch(argv: List[str]) -> Optional[int]:
    """Run ``hook-dispatch`` in the warm daemon; return its exit code.

    Returns None whenever the daemon did not produce a verdict — the caller
    then runs hook-dispatch in-process, with stdin restored from what was read
    here. Stdout/stderr are only written once a complete verdict is in hand,
    so a fallback never double-prints.
    """
    if not enabled():
        return None
    stdin = sys.stdin
    try:
        if stdin is None or stdin.isatty():
            return None
        encoding = stdin.encoding or "utf-8"
        errors = stdin.errors or "strict"
        data = stdin.buffer.read()
    except (AttributeError, OSError, ValueError):
        return None

    code: Optional[int] = None
    try:
        code = _dispatch_via_socket(argv, data, encoding, errors)
    except Exception:
        code = None
    if code is None:
        _restore_stdin(data, encoding, errors)
    return code


def _dispatch_via_socket(argv: List[str], data: bytes, encoding: str, errors: str) -> Optional[int]:
    t0 = time.time()
    sys_path = _normalized_sys_path()
    key = install_key(sys_path)
    sock = _connect(key)
    if sock is None:
        if _mode() != "manual":
            _autostart(key, sys_path)
        return None
    try:
        sock.settimeout(_RESPONSE_TIMEOUT)
        umask = os.umask(0o022)
        os.umask(umask)
        _send_json(sock, {
            "v": PROTOCOL_VERSION,
            "op": "hook",
            "key": key,
            "argv": list(argv),
            "sys_argv": list(sys.argv),
            "env": dict(os.environ),
            "cwd": os.getcwd(),
            "umask": umask,
            "stdin_encoding": encoding,
            "stdin_errors": errors,
            "t0": t0,
        })
        _send_frame(sock, data)
        resp = _recv_json(sock)
        if resp.get("v") != PROTOCOL_VERSION or not isinstance(resp.get("exit"), int):
            return None
        out = _recv_frame(sock)
        err = _recv_frame(sock)
    except (OSError, ValueError, ConnectionError, struct.error):
        return None
    finally:
        sock.close()

    for stream, payload in ((sys.stdout, out), (sys.stderr, err)):
        if not payload:
            continue
        try:
            stream.flush()
            stream.buffer.write(payload)
            stream.buffer.flush()
        except (AttributeError, OSError, ValueError):
            pass
    return int(resp["exit"])


_BOOT = (
    "import json, os, sys\n"
    "sys.path[:] = json.loads(os.environ.pop({env!r}))\n"
    "from prismor.runtime.hookd import serve\n"
    "sys.exit(serve())\n"
)

# The daemon parent's own environment. Children run with the CLIENT's full
# environment, so nothing here is visible to policy evaluation; this only keeps
# a hook's secrets and project-specific variables out of a long-lived process.
_PASSTHROUGH_ENV = (
    "HOME", "USER", "LOGNAME", "PATH", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR",
    "PRISMOR_HOME", "PRISMOR_HOOKD_IDLE", "SYSTEMROOT",
)


def _autostart(key: str, sys_path: List[str]) -> bool:
    run = _ensure_run_dir()
    if run is None:
        return False
    stamp = os.path.join(run, f"hookd-{key}.spawn")
    try:
        if time.time() - os.stat(stamp).st_mtime < _SPAWN_BACKOFF:
            return False
    except OSError:
        pass
    try:
        with open(stamp, "w"):
            pass
        os.utime(stamp)
    except OSError:
        return False
    return _spawn(sys_path)


def _spawn(sys_path: List[str]) -> bool:
    import subprocess

    env = {k: os.environ[k] for k in _PASSTHROUGH_ENV if k in os.environ}
    env[_SYSPATH_ENV] = json.dumps(sys_path)
    log_path = os.path.join(_run_dir(), "hookd.log")
    try:
        if os.path.exists(log_path) and os.path.getsize(log_path) > 1_000_000:
            os.replace(log_path, log_path + ".1")
        log = open(log_path, "ab")
    except OSError:
        log = subprocess.DEVNULL  # type: ignore[assignment]
    try:
        # -S: no site processing. sys.path is set explicitly from the client, so
        # site-packages are already on it, and skipping site keeps .pth hooks
        # from importing a *different* prismor before the path is fixed up.
        subprocess.Popen(
            [sys.executable, "-S", "-c", _BOOT.format(env=_SYSPATH_ENV)],
            env=env,
            cwd=_run_dir(),
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=log,
            start_new_session=True,
            close_fds=True,
        )
        return True
    except OSError:
        return False
    finally:
        if log is not subprocess.DEVNULL:
            log.close()


def request(op: str, key: Optional[str] = None, timeout: float = 2.0,
            socket_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Send a control op (ping/stop) to one daemon."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect(socket_path or _socket_path(key or install_key()))
    except OSError:
        sock.close()
        return None
    try:
        sock.settimeout(timeout)
        _send_json(sock, {"v": PROTOCOL_VERSION, "op": op})
        return _recv_json(sock)
    except (OSError, ValueError, ConnectionError, struct.error):
        return None
    finally:
        sock.close()


# ── Server ───────────────────────────────────────────────────────────────────

# Imported by the parent before it serves. Anything the hook path imports
# lazily and is missing here is simply imported by each child (correct, just
# slower); nothing on this list may start a thread or open a connection at
# import time, since the parent forks.
_WARM_MODULES = (
    "prismor.runtime.immunity_cli",
    "prismor.runtime.cli",
    "prismor.runtime.runtime",
    "prismor.runtime.hooks",
    "prismor.runtime.policy_engine",
    "prismor.runtime.store",
    "prismor.runtime.scanner",
    "prismor.runtime.sinks",
    "prismor.runtime.scoped_agent",
    "prismor.runtime.extensions",
    "prismor.runtime.token_usage",
    "prismor.runtime.mirror",
    "prismor.runtime.pause",
    "prismor.runtime.agents",
    "prismor.runtime.canary",
    "prismor.runtime.iam",
    "prismor.runtime.learning",
    "prismor.runtime.trifecta",
    "prismor.runtime.redaction",
    "prismor.runtime.data_boundary",
    "prismor.runtime.egress",
    "prismor.runtime.shell_context",
    "prismor.runtime.tag_rules",
    "prismor.runtime.semantic_guard",
    "prismor.runtime.semantic_guard_v2",
    "prismor.runtime.cloaking",
    "prismor.runtime.enterprise.identity",
    "prismor.runtime.enterprise.remote_policy",
    "prismor.runtime.enterprise.workspace_scope",
    "prismor.runtime.enterprise.receipt_signing",
    "prismor.runtime.enterprise.telemetry",
    "prismor.runtime.enterprise.telemetry_spool",
    "prismor.runtime.enterprise.heartbeat",
    "sqlite3",
    "subprocess",
    "urllib.request",
    "ssl",
    "hashlib",
    "uuid",
    "tempfile",
)


def _log(msg: str) -> None:
    try:
        sys.stderr.write(f"{time.strftime('%Y-%m-%dT%H:%M:%S')} hookd[{os.getpid()}] {msg}\n")
        sys.stderr.flush()
    except Exception:
        pass


def _warm() -> None:
    import importlib

    for name in _WARM_MODULES:
        try:
            importlib.import_module(name)
        except Exception as exc:
            _log(f"warm import {name} failed: {exc!r}")
    # Content-keyed caches only: the default policy's parsed YAML and its
    # compiled regexes. No workspace, no enrollment, no network.
    try:
        from prismor.runtime import immunity_cli

        immunity_cli._prismor_commands()
        from prismor.runtime import cli

        cli._PARSER = cli.build_parser()
    except Exception as exc:
        _log(f"warm command table failed: {exc!r}")
    try:
        from prismor.runtime.policy_engine import PolicyEngine

        PolicyEngine()
    except Exception as exc:
        _log(f"warm policy engine failed: {exc!r}")


def _package_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _fingerprint() -> str:
    """Stat-level fingerprint of the prismor package. Changes on upgrade/edit."""
    import hashlib

    h = hashlib.sha256()
    root = _package_root()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d != "__pycache__" and not d.startswith("."))
        for name in sorted(filenames):
            if not name.endswith((".py", ".yaml", ".yml", ".json")):
                continue
            path = os.path.join(dirpath, name)
            try:
                st = os.stat(path)
            except OSError:
                continue
            h.update(f"{path}\0{st.st_mtime_ns}\0{st.st_size}\n".encode("utf-8", "surrogateescape"))
    return h.hexdigest()


def _peer_ok(conn: socket.socket) -> bool:
    so_peercred = getattr(socket, "SO_PEERCRED", None)
    if so_peercred is None or not hasattr(os, "getuid"):
        # macOS/BSD: the 0700 run directory and 0600 socket are the boundary.
        return True
    try:
        creds = conn.getsockopt(socket.SOL_SOCKET, so_peercred, struct.calcsize("3i"))
        _pid, uid, _gid = struct.unpack("3i", creds)
    except OSError:
        return False
    return uid == os.getuid()


class _Server:
    def __init__(self, key: str, listener: socket.socket, lock_fd: int, listener_ino: int) -> None:
        self.key = key
        self.listener = listener
        self.listener_ino = listener_ino
        self.lock_fd = lock_fd
        self.started = time.time()
        self.served = 0
        self.fallbacks = 0
        self.fingerprint = _fingerprint()
        self.fingerprint_at = time.monotonic()
        self.stopping = False

    def stale(self) -> bool:
        now = time.monotonic()
        if now - self.fingerprint_at < _FINGERPRINT_INTERVAL:
            return False
        self.fingerprint_at = now
        return _fingerprint() != self.fingerprint

    def handle(self, conn: socket.socket) -> None:
        if not _peer_ok(conn):
            return
        conn.settimeout(5.0)
        try:
            header = _recv_json(conn)
        except (OSError, ValueError, ConnectionError, struct.error):
            return
        if header.get("v") != PROTOCOL_VERSION:
            _try_send(conn, {"v": PROTOCOL_VERSION, "error": "protocol"})
            return
        op = header.get("op")
        if op == "ping":
            from prismor.runtime import __version__

            _try_send(conn, {
                "v": PROTOCOL_VERSION, "ok": True, "pid": os.getpid(), "version": __version__,
                "started": self.started, "served": self.served, "key": self.key,
                "package": _package_root(), "python": sys.executable,
            })
            return
        if op == "stop":
            self.stopping = True
            _try_send(conn, {"v": PROTOCOL_VERSION, "ok": True})
            return
        if op != "hook":
            _try_send(conn, {"v": PROTOCOL_VERSION, "error": "op"})
            return
        argv = header.get("argv")
        if header.get("key") != self.key or not isinstance(argv, list) or argv[:1] != ["hook-dispatch"]:
            _try_send(conn, {"v": PROTOCOL_VERSION, "error": "request"})
            return
        if self.stale():
            # Code on disk changed under us: decline (the client evaluates
            # in-process) and exit so the next call starts a fresh daemon.
            _log("package changed on disk; exiting")
            self.stopping = True
            _try_send(conn, {"v": PROTOCOL_VERSION, "error": "stale"})
            return
        try:
            data = _recv_frame(conn)
        except (OSError, ConnectionError, struct.error):
            return
        try:
            pid = os.fork()
        except OSError as exc:
            _log(f"fork failed: {exc!r}")
            _try_send(conn, {"v": PROTOCOL_VERSION, "error": "fork"})
            return
        if pid == 0:
            code = 70
            try:
                code = _child(self, conn, header, data)
            finally:
                os._exit(code)
        self.served += 1

    def close(self) -> None:
        path = _socket_path(self.key)
        try:
            # Only unlink the socket if it is still ours.
            if os.stat(path).st_ino == self.listener_ino:
                os.unlink(path)
        except OSError:
            pass
        try:
            self.listener.close()
        except OSError:
            pass


def _try_send(conn: socket.socket, obj: Dict[str, Any]) -> None:
    try:
        _send_json(conn, obj)
    except OSError:
        pass


def _anon_fd() -> int:
    """An anonymous, seekable file descriptor (memfd on Linux, else unlinked temp)."""
    if hasattr(os, "memfd_create"):
        return os.memfd_create("prismor-hookd", 0)
    import tempfile

    fd, path = tempfile.mkstemp(prefix="hookd-", dir=_run_dir())
    os.unlink(path)
    return fd


def _read_all(fd: int) -> bytes:
    os.lseek(fd, 0, os.SEEK_SET)
    chunks = []
    while True:
        chunk = os.read(fd, 1 << 20)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


def _reset_import_time_state(header: Dict[str, Any]) -> None:
    """Re-derive the few values modules compute at import time from the process
    environment — imported in the parent, they would otherwise describe the
    daemon rather than this call."""
    cli = sys.modules.get("prismor.runtime.cli")
    if cli is not None and hasattr(cli, "_HOOK_T0"):
        try:
            cli._HOOK_T0 = float(os.environ.get("PRISMOR_HOOK_T0") or 0) or float(header.get("t0") or time.time())
        except ValueError:
            cli._HOOK_T0 = float(header.get("t0") or time.time())
    sweep = sys.modules.get("prismor.runtime.sweep")
    if sweep is not None and hasattr(sweep, "PRISMOR_HOME"):
        from pathlib import Path

        sweep.PRISMOR_HOME = Path(os.environ.get("PRISMOR_HOME", Path.home() / ".prismor"))


def _exit_code(value: Any) -> int:
    """Mirror the interpreter's handling of ``SystemExit.code``."""
    if value is None:
        return 0
    if isinstance(value, int):
        return value & 0xFF
    try:
        sys.stderr.write(f"{value}\n")
    except Exception:
        pass
    return 1


def _child(server: _Server, conn: socket.socket, header: Dict[str, Any], data: bytes) -> int:
    global _IN_CHILD, _DRAINING
    import atexit
    import signal

    signal.signal(signal.SIGCHLD, signal.SIG_DFL)
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    try:
        server.listener.close()
    except OSError:
        pass
    try:
        # A child still draining telemetry must not keep the next daemon from
        # taking the single-instance lock.
        os.close(server.lock_fd)
    except OSError:
        pass
    _IN_CHILD = True
    atexit._clear()  # handlers registered by the parent's imports are not ours

    try:
        env = header.get("env") or {}
        os.environ.clear()
        os.environ.update({str(k): str(v) for k, v in env.items()})
        os.umask(int(header.get("umask", 0o022)))
        os.chdir(str(header["cwd"]))
        sys.argv = [str(a) for a in (header.get("sys_argv") or ["prismor"])]

        in_fd, out_fd, err_fd = _anon_fd(), _anon_fd(), _anon_fd()
        os.write(in_fd, data)
        os.lseek(in_fd, 0, os.SEEK_SET)
        os.dup2(in_fd, 0)
        os.dup2(out_fd, 1)
        os.dup2(err_fd, 2)
        sys.stdin = open(0, "r", encoding=header.get("stdin_encoding") or "utf-8",
                         errors=header.get("stdin_errors") or "strict", closefd=False)
        sys.stdout = open(1, "w", encoding="utf-8", errors="replace", closefd=False)
        sys.stderr = open(2, "w", encoding="utf-8", errors="replace", closefd=False)
        _reset_import_time_state(header)
    except Exception as exc:
        _log(f"child setup failed: {exc!r}")
        _try_send(conn, {"v": PROTOCOL_VERSION, "error": "setup"})
        return 70

    code = 0
    try:
        from prismor.runtime.immunity_cli import main

        main([str(a) for a in header["argv"]])
    except SystemExit as exc:
        code = _exit_code(exc.code)
    except BaseException:
        import traceback

        traceback.print_exc()
        code = 1
    try:
        atexit._run_exitfuncs()
    except Exception:
        pass
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.flush()
        except Exception:
            pass

    try:
        conn.settimeout(10.0)
        _send_json(conn, {"v": PROTOCOL_VERSION, "exit": code})
        _send_frame(conn, _read_all(out_fd))
        _send_frame(conn, _read_all(err_fd))
    except OSError:
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass

    # Verdict delivered — now the work nothing is waiting on.
    _DRAINING = True
    for fn, args, kwargs in _DEFERRED:
        try:
            fn(*args, **kwargs)
        except Exception:
            pass
    import threading

    deadline = time.monotonic() + _CHILD_THREAD_GRACE
    for t in threading.enumerate():
        if t is threading.current_thread():
            continue
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        t.join(remaining)
    return code


def serve() -> int:
    """Run the daemon in the foreground until idle, stopped, or stale."""
    import signal

    from prismor.runtime.store import try_lock_exclusive

    if not enabled():
        return 1
    run = _ensure_run_dir()
    if run is None:
        _log("run directory unusable; not starting")
        return 1
    key = install_key(list(sys.path))
    lock_fd = os.open(os.path.join(run, f"hookd-{key}.lock"), os.O_RDWR | os.O_CREAT, 0o600)
    if not try_lock_exclusive(lock_fd):
        os.close(lock_fd)
        return 0  # another daemon for this install already owns the socket

    path = _socket_path(key)
    try:
        os.unlink(path)  # we hold the lock, so any existing socket is stale
    except FileNotFoundError:
        pass
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    old_umask = os.umask(0o177)
    try:
        listener.bind(path)
    finally:
        os.umask(old_umask)
    os.chmod(path, 0o600)
    listener.listen(128)

    _warm()
    server = _Server(key, listener, lock_fd, os.stat(path).st_ino)

    def _terminate(_signum, _frame):
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, _terminate)
    signal.signal(signal.SIGINT, _terminate)
    # Children are never waited on individually; let the kernel reap them.
    signal.signal(signal.SIGCHLD, signal.SIG_IGN)

    _log(f"serving {path} (python={sys.executable}, package={_package_root()})")
    last_activity = time.monotonic()
    try:
        while not server.stopping:
            idle_left = _IDLE_TIMEOUT - (time.monotonic() - last_activity)
            if idle_left <= 0:
                _log("idle; exiting")
                break
            listener.settimeout(min(60.0, idle_left))
            try:
                conn, _ = listener.accept()
            except socket.timeout:
                continue
            except InterruptedError:
                continue
            last_activity = time.monotonic()
            try:
                server.handle(conn)
            except Exception as exc:
                _log(f"request failed: {exc!r}")
            finally:
                try:
                    conn.close()
                except OSError:
                    pass
            if not os.path.exists(path):
                _log("socket removed; exiting")
                break
    finally:
        server.close()
        _log(f"stopped after {server.served} request(s)")
    return 0


# ── `prismor hookd` ──────────────────────────────────────────────────────────


def _daemon_sockets() -> List[str]:
    try:
        names = os.listdir(_sock_dir())
    except OSError:
        return []
    return sorted(os.path.join(_sock_dir(), n) for n in names if n.startswith("hookd-") and n.endswith(".sock"))


def cli_main(action: str) -> int:
    """``prismor hookd status|stop|restart``.

    Daemons are keyed by the hook's interpreter and import path, which a
    terminal invocation of ``prismor`` generally doesn't share — so these act
    on every daemon in the run directory rather than guessing which one the
    hooks use. There is no ``start``: the next hook call starts one.
    """
    if not hasattr(os, "fork") or not hasattr(socket, "AF_UNIX"):
        print("hookd: not supported on this platform — hooks run in-process.")
        return 1
    if _mode() in ("0", "off", "false", "no", "disabled"):
        print("hookd: disabled by PRISMOR_HOOKD in this shell — hooks without it still use the daemon.")
    running = []
    for path in _daemon_sockets():
        info = request("ping", socket_path=path, timeout=0.5)
        if info and info.get("ok"):
            running.append((path, info))
    if action == "status":
        if not running:
            print("hookd: not running — the next hook call starts it (PRISMOR_HOOKD=0 disables).")
            return 1
        for path, info in running:
            up = int(time.time() - float(info.get("started") or time.time()))
            print(f"hookd: running  pid={info.get('pid')}  version={info.get('version')}  "
                  f"uptime={up}s  served={info.get('served')}")
            print(f"       socket  {path}")
            print(f"       python  {info.get('python')}")
            print(f"       package {info.get('package')}")
        return 0
    if action in ("stop", "restart"):
        for path, _info in running:
            request("stop", socket_path=path, timeout=1.0)
        if not running:
            print("hookd: not running.")
        elif action == "stop":
            print(f"hookd: stopped {len(running)} daemon(s). The next hook call starts a fresh one "
                  "unless PRISMOR_HOOKD=0.")
        else:
            print(f"hookd: stopped {len(running)} daemon(s); the next hook call starts a fresh one.")
        return 0
    print(f"hookd: unknown action {action!r}")
    return 2
