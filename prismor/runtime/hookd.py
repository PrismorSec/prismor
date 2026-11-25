"""Opt-in warm hook server: ``PRISMOR_HOOKD=1`` in the agent's environment.

A hook process spends most of its life getting ready: interpreter start,
~300 module imports and ~450 regex compiles, then ~20 ms deciding. This keeps
one process per user (and per interpreter + configuration) that has done the
imports and filled the ``re`` cache, and forks it once per hook call. The
fork runs the very same ``immunity_cli.main()`` a fresh process would, with
the caller's argv, environment, cwd, umask and stdin, so policy, findings,
telemetry and the audit chain come out of identical code against files read
fresh on every call. The server itself never loads a policy or touches the
store: nothing it holds can go stale, and a policy change (or the unlock flow)
takes effect on the next call exactly as it does today.

The client (the dispatch shim) only uses the server when it can prove it is
ours: requests and replies carry an HMAC under ``hookd.key`` in Prismor home,
a file the self-edit rule keeps the agent from reading. Anything else -- no
server, a connect slower than ``CONNECT_TIMEOUT``, a bad or missing reply, a
reply slower than ``PRISMOR_HOOKD_TIMEOUT`` -- returns ``None`` and the shim
evaluates in-process as before. Nothing is written to the agent until a reply
verifies, so a fallback never mixes two outputs. POSIX only (needs fork and
unix sockets); elsewhere the shim always runs in-process.

The client half is imported by every hook call, so it sticks to builtins.
"""
from __future__ import annotations

import marshal
import os
import sys

CONNECT_TIMEOUT = 0.15
IDLE_EXIT = 1800.0
_V = 1
_MAX_FRAME = 64 << 20


def _sha256(data: bytes) -> bytes:
    try:
        from _sha2 import sha256
    except ImportError:  # pragma: no cover - builds without the builtin
        from hashlib import sha256
    return sha256(data).digest()


def _mac(key: bytes, data: bytes) -> bytes:
    """HMAC-SHA256 from the builtin hash: the hmac module costs ~5 ms to import."""
    key = key.ljust(64, b"\0")
    return _sha256(bytes(b ^ 0x5C for b in key) + _sha256(bytes(b ^ 0x36 for b in key) + data))


def _home() -> str:
    return os.environ.get("PRISMOR_HOME") or os.path.join(os.path.expanduser("~"), ".prismor")


def _paths() -> tuple:
    """(key file, socket, spawn marker). One server per interpreter, import
    path and Prismor configuration: env read at import time must match."""
    ident = repr((sys.executable, sys.path, os.environ.get("HOME"),
                  sorted((k, v) for k, v in os.environ.items() if k.startswith("PRISMOR_") and k != "PRISMOR_HOOK_T0")))
    tag = _sha256(ident.encode("utf-8", "surrogateescape")).hex()[:12]
    home = _home()
    return (os.path.join(home, "hookd.key"), os.path.join(home, f"hookd-{tag}.sock"),
            os.path.join(home, f"hookd-{tag}.spawn"))


def _recv_all(conn, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = conn.recv(min(n - len(buf), 1 << 20))
        if not chunk:
            raise EOFError
        buf += chunk
    return bytes(buf)


def _frame(mac: bytes, payload: bytes) -> bytes:
    return mac + len(payload).to_bytes(4, "big") + payload


def _read_frame(conn) -> tuple:
    head = _recv_all(conn, 36)
    n = int.from_bytes(head[32:], "big")
    if n > _MAX_FRAME:
        raise ValueError("frame too large")
    return head[:32], _recv_all(conn, n)


# ── client ──────────────────────────────────────────────────────────────────

def run_client():
    """Run this hook call on the warm server. Returns the exit code, or
    ``None`` (having written nothing) when the caller must run in-process."""
    if os.environ.get("PRISMOR_HOOKD") != "1" or not hasattr(os, "fork") or sys.argv[1:2] != ["hook-dispatch"]:
        return None
    import io
    enc, errs = "utf-8", "replace"  # never the locale codec (cp1252 on Windows)
    if hasattr(sys.stdin, "buffer"):
        data = sys.stdin.buffer.read()
        if data.startswith(b"\xef\xbb\xbf"):
            data = data[3:]
        # The in-process fallback reads the same bytes, decoded as it would have.
        sys.stdin = io.TextIOWrapper(io.BytesIO(data), encoding=enc, errors=errs, newline="\n")
    else:  # already text (scripts/dev-hook.py hands over a StringIO)
        text = sys.stdin.read()
        sys.stdin = io.StringIO(text)
        enc, errs = "utf-8", "surrogateescape"
        data = text.encode(enc, errs)
    try:
        return _call(data, enc, errs)
    except Exception:
        return None


def _call(data: bytes, enc: str, errs: str):
    import _socket
    from _operator import _compare_digest
    key_path, sock_path, marker = _paths()
    if len(sock_path.encode()) > 100:  # sun_path limit (104 on macOS)
        return None
    try:
        with open(key_path, "rb") as fh:
            key = fh.read()
    except OSError:
        key = b""
    conn = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
    try:
        conn.settimeout(CONNECT_TIMEOUT)
        try:
            if len(key) < 32:
                raise ConnectionRefusedError
            conn.connect(sock_path)
        except (FileNotFoundError, ConnectionRefusedError):
            _spawn(marker)
            return None
        except OSError:
            return None
        nonce = os.urandom(16)
        umask = os.umask(0)
        os.umask(umask)
        payload = marshal.dumps((_V, nonce, sys.argv[1:], dict(os.environ), os.getcwd(), umask, data,
                                 enc, errs, sys.argv[0]))
        conn.settimeout(float(os.environ.get("PRISMOR_HOOKD_TIMEOUT") or 15))
        conn.sendall(_frame(_mac(key, payload), payload))
        mac, reply = _read_frame(conn)
    finally:
        conn.close()
    if not _compare_digest(mac, _mac(key, nonce + reply)):
        return None
    code, out, err = marshal.loads(reply)  # nosec B302 - only after its HMAC verified
    if type(code) is not int or type(out) is not bytes or type(err) is not bytes:
        return None
    for fd, chunk in ((1, out), (2, err)):
        while chunk:
            chunk = chunk[os.write(fd, chunk):]
    return code


def _spawn(marker: str) -> None:
    """Start a server in the background for the next call; this one runs
    in-process. The marker keeps a burst of parallel hooks to one spawn."""
    import time
    try:
        if time.time() - os.stat(marker).st_mtime < 30:
            return
        os.unlink(marker)
    except OSError:
        pass
    try:
        os.close(os.open(marker, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
    except OSError:
        return
    import subprocess
    code = f"import sys; sys.path[:] = {sys.path!r}; from prismor.runtime.hookd import serve; serve()"
    subprocess.Popen([sys.executable, "-c", code], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL, start_new_session=True, close_fds=True, cwd=_home())


# ── server ──────────────────────────────────────────────────────────────────

_WARM_PAYLOADS = (
    ("PreToolUse", "Bash", {"command": "git status && ls -la"}),
    ("PreToolUse", "Read", {"file_path": "README.md"}),
    ("PreToolUse", "Write", {"file_path": "notes.md", "content": "x"}),
    ("PreToolUse", "WebFetch", {"url": "https://example.com/", "prompt": "x"}),
    ("PostToolUse", "Bash", {"command": "git status"}),
    ("UserPromptSubmit", "", {}),
)


def _profile() -> tuple:
    """Module names and regexes a few typical hook calls use, recorded in a
    throwaway fork against a scratch home and workspace. The server takes only
    these names and pattern strings from it, never its state."""
    import tempfile
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            os.close(r)
            import signal
            signal.alarm(20)  # a profile run that hangs must not hang the server
            import io
            import json
            import re
            import shutil
            seen: dict = {}
            real = re._compile

            def _record(pattern, flags):
                if isinstance(pattern, (str, bytes)):
                    seen.setdefault((pattern, int(flags)), None)
                return real(pattern, flags)
            re._compile = _record
            scratch = tempfile.mkdtemp(prefix="prismor-hookd-warm-")
            os.environ.clear()
            os.environ.update(HOME=scratch, PRISMOR_HOME=os.path.join(scratch, ".prismor"), PATH="/usr/bin:/bin")
            os.chdir(scratch)
            devnull = os.open(os.devnull, os.O_RDWR)
            os.dup2(devnull, 1)
            os.dup2(devnull, 2)
            from prismor.runtime.immunity_cli import main
            for i, (event, tool, tool_input) in enumerate(_WARM_PAYLOADS):
                payload = {"hook_event_name": event, "session_id": "warm", "cwd": scratch,
                           "tool_name": tool, "tool_input": tool_input, "tool_use_id": f"warm-{i}", "prompt": "hi"}
                sys.stdin = io.StringIO(json.dumps(payload))
                try:
                    main(["hook-dispatch", "--agent", "claude", "--workspace", scratch, "--mode", "enforce"])
                except BaseException:  # noqa: BLE001 - SystemExit is the normal exit
                    pass
            shutil.rmtree(scratch, ignore_errors=True)
            out = marshal.dumps((sorted(sys.modules), list(seen)))
            while out:
                out = out[os.write(w, out):]
        finally:
            os._exit(0)
    os.close(w)
    chunks = []
    while True:
        chunk = os.read(r, 1 << 20)
        if not chunk:
            break
        chunks.append(chunk)
    os.close(r)
    os.waitpid(pid, 0)
    return marshal.loads(b"".join(chunks)) if chunks else ([], [])  # nosec B302 - our own fork's pipe


def _code_mtimes() -> dict:
    roots = tuple(os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + s
                  for s in ("", os.sep + ".." + os.sep + "supplychain"))
    out = {}
    for mod in list(sys.modules.values()):
        f = getattr(mod, "__file__", None)
        if f and os.path.abspath(f).startswith(tuple(os.path.normpath(r) for r in roots)):
            try:
                out[f] = os.stat(f).st_mtime_ns
            except OSError:
                pass
    return out


def _stale(mtimes: dict) -> bool:
    for f, m in mtimes.items():
        try:
            if os.stat(f).st_mtime_ns != m:
                return True
        except OSError:
            return True
    return False


def serve() -> None:
    import importlib
    import re
    import socket
    import threading
    import time
    key_path, sock_path, marker = _paths()
    try:
        os.makedirs(os.path.dirname(key_path), exist_ok=True)
        try:
            fd = os.open(key_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.write(fd, os.urandom(32))
            os.close(fd)
        except FileExistsError:
            pass
        with open(key_path, "rb") as fh:
            key = fh.read()
        if len(key) < 32:
            return
        modules, patterns = _profile()
        for name in modules:
            try:
                importlib.import_module(name)
            except BaseException:  # noqa: BLE001 - a module that will not preload is simply not warm
                pass
        for pattern, flags in patterns:
            try:
                re.compile(pattern, flags)
            except Exception:  # nosec B112 - same: an uncompilable pattern stays cold
                continue
        try:  # the parsed default policy: that cache is keyed by file content, so it cannot go stale
            from prismor.runtime import policy_engine
            policy_engine._load_yaml(policy_engine._DEFAULT_POLICY_PATH)
        except Exception:  # nosec B110 - an unwarmed cache only costs the parse
            pass
        # fork() from a threaded process can deadlock the child.
        if threading.active_count() != 1:
            return
        mtimes = _code_mtimes()
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        old = os.umask(0o077)
        try:
            try:
                probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                probe.settimeout(CONNECT_TIMEOUT)
                probe.connect(sock_path)
                probe.close()
                return  # another server already answers here
            except OSError:
                try:
                    os.unlink(sock_path)
                except FileNotFoundError:
                    pass
            listener.bind(sock_path)
        finally:
            os.umask(old)
        listener.listen(64)
        inode = os.stat(sock_path).st_ino
    finally:
        try:
            os.unlink(marker)
        except OSError:
            pass
    listener.settimeout(1.0)
    last = time.monotonic()
    try:
        while time.monotonic() - last < IDLE_EXIT:
            try:
                while os.waitpid(-1, os.WNOHANG)[0]:
                    pass
            except ChildProcessError:
                pass
            try:
                conn, _ = listener.accept()
            except socket.timeout:
                try:  # socket removed or replaced (home deleted, a newer server): stop
                    if os.stat(sock_path).st_ino != inode:
                        break
                except OSError:
                    break
                continue
            last = time.monotonic()
            try:
                with open(key_path, "rb") as fh:
                    rekeyed = fh.read() != key
                if rekeyed or os.stat(sock_path).st_ino != inode or _stale(mtimes):
                    conn.close()  # the client falls back; the next call starts a fresh server
                    break
            except OSError:
                conn.close()
                break
            sys.stdout.flush()
            sys.stderr.flush()
            pid = os.fork()
            if pid == 0:
                listener.close()
                _child(conn, key)
            conn.close()
    finally:
        listener.close()
        try:
            if os.stat(sock_path).st_ino == inode:
                os.unlink(sock_path)
        except OSError:
            pass


def _child(conn, key: bytes) -> None:
    """One hook call in a fork of the warm server. Never returns."""
    try:
        conn.setblocking(True)
        conn.settimeout(5.0)
        mac, payload = _read_frame(conn)
        from _operator import _compare_digest
        if not _compare_digest(mac, _mac(key, payload)):
            os._exit(0)
        v, nonce, argv, env, cwd, umask, data, enc, errs, argv0 = marshal.loads(payload)  # nosec B302 - HMAC verified above
        if v != _V or argv[:1] != ["hook-dispatch"]:
            os._exit(0)
        conn.settimeout(None)
        code, out, err = _run(argv0, argv, env, cwd, umask, data, enc, errs)
        reply = marshal.dumps((code, out, err))
        conn.sendall(_frame(_mac(key, nonce + reply), reply))
    except BaseException:  # noqa: BLE001 - no reply: the client runs the call itself
        pass
    finally:
        os._exit(0)


def _run(argv0, argv, env, cwd, umask, data, enc, errs) -> tuple:
    """Become the hook process the client would have been, run it, and
    return (exit code, stdout bytes, stderr bytes)."""
    import atexit
    import io
    import tempfile
    import threading
    os.environ.clear()
    os.environ.update(env)
    os.chdir(cwd)
    os.umask(umask)
    files = [tempfile.TemporaryFile() for _ in range(3)]
    files[0].write(data)
    files[0].seek(0)
    for fd, fh in enumerate(files):
        os.dup2(fh.fileno(), fd)
    # Fresh std streams, as interpreter start creates them (POSIX newline).
    sys.stdin = sys.__stdin__ = io.TextIOWrapper(io.open(0, "rb", closefd=False), encoding=enc,
                                                 errors=errs, newline="\n")
    sys.stdout = sys.__stdout__ = io.TextIOWrapper(io.open(1, "wb", closefd=False), encoding=enc,
                                                   errors="strict", newline="\n")
    sys.stderr = sys.__stderr__ = io.TextIOWrapper(io.open(2, "wb", closefd=False), encoding=enc,
                                                   errors="backslashreplace", newline="\n", line_buffering=True)
    sys.argv = [argv0, *argv]
    from prismor.runtime import cli, perf
    perf.reset()
    try:
        cli._HOOK_T0 = float(env.get("PRISMOR_HOOK_T0") or 0) or cli._HOOK_T0
    except ValueError:
        pass
    from prismor.runtime.immunity_cli import main
    try:
        code = main()
    except SystemExit as exc:
        code = exc.code
    except BaseException:  # noqa: BLE001 - what an uncaught error does to a fresh process
        import traceback
        traceback.print_exc()
        code = 1
    if code is None:
        code = 0
    elif type(code) is not int:
        try:
            sys.stderr.write(f"{code}\n")
        except Exception:  # nosec B110 - the exit code still reports the failure
            pass
        code = 1
    # Interpreter shutdown order: join threads, run atexit, flush the streams.
    try:
        threading._shutdown()
    except Exception:  # nosec B110 - a thread that will not join must not lose the reply
        pass
    atexit._run_exitfuncs()
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.flush()
        except Exception:  # nosec B110 - as at shutdown: a failed flush is dropped
            pass
    files[1].seek(0)
    files[2].seek(0)
    return code, files[1].read(), files[2].read()


if __name__ == "__main__":
    serve()
