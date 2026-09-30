"""Warm hook daemon (prismor/runtime/hookd.py).

The daemon is an accelerator, never a second policy engine, so the properties
worth pinning are: a daemon verdict is byte-identical to the in-process one;
every way the daemon can fail to answer falls back to in-process evaluation
with stdin intact; and best-effort network work leaves the verdict path.
"""
from __future__ import annotations

import io
import json
import os
import socket
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from prismor.runtime import hookd

REPO_ROOT = Path(__file__).resolve().parents[1]

pytestmark = pytest.mark.skipif(
    not hasattr(os, "fork") or not hasattr(socket, "AF_UNIX"),
    reason="hookd needs fork + AF_UNIX",
)


def _danger_command() -> str:
    # Assembled so this file doesn't itself read as the destructive command.
    return " ".join(["rm", "-" + "rf", "/", "--no-preserve-" + "root"])


def _payload(workspace: Path, **fields) -> bytes:
    base = {"hook_event_name": "PreToolUse", "session_id": "hookd-test", "cwd": str(workspace)}
    base.update(fields)
    return json.dumps(base).encode()


def _run_hook(workspace: Path, data: bytes, hookd_mode: str) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO_ROOT)
    env["PRISMOR_HOOKD"] = hookd_mode
    env["PRISMOR_NO_UPDATE_CHECK"] = "1"
    return subprocess.run(
        [sys.executable, "-m", "prismor.runtime.immunity_cli", "hook-dispatch",
         "--agent", "claude", "--mode", "enforce"],
        input=data, capture_output=True, cwd=str(workspace), env=env, timeout=120,
    )


def _live_daemons():
    out = []
    for path in hookd._daemon_sockets():
        info = hookd.request("ping", socket_path=path, timeout=1.0)
        if info and info.get("ok"):
            out.append((path, info))
    return out


@pytest.fixture
def workspace(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    subprocess.run(["git", "init", "-q", str(ws)], check=True)
    return ws


@pytest.fixture
def daemon(workspace):
    """A real daemon, auto-started the way a hook call starts it."""
    _run_hook(workspace, _payload(workspace, tool_name="Read", tool_input={"file_path": "x"}), "")
    deadline = time.time() + 20
    while time.time() < deadline and not _live_daemons():
        time.sleep(0.1)
    live = _live_daemons()
    assert live, "daemon did not start: " + _read_log()
    yield live[0]
    for path, _info in _live_daemons():
        hookd.request("stop", socket_path=path, timeout=2.0)


def _read_log() -> str:
    try:
        return Path(hookd._run_dir(), "hookd.log").read_text()
    except OSError:
        return "(no log)"


# ── end to end ───────────────────────────────────────────────────────────────


def test_daemon_verdicts_match_in_process(workspace, daemon):
    cases = {
        "allow": _payload(workspace, tool_name="Read", tool_input={"file_path": str(workspace / "a.txt")}),
        "block": _payload(workspace, tool_name="Bash", tool_input={"command": _danger_command()}),
        "prompt": _payload(workspace, hook_event_name="UserPromptSubmit", prompt="list the files"),
    }
    served_before = daemon[1]["served"]
    for name, data in cases.items():
        in_proc = _run_hook(workspace, data, "0")
        via_daemon = _run_hook(workspace, data, "manual")
        assert via_daemon.returncode == in_proc.returncode, name
        assert via_daemon.stdout == in_proc.stdout, name
        assert via_daemon.stderr == in_proc.stderr, name
    assert _run_hook(workspace, cases["block"], "manual").returncode == 2

    info = hookd.request("ping", socket_path=daemon[0])
    # Every "manual" call above was answered by the daemon, not the fallback.
    assert info["served"] - served_before == len(cases) + 1


def test_run_dir_and_socket_are_owner_only(daemon):
    path = daemon[0]
    assert stat.S_IMODE(os.stat(hookd._run_dir()).st_mode) == 0o700
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_stop_then_next_hook_restarts(workspace, daemon):
    assert hookd.cli_main("stop") == 0
    deadline = time.time() + 5
    while time.time() < deadline and _live_daemons():
        time.sleep(0.05)
    assert not _live_daemons()
    # No daemon: the call is still evaluated (in-process) and blocks.
    data = _payload(workspace, tool_name="Bash", tool_input={"command": _danger_command()})
    os.utime(Path(hookd._run_dir()) / next(
        n for n in os.listdir(hookd._run_dir()) if n.endswith(".spawn")), (0, 0))
    assert _run_hook(workspace, data, "").returncode == 2
    deadline = time.time() + 20
    while time.time() < deadline and not _live_daemons():
        time.sleep(0.1)
    assert _live_daemons(), "the next hook call should have started a fresh daemon"


# ── client fallbacks ─────────────────────────────────────────────────────────


def _fake_stdin(monkeypatch, data: bytes):
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(data), encoding="utf-8"))


def test_disabled_leaves_stdin_untouched(monkeypatch):
    monkeypatch.setenv("PRISMOR_HOOKD", "0")
    _fake_stdin(monkeypatch, b'{"a": 1}')
    assert hookd.dispatch(["hook-dispatch"]) is None
    assert sys.stdin.read() == '{"a": 1}'


def test_no_daemon_in_manual_mode_falls_back_without_spawning(monkeypatch):
    monkeypatch.setenv("PRISMOR_HOOKD", "manual")
    spawned = []
    monkeypatch.setattr(hookd, "_spawn", lambda *a, **k: spawned.append(a) or True)
    _fake_stdin(monkeypatch, b'{"b": 2}')
    assert hookd.dispatch(["hook-dispatch"]) is None
    assert spawned == []
    assert sys.stdin.read() == '{"b": 2}'


def test_autostart_is_rate_limited(monkeypatch):
    monkeypatch.setenv("PRISMOR_HOOKD", "")
    spawned = []
    monkeypatch.setattr(hookd, "_spawn", lambda *a, **k: spawned.append(a) or True)
    for _ in range(3):
        _fake_stdin(monkeypatch, b"{}")
        assert hookd.dispatch(["hook-dispatch"]) is None
    assert len(spawned) == 1


def test_daemon_that_drops_the_request_falls_back_with_stdin_intact(monkeypatch):
    """Accepted, then no verdict (a child crash, a kill) — evaluate in-process."""
    monkeypatch.setenv("PRISMOR_HOOKD", "manual")
    assert hookd._ensure_run_dir()
    path = hookd._socket_path(hookd.install_key())
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(path)
    server.listen(1)

    def _accept_and_drop():
        conn, _ = server.accept()
        conn.recv(64)
        conn.close()

    t = threading.Thread(target=_accept_and_drop, daemon=True)
    t.start()
    try:
        _fake_stdin(monkeypatch, b'{"tool_name": "Bash"}')
        assert hookd.dispatch(["hook-dispatch"]) is None
        assert sys.stdin.read() == '{"tool_name": "Bash"}'
    finally:
        t.join(5)
        server.close()
        os.unlink(path)


# ── deferral ─────────────────────────────────────────────────────────────────


def test_run_or_defer_runs_immediately_in_process():
    calls = []
    hookd.run_or_defer(calls.append, 1)
    assert calls == [1]


def test_run_or_defer_in_child_snapshots_and_defers(monkeypatch):
    monkeypatch.setattr(hookd, "_IN_CHILD", True)
    monkeypatch.setattr(hookd, "_DEFERRED", [])
    seen = []
    findings = [{"rule": "a"}]
    hookd.run_or_defer(lambda f: seen.append(f), findings)
    findings.append({"rule": "later-mutation"})
    assert seen == []
    fn, args, kwargs = hookd._DEFERRED[0]
    fn(*args, **kwargs)
    assert seen == [[{"rule": "a"}]]


def test_upload_telemetry_is_deferred_in_child(monkeypatch):
    from prismor.runtime import sinks
    from prismor.runtime.enterprise import identity

    monkeypatch.setattr(hookd, "_IN_CHILD", True)
    monkeypatch.setattr(hookd, "_DEFERRED", [])

    def _boom():
        raise AssertionError("upload ran on the verdict path")

    monkeypatch.setattr(identity, "load_identity", _boom)
    sinks.upload_telemetry([{"verdict": "blocked"}], timeout=1.0)
    assert len(hookd._DEFERRED) == 1


def test_long_prismor_home_gets_a_short_owner_only_socket_dir(monkeypatch, tmp_path):
    # AF_UNIX caps the path (104 bytes on macOS); binding past it failed outright.
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / ("x" * 120)))
    path = hookd._socket_path(hookd.install_key())
    assert len(path.encode()) <= 104
    assert hookd._ensure_run_dir()
    assert stat.S_IMODE(os.stat(os.path.dirname(path)).st_mode) == 0o700


def test_socket_dir_planted_as_a_symlink_disables_the_daemon(monkeypatch, tmp_path):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / ("y" * 120)))
    sock_dir = hookd._sock_dir()
    os.symlink(tmp_path, sock_dir)
    try:
        assert hookd._ensure_run_dir() is None
    finally:
        os.unlink(sock_dir)
