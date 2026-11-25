"""The gateway answers over real pipes without waiting for the next request.

Windows held a reply back until the client wrote again (a blocking stdin read
serialises writes on the pipe), so this drives `mcp-gateway --mirror` as a
subprocess and checks each reply arrives while stdin stays open.
Also: Write is byte-exact, Bash picks PowerShell on Windows, shape_call_event
makes relative paths absolute.
"""
import json
import os
import queue
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from prismor.runtime import mirror


def _rpc(i, method, params=None):
    return json.dumps({"jsonrpc": "2.0", "id": i, "method": method, "params": params or {}}) + "\n"


def test_replies_arrive_before_next_request(tmp_path):
    env = dict(os.environ, PRISMOR_HOME=str(tmp_path / "home"))
    env.pop("PRISMOR_WORKSPACE", None)
    proc = subprocess.Popen(
        [sys.executable, "-m", "prismor.runtime.immunity_cli", "mcp-gateway", "--mirror",
         "--workspace", str(tmp_path)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env)
    lines: "queue.Queue[bytes]" = queue.Queue()
    threading.Thread(target=lambda: [lines.put(l) for l in proc.stdout], daemon=True).start()
    try:
        proc.stdin.write(_rpc(1, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                                "clientInfo": {"name": "t", "version": "1"}}).encode())
        proc.stdin.flush()
        assert json.loads(lines.get(timeout=30))["id"] == 1
        proc.stdin.write(_rpc(2, "ping").encode())
        proc.stdin.flush()
        reply = json.loads(lines.get(timeout=15))  # stdin still open: no 2nd request needed
        assert reply["id"] == 2
    finally:
        proc.kill()
        proc.wait()


def test_write_is_byte_exact(tmp_path):
    out = mirror.execute("Write", {"file_path": str(tmp_path / "a"), "content": "a\nb\n"}, tmp_path)
    assert (tmp_path / "a").read_bytes() == b"a\nb\n" and "4 bytes" in out
    out = mirror.execute("Write", {"file_path": str(tmp_path / "b"), "content": "x\r\ny\r\n"}, tmp_path)
    assert (tmp_path / "b").read_bytes() == b"x\r\ny\r\n" and "6 bytes" in out


def test_edit_keeps_crlf(tmp_path):
    (tmp_path / "c").write_bytes(b"one\r\ntwo\r\nthree\r\n")
    mirror.execute("Edit", {"file_path": str(tmp_path / "c"),
                            "old_string": "one\ntwo", "new_string": "1\n2"}, tmp_path)
    assert (tmp_path / "c").read_bytes() == b"1\r\n2\r\nthree\r\n"


def test_shell_is_powershell_on_windows(monkeypatch):
    monkeypatch.delenv("PRISMOR_MIRROR_SHELL", raising=False)
    monkeypatch.setattr(mirror.os, "name", "nt")
    argv = mirror._shell_argv("Remove-Item x")
    assert argv[1:4] == ["-NoProfile", "-NonInteractive", "-Command"]
    assert argv[4] == "Remove-Item x; exit $LASTEXITCODE"
    monkeypatch.setenv("PRISMOR_MIRROR_SHELL", "bash -c")
    assert mirror._shell_argv("ls") == ["bash", "-c", "ls"]


def test_shell_default_untouched_on_posix(monkeypatch):
    monkeypatch.delenv("PRISMOR_MIRROR_SHELL", raising=False)
    if os.name == "posix":
        assert mirror._shell_argv("ls") is None


def test_event_paths_absolute_and_unaltered(tmp_path):
    ws = tmp_path
    ev = mirror.shape_call_event("Read", {"file_path": r"C:\Users\Me\.aws\credentials"}, ws)
    assert ev == {"type": "file_read", "path": r"C:\Users\Me\.aws\credentials"}
    ev = mirror.shape_call_event("Write", {"file_path": r".prismor\policy.yaml", "content": "x"}, ws)
    assert ev["type"] == "file_write" and ev["path"] == os.path.join(str(ws), r".prismor\policy.yaml")
    ev = mirror.shape_call_event("Write", {"file_path": r"\\srv\share\x", "content": "x"}, ws)
    assert ev["path"] == r"\\srv\share\x"


def test_gateway_resolves_npx_via_which(monkeypatch):
    import prismor.runtime.mcp_gateway as gw
    seen = {}

    def fake_popen(argv, **kw):
        seen["argv"] = argv
        raise OSError("stop")

    monkeypatch.setattr(gw.os, "name", "nt")
    monkeypatch.setattr(gw.shutil, "which", lambda c, path=None: r"C:\nodejs\npx.cmd")
    monkeypatch.setattr(gw.subprocess, "Popen", fake_popen)
    up = gw.UpstreamStdio(gw.UpstreamSpec(name="x", command=["npx", "-y", "pkg"], transport="stdio"))
    with pytest.raises(gw.UpstreamError):
        up._spawn()
    assert seen["argv"] == [r"C:\nodejs\npx.cmd", "-y", "pkg"]
