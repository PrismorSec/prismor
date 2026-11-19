"""Gateway idle stop: a stdio upstream with idleTimeout is stopped when idle,
list calls are answered from the last reply, and the next call restarts it
with the client's handshake.

Run: python3 -m pytest tests/test_gateway_idle_stop.py
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO))

from prismor.runtime.mcp_gateway import UpstreamError, UpstreamSpec, UpstreamStdio  # noqa: E402

# Refuses tools/call until it has seen the handshake, so a restart that skips
# `initialize` fails the test. Appends one line per start to argv[1].
_SERVER = r'''
import json, sys
open(sys.argv[1], "a").write("start\n")
ready = False
for line in sys.stdin:
    msg = json.loads(line)
    m, i = msg.get("method"), msg.get("id")
    if m == "notifications/initialized":
        ready = True
        continue
    if i is None:
        continue
    if m == "initialize":
        r = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}}, "serverInfo": {"name": "f", "version": "1"}}
    elif m == "tools/list":
        r = {"tools": [{"name": "echo", "inputSchema": {"type": "object"}}]}
    elif m == "tools/call" and ready:
        r = {"content": [{"type": "text", "text": "ok"}]}
    else:
        print(json.dumps({"jsonrpc": "2.0", "id": i, "error": {"code": -32600, "message": "not initialized"}}), flush=True)
        continue
    print(json.dumps({"jsonrpc": "2.0", "id": i, "result": r}), flush=True)
'''

_INIT = {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}


def _upstream(tmp_path, idle):
    script = tmp_path / "server.py"
    script.write_text(_SERVER)
    starts = tmp_path / "starts"
    spec = UpstreamSpec(name="fake", command=[sys.executable, str(script), str(starts)],
                        transport="stdio", idle_timeout=idle, inherit_env=True)
    return UpstreamStdio(spec), starts


def _wait(cond, secs=5.0):
    end = time.monotonic() + secs
    while time.monotonic() < end and not cond():
        time.sleep(0.05)
    return cond()


def test_idle_stop_caches_lists_and_restarts_with_handshake(tmp_path):
    up, starts = _upstream(tmp_path, idle=0.4)
    try:
        up.initialize(_INIT)
        tools = up.request("tools/list", {})
        proc = up._proc
        assert _wait(lambda: up.idle_stops == 1), "server was not stopped when idle"
        assert proc.poll() is not None and up._proc is None

        assert up.request("tools/list", {}) == tools      # from cache, no restart
        assert up._proc is None and starts.read_text().count("start") == 1

        result = up.request("tools/call", {"name": "echo", "arguments": {}})
        assert result["content"][0]["text"] == "ok"        # handshake was repeated
        assert up.idle_restarts == 1 and starts.read_text().count("start") == 2
    finally:
        up.close()


def test_no_idle_stop_without_timeout(tmp_path):
    up, _ = _upstream(tmp_path, idle=0)
    try:
        up.initialize(_INIT)
        up.request("tools/list", {})
        time.sleep(1.0)
        assert up._proc is not None and up._proc.poll() is None and up.idle_stops == 0
    finally:
        up.close()


def test_never_stops_before_the_handshake(tmp_path):
    up, _ = _upstream(tmp_path, idle=0.2)
    try:
        try:
            up.request("tools/list", {})  # no initialize: there is nothing to repeat
        except UpstreamError:
            pass
        time.sleep(0.8)
        assert up.idle_stops == 0
    finally:
        up.close()


def test_idle_timeout_from_config_entry():
    from prismor.runtime.mcp_gateway import _spec_from_entry
    assert _spec_from_entry("a", {"command": "x", "idleTimeout": 900}).idle_timeout == 900
    assert _spec_from_entry("a", {"command": "x"}).idle_timeout == 0
