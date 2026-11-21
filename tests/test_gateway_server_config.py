"""Per-server gateway settings: tool overrides, tools/list cache TTL, call
timeout. Real stdio upstream (tests/fixtures/shop_mcp_server.py) and the real
policy engine."""

import sys
from pathlib import Path

import pytest
import yaml

from prismor.runtime.mcp_gateway import CALL_TIMEOUT, Gateway, _spec_from_entry

SERVER = Path(__file__).parent / "fixtures" / "shop_mcp_server.py"
ENTRY = {
    "command": sys.executable, "args": [str(SERVER)], "timeout": 7,
    "tools": {"cacheTtl": 300, "overrides": {
        "list_orders": {"name": "orders", "description": "Orders, newest first",
                        "inputSchema": {"type": "object", "properties": {"limit": {"type": "integer"}}}},
        "delete_doc": {"name": "remove"},
    }},
}


@pytest.fixture
def ws(tmp_path, monkeypatch):
    for k in [k for k in __import__("os").environ if k.startswith("PRISMOR")]:
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / "home"))
    (tmp_path / ".prismor").mkdir()
    (tmp_path / ".prismor" / "agents.yaml").write_text(yaml.safe_dump({"global_deny_tools": ["mcp__shop__delete_doc"]}))
    return tmp_path


def _session(ws, entry=ENTRY):
    g = Gateway([_spec_from_entry("shop", entry)], workspace=ws, mode="enforce")
    sent = []
    g._send = lambda m: sent.append(m)
    g._dispatch({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                 "params": {"protocolVersion": "2025-03-26", "clientInfo": {"name": "t"}}})
    return g, sent


def _list(g, sent):
    g._dispatch({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    return {t["name"]: t for t in sent[-1]["result"]["tools"]}


def test_entry_parses_server_settings():
    spec = _spec_from_entry("shop", ENTRY)
    assert spec.tools_ttl == 300 and spec.call_timeout == 7
    assert spec.overrides["delete_doc"] == {"name": "remove"}
    bare = _spec_from_entry("shop", {"command": "x", "timeout": True, "tools": {"cacheTtl": -1}})
    assert bare.tools_ttl == 0 and bare.call_timeout is None and bare.overrides == {}


def test_override_changes_what_the_agent_sees_not_what_policy_judges(ws):
    g, sent = _session(ws)
    try:
        tools = _list(g, sent)
        assert "shop__list_orders" not in tools
        assert tools["shop__orders"]["description"] == "[shop] Orders, newest first"
        assert tools["shop__orders"]["inputSchema"]["properties"] == {"limit": {"type": "integer"}}
        # Calls route to the upstream's own name.
        g._handle_tools_call_safe(9, {"name": "shop__orders", "arguments": {}})
        assert not sent[-1]["result"].get("isError")
        # A deny on the upstream name still holds after a rename: hidden, and blocked by name.
        assert "shop__remove" not in tools
        g._handle_tools_call_safe(10, {"name": "shop__remove", "arguments": {"doc": "d"}})
        assert sent[-1]["result"]["isError"] and "Blocked by Prismor" in sent[-1]["result"]["content"][0]["text"]
    finally:
        g.close()


def test_tools_list_is_cached_until_ttl_or_list_changed(ws):
    g, sent = _session(ws)
    up = g.upstreams[0]
    asked = []
    real = up.request
    up.request = lambda m, p, timeout=30.0: (asked.append(m), real(m, p, timeout=timeout))[1]
    try:
        _list(g, sent)
        _list(g, sent)
        assert asked.count("tools/list") == 1
        g._make_notification_handler("shop")("notifications/tools/list_changed", {})
        _list(g, sent)
        assert asked.count("tools/list") == 2
    finally:
        g.close()


def test_no_ttl_asks_the_upstream_every_time(ws):
    g, sent = _session(ws, {"command": sys.executable, "args": [str(SERVER)]})
    up = g.upstreams[0]
    asked = []
    real = up.request
    up.request = lambda m, p, timeout=30.0: (asked.append(m), real(m, p, timeout=timeout))[1]
    try:
        _list(g, sent)
        _list(g, sent)
        assert asked.count("tools/list") == 2
    finally:
        g.close()


@pytest.mark.parametrize("entry,expected", [(ENTRY, 7.0), ({"command": sys.executable, "args": [str(SERVER)]}, CALL_TIMEOUT)])
def test_call_uses_the_server_timeout(ws, entry, expected):
    g, sent = _session(ws, entry)
    up = g.upstreams[0]
    seen = []
    real = up.request
    up.request = lambda m, p, timeout=30.0: (seen.append((m, timeout)), real(m, p, timeout=timeout))[1]
    try:
        name = next(n for n in _list(g, sent) if n.endswith("orders"))
        g._handle_tools_call_safe(9, {"name": name, "arguments": {}})
        assert ("tools/call", expected) in seen
    finally:
        g.close()


def test_call_before_any_list_finds_the_tool(ws):
    # A hosted session (or a client that remembers tool names) may call
    # without listing first: the gateway builds its routes instead of
    # answering "unknown tool" - renamed and denied tools included.
    g, sent = _session(ws)
    try:
        g._handle_tools_call_safe(3, {"name": "shop__orders", "arguments": {}})
        assert "error" not in sent[-1] and not sent[-1]["result"].get("isError")
        g._handle_tools_call_safe(4, {"name": "shop__remove", "arguments": {"doc": "d"}})
        assert "Blocked by Prismor" in sent[-1]["result"]["content"][0]["text"]
        g._handle_tools_call_safe(5, {"name": "shop__nope", "arguments": {}})
        assert "unknown tool" in sent[-1]["error"]["message"]
        assert all(m.get("id") != 2 for m in sent)  # no stray tools/list reply
    finally:
        g.close()
