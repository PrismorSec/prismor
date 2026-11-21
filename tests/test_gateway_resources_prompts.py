"""Resources and prompts through the gateway: listed, routed, judged and scanned like tools."""
import sys
from pathlib import Path

import pytest
import yaml

from prismor.runtime.mcp_gateway import Gateway, _spec_from_entry

FIXTURES = Path(__file__).parent / "fixtures"
CATALOG = {"command": sys.executable, "args": [str(FIXTURES / "catalog_mcp_server.py")]}
TOOLS_ONLY = {"command": sys.executable, "args": [str(FIXTURES / "stub_mcp_server.py")]}


@pytest.fixture
def ws(tmp_path, monkeypatch):
    for k in [k for k in __import__("os").environ if k.startswith("PRISMOR")]:
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / "home"))
    (tmp_path / ".prismor").mkdir()
    return tmp_path


def _session(ws, deny=()):
    (ws / ".prismor" / "agents.yaml").write_text(yaml.safe_dump({"global_deny_tools": list(deny)}))
    g = Gateway([_spec_from_entry("cat", CATALOG), _spec_from_entry("stub", TOOLS_ONLY)],
                workspace=ws, mode="enforce")
    sent = []
    g._send = lambda m: sent.append(m)
    g._dispatch({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                 "params": {"protocolVersion": "2025-06-18", "clientInfo": {"name": "t"}}})
    return g, sent


def _ask(g, sent, method, params=None, rid=9):
    if method in ("resources/read", "prompts/get"):
        g._handle_fetch_safe(rid, method, params or {})
    else:
        g._dispatch({"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}})
    return next(m for m in reversed(sent) if m.get("id") == rid)


def test_capabilities_and_lists(ws):
    g, sent = _session(ws)
    try:
        assert set(sent[0]["result"]["capabilities"]) == {"tools", "resources", "prompts"}
        res = _ask(g, sent, "resources/list")["result"]["resources"]
        # Both pages, URIs untouched, a server with no resources contributes nothing.
        assert [r["uri"] for r in res] == ["docs://readme", "docs://poisoned"]
        assert res[0]["description"] == "[cat] The readme"
        assert _ask(g, sent, "resources/templates/list")["result"]["resourceTemplates"][0]["uriTemplate"] == "notes://{id}"
        assert [p["name"] for p in _ask(g, sent, "prompts/list")["result"]["prompts"]] == ["cat__greet"]
    finally:
        g.close()


def test_read_and_get_route_to_the_right_server(ws):
    g, sent = _session(ws)
    try:
        # No list first: the gateway builds the routes itself.
        read = _ask(g, sent, "resources/read", {"uri": "docs://readme"})
        assert read["result"]["contents"][0]["text"] == "Hello from the readme"
        note = _ask(g, sent, "resources/read", {"uri": "notes://42"})
        assert note["result"]["contents"][0]["text"] == "note 42"
        got = _ask(g, sent, "prompts/get", {"name": "cat__greet", "arguments": {"who": "Ana"}})
        assert got["result"]["messages"][0]["content"]["text"] == "Say hi to Ana"
        assert "unknown resource" in _ask(g, sent, "resources/read", {"uri": "nope://x"})["error"]["message"]
        assert "unknown prompt" in _ask(g, sent, "prompts/get", {"name": "cat__nope"})["error"]["message"]
    finally:
        g.close()


def test_a_poisoned_resource_is_withheld(ws):
    g, sent = _session(ws)
    try:
        out = _ask(g, sent, "resources/read", {"uri": "docs://poisoned"})
        assert "withheld" in out["error"]["message"] and "system prompt" not in out["error"]["message"]
    finally:
        g.close()


def test_server_deny_covers_resources_and_prompts(ws):
    g, sent = _session(ws, deny=["mcp__cat__*"])
    try:
        assert "Blocked by Prismor" in _ask(g, sent, "resources/read", {"uri": "docs://readme"})["error"]["message"]
        assert "Blocked by Prismor" in _ask(g, sent, "prompts/get", {"name": "cat__greet"})["error"]["message"]
    finally:
        g.close()
