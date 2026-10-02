"""MCP gateway hides tools a caller can never use, and passes structured
arguments to `when:` rules. Real stdio upstream (tests/fixtures/shop_mcp_server.py)
and the real policy engine."""

import sys
from pathlib import Path

import pytest
import yaml

from prismor.runtime.mcp_gateway import Gateway, UpstreamSpec

SERVER = Path(__file__).parent / "fixtures" / "shop_mcp_server.py"
POLICY = {
    "version": "1.0",
    "settings": {"conditions": {"is_carol": "principal.id == 'carol'"}},
    "rules": [
        {"id": "export-carol-only", "severity": "HIGH", "category": "custom-authz", "title": "export",
         "event_types": ["tool_result", "network", "mcp"], "fields": ["tool_name"],
         "patterns": ["__export_all_customers$"], "when": "not is_carol", "action": "block", "mode": "enforce"},
        {"id": "refund-cap", "severity": "HIGH", "category": "custom-authz", "title": "refund",
         "event_types": ["tool_result", "network", "mcp"], "fields": ["tool_name"],
         "patterns": ["__refund_order$"], "when": "args.amount >= 500", "action": "block", "mode": "enforce"},
    ],
}


@pytest.fixture
def ws(tmp_path, monkeypatch):
    for k in [k for k in __import__("os").environ if k.startswith("PRISMOR")]:
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / "home"))
    (tmp_path / ".prismor").mkdir()
    (tmp_path / ".prismor" / "policy.yaml").write_text(yaml.safe_dump(POLICY))
    (tmp_path / ".prismor" / "agents.yaml").write_text(yaml.safe_dump({"global_deny_tools": ["mcp__shop__delete_doc"]}))
    return tmp_path


def _session(ws, mode="enforce"):
    g = Gateway([UpstreamSpec(name="shop", command=[sys.executable, str(SERVER)])], workspace=ws, mode=mode)
    sent = []
    g._send = lambda m: sent.append(m)
    g._dispatch({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                 "params": {"protocolVersion": "2025-03-26", "clientInfo": {"name": "t"}}})
    g._dispatch({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    return g, sent, {t["name"] for t in sent[-1]["result"]["tools"]}


def _call(g, sent, name, args):
    g._handle_tools_call_safe(9, {"name": name, "arguments": args})
    return sent[-1]


@pytest.mark.parametrize("who,visible", [
    ("user:bob", {"shop__list_orders", "shop__refund_order"}),
    ("user:carol", {"shop__list_orders", "shop__refund_order", "shop__export_all_customers"}),
])
def test_tool_list_is_per_caller(ws, monkeypatch, who, visible):
    monkeypatch.setenv("PRISMOR_SUBJECT", who)
    g, sent, tools = _session(ws)
    try:
        assert tools == visible
        r = _call(g, sent, "shop__delete_doc", {"doc": "d"})
        assert "denied by policy" in r["error"]["message"]
    finally:
        g.close()


def test_argument_dependent_tools_stay_listed_and_are_judged_per_call(ws, monkeypatch):
    monkeypatch.setenv("PRISMOR_SUBJECT", "user:bob")
    g, sent, _ = _session(ws)
    try:
        assert not _call(g, sent, "shop__refund_order", {"amount": 50})["result"].get("isError")
        assert _call(g, sent, "shop__refund_order", {"amount": 900})["result"].get("isError")
    finally:
        g.close()


def test_observe_mode_hides_nothing(ws, monkeypatch):
    monkeypatch.setenv("PRISMOR_SUBJECT", "user:bob")
    g, _, tools = _session(ws, mode="observe")
    try:
        assert len(tools) == 4
    finally:
        g.close()


def test_call_event_carries_structured_arguments(ws):
    g, _, _ = _session(ws)
    try:
        ev = g._build_call_event(g._routes["shop__refund_order"], {"amount": 7})
        assert ev["metadata"]["kwargs"] == {"amount": 7}
    finally:
        g.close()
