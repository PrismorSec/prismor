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
        assert r["result"]["isError"] and "Blocked by Prismor" in r["result"]["content"][0]["text"]
    finally:
        g.close()


def test_calling_a_hidden_tool_by_name_is_blocked_and_logged(ws, monkeypatch):
    """A hidden tool used to be refused before evaluation, so an agent probing
    for denied tools left no trace in the console."""
    from prismor.runtime import runtime
    recorded = []
    monkeypatch.setattr(runtime, "_dispatch_telemetry", lambda **kw: recorded.append(kw))
    monkeypatch.setenv("PRISMOR_SUBJECT", "user:bob")
    g, sent, tools = _session(ws)
    try:
        assert "shop__delete_doc" not in tools
        assert recorded == []  # the list probe is not a call
        assert _call(g, sent, "shop__delete_doc", {"doc": "d"})["result"]["isError"]
        assert len(recorded) == 1
    finally:
        g.close()


def test_a_per_person_tool_deny_hides_the_tool_from_that_person_only(ws, monkeypatch):
    (ws / ".prismor" / "iam.yaml").write_text(yaml.safe_dump(
        {"agents": {"user:dave": {"allowed_tools": ["*"], "deny_tools": ["mcp__shop__list_orders"]}}}))
    monkeypatch.setenv("PRISMOR_SUBJECT", "user:dave")
    g, sent, tools = _session(ws)
    try:
        assert "shop__list_orders" not in tools and "shop__refund_order" in tools
        assert _call(g, sent, "shop__list_orders", {})["result"]["isError"]
    finally:
        g.close()
    monkeypatch.setenv("PRISMOR_SUBJECT", "user:erin")
    g, _, tools = _session(ws)
    try:
        assert "shop__list_orders" in tools
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


def test_tools_list_probes_are_not_recorded_as_calls(ws, monkeypatch):
    """Each tool was probed with a full evaluation at tools/list, and every
    probe was reported to the console as a tool call (phantom write_file /
    edit_file calls in a read-only session)."""
    from prismor.runtime import runtime
    from prismor.runtime.enterprise import heartbeat
    recorded = []
    monkeypatch.setattr(runtime, "_dispatch_telemetry", lambda **kw: recorded.append(kw))
    monkeypatch.setattr(heartbeat, "record_call", lambda **kw: recorded.append(kw))
    monkeypatch.setenv("PRISMOR_SUBJECT", "user:bob")
    g, _, tools = _session(ws)
    try:
        assert "shop__export_all_customers" not in tools  # probing still hides
        assert recorded == []
    finally:
        g.close()


# ── a server entry's tool selection (hosted endpoints, "new tools start off") ──

def _selected_session(ws, mode="enforce", **selection):
    spec = UpstreamSpec(name="shop", command=[sys.executable, str(SERVER)], **selection)
    g = Gateway([spec], workspace=ws, mode=mode)
    sent = []
    g._send = lambda m: sent.append(m)
    g._dispatch({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                 "params": {"protocolVersion": "2025-03-26", "clientInfo": {"name": "t"}}})
    g._dispatch({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    return g, sent, {t["name"] for t in sent[-1]["result"]["tools"]}


def test_a_tool_the_selection_denies_is_hidden_blocked_and_logged(ws, monkeypatch):
    from prismor.runtime import runtime
    recorded = []
    monkeypatch.setattr(runtime, "_dispatch_telemetry", lambda **kw: recorded.append(kw))
    monkeypatch.setenv("PRISMOR_SUBJECT", "user:carol")
    g, sent, tools = _selected_session(ws, deny_tools=["refund_*"])
    try:
        assert "shop__refund_order" not in tools and "shop__list_orders" in tools
        r = _call(g, sent, "shop__refund_order", {"amount": 1})
        assert r["result"]["isError"] and "Blocked by Prismor" in r["result"]["content"][0]["text"]
        assert any(f.get("category") == "agent-control" for kw in recorded for f in kw["findings"])
    finally:
        g.close()


def test_an_allow_list_keeps_only_the_known_tools(ws, monkeypatch):
    """"New tools start off": the console sends the reviewed tools as allow."""
    monkeypatch.setenv("PRISMOR_SUBJECT", "user:carol")
    g, sent, tools = _selected_session(ws, allow_tools=["list_orders"])
    try:
        assert tools == {"shop__list_orders"}
        assert not _call(g, sent, "shop__list_orders", {})["result"].get("isError")
        assert _call(g, sent, "shop__export_all_customers", {})["result"]["isError"]
    finally:
        g.close()


def test_the_selection_hides_even_in_observe_mode(ws, monkeypatch):
    monkeypatch.setenv("PRISMOR_SUBJECT", "user:carol")
    g, _, tools = _selected_session(ws, mode="observe", deny_tools=["list_orders"])
    try:
        assert "shop__list_orders" not in tools
    finally:
        g.close()


def test_the_selection_is_read_from_the_server_entry():
    from prismor.runtime.mcp_gateway import _spec_from_entry
    s = _spec_from_entry("gh", {"url": "https://x.example/mcp", "tools": {"allow": ["get_*"], "deny": ["get_secret"]}})
    assert s.allow_tools == ["get_*"] and s.deny_tools == ["get_secret"]
    assert s.excludes("get_secret") and s.excludes("push_files") and not s.excludes("get_file")
    assert _spec_from_entry("t", {"command": "x"}).allow_tools is None
