"""Agent connections: an agent may hand work only to agents a policy connects it to.

Sender side: every channel an agent hands work over (an orchestrator handoff,
LangGraph/CrewAI delegation, a headless coding-agent CLI, an agent served over
MCP, A2A) is normalized to one ``{from, to, channel}`` message and decided by
``settings.agent_connections``. Receiver side: a standard EdDSA JWT is verified
against the registered agents' keys, so an agent without Prismor cannot skip
the sender's check.
"""
from __future__ import annotations

import asyncio
import base64
import json
from pathlib import Path

import pytest
import yaml

from prismor.runtime import agent_connections as ac
from prismor.runtime.runtime import evaluate_tool_call

crypto = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ed25519")

POLICY = {
    "mode": "enforce",
    "agents": {
        "agt_deploy": {"name": "deploy-bot",
                       "aliases": ["crewai:Deploy Engineer", "mcp:deploy-server", "a2a:https://deploy.internal"]},
        "agt_planner": {"name": "planner"},
    },
    "allow": [{"from": "planner", "to": "deploy-bot"},
              {"from": "support-triage", "to": "billing-assistant", "action": "ask"},
              {"from": "codex", "to": "claude"},
              {"from": "reporter", "to": "deploy-bot", "channels": ["a2a"]}],
}


def _ws(tmp_path: Path, **over) -> Path:
    ws = tmp_path / "ws"
    (ws / ".prismor").mkdir(parents=True)
    (ws / ".prismor" / "policy.yaml").write_text(yaml.safe_dump({"settings": {"agent_connections": {**POLICY, **over}}}))
    return ws


def _eval(ws: Path, src: str, *, tool: str = "agent", meta=None, etype: str = "shell", command: str = "{}"):
    event = {"ts": "2026-11-03T00:00:00Z", "session_id": "s1", "agent": "fw",
             "agent_event": "PreToolUse", "type": etype, "command": command,
             "metadata": {"tool_name": tool, "from_agent": src, **(meta or {})}}
    return evaluate_tool_call(event=event, workspace=ws, agent="fw", agent_name="crew",
                              mode="enforce", session_id="s1", persist=False)


def _handoff(ws: Path, src: str, dst: str):
    return _eval(ws, src, tool=dst, meta={"handoff_to": dst})


def _rule(decision):
    return [f for f in decision.findings if f.get("ruleId") == ac.RULE_ID]


def test_connected_pair_is_allowed(tmp_path):
    d = _handoff(_ws(tmp_path), "planner", "deploy-bot")
    assert d.allow and not _rule(d)


def test_unconnected_pair_is_blocked(tmp_path):
    d = _handoff(_ws(tmp_path), "research-crawler", "deploy-bot")
    assert not d.allow
    assert _rule(d)[0]["toAgent"] == "deploy-bot"


def test_ask_pair_needs_approval(tmp_path):
    f = _rule(_handoff(_ws(tmp_path), "support-triage", "billing-assistant"))
    assert f and f[0]["action"] == "step_up"


def test_observe_flags_but_never_blocks(tmp_path):
    d = _handoff(_ws(tmp_path, mode="observe"), "research-crawler", "deploy-bot")
    assert d.allow and _rule(d)


def test_no_policy_means_feature_off(tmp_path):
    ws = tmp_path / "plain"
    ws.mkdir()
    assert not _rule(_handoff(ws, "anyone", "deploy-bot"))


def test_names_ids_and_aliases_meet(tmp_path):
    ws = _ws(tmp_path)
    for target in ("Deploy Bot", "deploy_bot", "agt_deploy", "Deploy Engineer"):
        assert _handoff(ws, "Planner", target).allow, target


def test_channel_limited_connection(tmp_path):
    assert not _handoff(_ws(tmp_path), "reporter", "deploy-bot").allow  # only allowed over a2a


# -- every channel, one decision ---------------------------------------------------

def test_langgraph_transfer_tool(tmp_path):
    ws = _ws(tmp_path)
    assert _eval(ws, "planner", tool="transfer_to_deploy_bot").allow
    assert not _eval(ws, "research-crawler", tool="transfer_to_deploy_bot").allow


def test_crewai_delegation(tmp_path):
    ws = _ws(tmp_path)
    meta = {"kwargs": {"task": "ship", "context": "", "coworker": "Deploy Engineer"}}
    assert _eval(ws, "planner", tool="Delegate work to coworker", meta=meta).allow
    assert not _eval(ws, "research-crawler", tool="delegate_work", meta=meta).allow


def test_headless_cli_agent(tmp_path):
    ws = _ws(tmp_path)
    assert _eval(ws, "codex", command='cd repo && claude -p "review this diff"').allow
    blocked = _eval(ws, "gemini", command='claude --model opus -p "rm the logs"')
    assert not blocked.allow and _rule(blocked)[0]["channel"] == "cli"
    assert _eval(ws, "gemini", command="echo claude -p is a flag").allow  # not a call
    assert not _eval(ws, "claude", command="codex exec 'deploy'").allow


def test_agent_served_over_mcp(tmp_path):
    ws = _ws(tmp_path)
    assert _eval(ws, "planner", tool="mcp__deploy-server__run").allow
    d = _eval(ws, "research-crawler", tool="mcp__deploy-server__run")
    assert not d.allow and _rule(d)[0]["channel"] == "tool"
    assert _eval(ws, "research-crawler", tool="mcp__github__list_prs").allow  # not an agent


def test_message_is_stamped_on_the_event(tmp_path):
    ws = _ws(tmp_path)
    event = {"type": "shell", "command": "{}", "agent": "fw", "agent_event": "PreToolUse",
             "metadata": {"tool_name": "transfer_to_deploy_bot", "from_agent": "planner"}}
    evaluate_tool_call(event=event, workspace=ws, agent="fw", mode="enforce", session_id="s2", persist=False)
    msg = event["metadata"]["agent_message"]
    assert (msg["from_id"], msg["to_id"], msg["channel"]) == ("agt_planner", "agt_deploy", "handoff")


# -- receiver side -------------------------------------------------------------

def _pair():
    from cryptography.hazmat.primitives import serialization
    key = crypto.Ed25519PrivateKey.generate()
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return key, base64.b64encode(raw).decode()


def _policy(keys):
    agents = {aid: {"name": aid.removeprefix("agt_"), "public_key": pub} for aid, pub in keys.items()}
    agents.setdefault("agt_deploy-bot", {"name": "deploy-bot", "aliases": ["a2a:https://deploy.internal"]})
    return ac.ConnectionPolicy.from_settings({"agent_connections": {
        "mode": "enforce", "agents": agents, "allow": [{"from": "planner", "to": "deploy-bot"}]}})


def test_caller_header_is_a_standard_jwt():
    jwt = pytest.importorskip("jwt")
    key, _ = _pair()
    tok = ac.sign_caller("planner", "deploy-bot", key, act="user:alice")
    claims = jwt.decode(tok, key.public_key(), algorithms=["EdDSA"], audience="deploy-bot")
    assert (claims["sub"], claims["iss"], claims["act"]) == ("planner", "prismor", {"sub": "user:alice"})


def test_receiver_accepts_signed_allowed_caller():
    key, pub = _pair()
    pol = _policy({"agt_planner": pub})
    assert ac.check_inbound(pol, ac.sign_caller("planner", "deploy-bot", key), "deploy-bot") == (True, "")
    # the caller may name the target by any of its aliases
    assert ac.check_inbound(pol, ac.sign_caller("agt_planner", "Deploy Bot", key), "agt_deploy-bot")[0]


def test_receiver_rejects_bad_callers():
    key, pub = _pair()
    other, _ = _pair()
    pol = _policy({"agt_planner": pub, "agt_research-crawler": pub})
    good = ac.sign_caller("planner", "deploy-bot", key)
    h, b, s = good.split(".")
    none_alg = base64.urlsafe_b64encode(b'{"alg":"none"}').decode().rstrip("=") + f".{b}."
    cases = {
        "missing": None,
        "forged": ac.sign_caller("planner", "deploy-bot", other),
        "alg none": none_alg,
        "other target": ac.sign_caller("planner", "billing-assistant", key),
        "expired": ac.sign_caller("planner", "deploy-bot", key, now=0),
        "not connected": ac.sign_caller("research-crawler", "deploy-bot", key),
        "unknown agent": ac.sign_caller("intruder", "deploy-bot", key),
    }
    for name, tok in cases.items():
        ok, reason = ac.check_inbound(pol, tok, "deploy-bot")
        assert not ok and reason, name


def test_receiver_rejects_replay():
    key, pub = _pair()
    pol = _policy({"agt_planner": pub})
    tok = ac.sign_caller("planner", "deploy-bot", key)
    assert ac.check_inbound(pol, tok, "deploy-bot")[0]
    assert ac.check_inbound(pol, tok, "deploy-bot") == (False, "caller header replayed")


def test_legacy_peers_still_read():
    key, pub = _pair()
    pol = ac.ConnectionPolicy.from_settings({"agent_connections": {
        "mode": "enforce", "allow": [{"from": "planner", "to": "deploy-bot"}], "peers": {"planner": pub}}})
    assert ac.check_inbound(pol, ac.sign_caller("planner", "deploy-bot", key), "deploy-bot")[0]


def test_asgi_guard_blocks_before_the_agent_runs():
    key, pub = _pair()
    reached = []

    async def app(scope, receive, send):
        reached.append(True)
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"{}"})

    guarded = ac.asgi_guard(app, agent="deploy-bot", policy=_policy({"agt_planner": pub}))

    def call(token):
        sent = []
        headers = [(ac.HEADER.encode(), token.encode())] if token else []

        async def send(msg):
            sent.append(msg)

        asyncio.run(guarded({"type": "http", "headers": headers}, None, send))
        return sent[0]["status"], sent

    assert call(None)[0] == 403 and not reached
    status, sent = call(ac.sign_caller("planner", "deploy-bot", key))
    assert status == 200 and reached
    assert json.loads(call(None)[1][1]["body"])["error"]["code"] == -32001
