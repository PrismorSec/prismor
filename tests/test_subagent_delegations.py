"""Delegation records: launch caps (subagent.number), expiry (subagent.age),
and data-boundary screening of what an agent hands a subagent."""
from __future__ import annotations

import pytest
import yaml

from prismor.runtime import agents, delegations, runtime


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / ".prismor"))
    agents._CONFIG_CACHE.clear()
    yield


def _policy(tmp_path, *rules, settings=None):
    home = tmp_path / ".prismor"
    home.mkdir(exist_ok=True)
    (home / "policy.yaml").write_text(yaml.safe_dump(
        {"version": "1.0", "rules": list(rules), **({"settings": settings} if settings else {})}))


def _rule(when, rid="cap"):
    return {"id": rid, "severity": "HIGH", "category": "custom-authz", "title": rid,
            "event_types": ["shell", "subagent_spawn"], "when": when, "action": "block", "mode": "enforce"}


def _sub_call(ws, sub_id, *, sid="s1", parent="support-bot", mode="enforce", record=True):
    return runtime.evaluate_tool_call(
        event={"type": "shell", "agent_event": "PreToolUse", "command": "q",
               "metadata": {"tool_name": "lookup", "subagent_id": sub_id, "subagent_type": "researcher",
                            "parent_agent_name": parent}},
        workspace=ws, agent="openai-agents", agent_name="researcher", mode=mode,
        session_id=sid, persist=False, record=record)


def _spawn(ws, prompt="look around", *, sid="cc1", sub_type="Explore", mode="enforce"):
    return runtime.evaluate_tool_call(
        event={"type": "subagent_spawn", "agent_event": "PreToolUse", "subagent_type": sub_type,
               "description": "d", "prompt": prompt, "metadata": {"tool_name": "Agent"}},
        workspace=ws, agent="claude", mode=mode, session_id=sid, persist=False)


def test_launch_cap_blocks_later_subagents_not_earlier_ones(tmp_path):
    _policy(tmp_path, _rule("subagent.number > 2"))
    assert _sub_call(tmp_path, "a").allow and _sub_call(tmp_path, "b").allow
    assert not _sub_call(tmp_path, "c").allow           # the third subagent
    assert _sub_call(tmp_path, "a").allow                # the first keeps working
    assert not _sub_call(tmp_path, "d").allow            # a refused one used no number
    assert [r["number"] for r in delegations.records("s1")] == [1, 2]


def test_cap_counts_per_parent_and_session(tmp_path):
    _policy(tmp_path, _rule("subagent.number > 1"))
    assert _sub_call(tmp_path, "a").allow
    assert _sub_call(tmp_path, "b", parent="other-bot").allow
    assert _sub_call(tmp_path, "c", sid="s2").allow


def test_claude_code_spawn_cap(tmp_path):
    _policy(tmp_path, _rule("subagent.number > 2"))
    assert _spawn(tmp_path).allow and _spawn(tmp_path).allow
    third = _spawn(tmp_path)
    assert not third.allow and third.blocking["ruleId"] == "cap"
    assert [r["kind"] for r in delegations.records("cc1")] == ["spawn", "spawn"]


def test_dry_runs_record_nothing(tmp_path):
    _policy(tmp_path, _rule("subagent.number > 1"))
    assert _sub_call(tmp_path, "a", record=False).allow
    assert delegations.records("s1") == []


def test_expiry_by_age(tmp_path, monkeypatch):
    _policy(tmp_path, _rule("subagent.age > 60"))
    clock = [1000.0]
    monkeypatch.setattr(delegations.time, "time", lambda: clock[0])
    assert _sub_call(tmp_path, "a").allow
    clock[0] += 30
    assert _sub_call(tmp_path, "a").allow
    clock[0] += 60
    assert not _sub_call(tmp_path, "a").allow           # 90s after it started
    assert _sub_call(tmp_path, "b").allow                # a new subagent starts fresh


def test_post_tool_use_does_not_count(tmp_path):
    _policy(tmp_path, _rule("subagent.number > 1"))
    runtime.evaluate_tool_call(
        event={"type": "subagent_spawn", "agent_event": "PostToolUse", "subagent_type": "Explore",
               "prompt": "x", "metadata": {"tool_name": "Agent"}},
        workspace=tmp_path, agent="claude", mode="enforce", session_id="cc1", persist=False)
    assert _spawn(tmp_path).allow


# ── data boundary on handoffs ───────────────────────────────────────────────

_HANDOFFS = {"data_boundary": {"enabled": True, "mode": "enforce", "handoffs": {
    "secret": "block", "email": "warn", "per_subagent": {"billing": {"email": "allow", "card": "allow"}},
    "card": "block"}}}
_KEY = "sk-proj-" + "Ab3dE6gH9jK2mN5pQ8sT1vW4yZ7bC0eF3hJ6kM9nP2rS5uV8"


def test_spawn_prompt_with_a_secret_is_blocked(tmp_path):
    _policy(tmp_path, settings=_HANDOFFS)
    d = _spawn(tmp_path, f"use the key {_KEY} to call the API")
    assert not d.allow and d.blocking["ruleId"] == "secret-to-subagent"
    assert _spawn(tmp_path, "summarise the README").allow


def test_handoff_classes_follow_per_subagent_overrides(tmp_path):
    _policy(tmp_path, settings=_HANDOFFS)
    mail = "Email the receipt to dana.whitfield@northwind-trading.co"
    warn = _spawn(tmp_path, mail, sub_type="researcher")
    assert warn.allow and any(f["ruleId"] == "pii-to-subagent" for f in warn.findings)
    allowed = _spawn(tmp_path, mail, sub_type="billing")
    assert allowed.allow and not any(f["ruleId"] == "pii-to-subagent" for f in allowed.findings)
    card = "charge 4539 1488 0343 6467"
    assert not _spawn(tmp_path, card, sub_type="researcher").allow
    assert _spawn(tmp_path, card, sub_type="billing").allow


def test_adapter_marked_handoff_is_screened(tmp_path):
    _policy(tmp_path, settings=_HANDOFFS)
    d = runtime.evaluate_tool_call(
        event={"type": "shell", "agent_event": "PreToolUse", "command": f"token {_KEY}",
               "metadata": {"tool_name": "ask_researcher", "handoff_to": "researcher",
                            "kwargs": {"input": f"token {_KEY}"}}},
        workspace=tmp_path, agent="openai-agents", agent_name="support-bot", mode="enforce",
        session_id="h1", persist=False)
    assert not d.allow
    assert any(f["ruleId"] == "secret-to-subagent" for f in d.findings)


def test_handoffs_inert_unless_configured(tmp_path):
    _policy(tmp_path, settings={"data_boundary": {"enabled": True, "mode": "enforce"}})
    d = _spawn(tmp_path, "Email dana.whitfield@northwind-trading.co")
    assert not any(f["ruleId"].endswith("-to-subagent") for f in d.findings)


def test_handoff_block_explains_the_handoff_setting(tmp_path):
    from prismor.runtime.unblock import data_boundary_steps
    steps = "\n".join(data_boundary_steps({"handoffTo": "researcher", "dataClasses": ["email"]}, tmp_path))
    assert "handoffs.per_subagent" in steps and '"researcher": {email: allow}' in steps
    assert "per_domain" not in steps
