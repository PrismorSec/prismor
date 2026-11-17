"""Allowed models and spend budgets: validation, accounting, and the live gate."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

from prismor.runtime import budgets, store
from prismor.runtime.policy_engine import PolicyEngine, validate_policy
from prismor.runtime.runtime import evaluate_tool_call

NOW = datetime.now(timezone.utc)


def usage(workspace, session, *, model="claude-sonnet-4-5", usd=1.0, agent="claude-code",
          subject=None, ts=None, mid=None, latency_ms=None):
    """One turn whose cost is exactly ``usd`` (provider-reported)."""
    store.record_token_usage(
        workspace=workspace, session_id=session, message_id=mid or f"{session}-{usd}-{ts}-{agent}-{subject}",
        ts=(ts or NOW).isoformat(), model=model, input_tokens=10, output_tokens=10,
        reported_cost_usd=usd, agent=agent, subject=subject, latency_ms=latency_ms)


def policy(workspace, settings, mode="enforce"):
    path = workspace / ".prismor" / "policy.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump({
        "version": "1.0", "settings": settings,
        "rules": [{"id": r, "mode": mode} for r in
                  ("model-not-allowed", "spend-budget-exceeded", "spend-budget-unavailable")]}))


def decide(workspace, event=None, **kw):
    event = event or {"type": "shell", "command": "echo hi", "agent_event": "PreToolUse"}
    return evaluate_tool_call(event=event, workspace=workspace, agent="claude", persist=False,
                              record=False, register_agent=False, flush_at_exit=False, **kw)


def ids(decision):
    return {f.get("ruleId") for f in decision.findings}


@pytest.mark.parametrize("raw, bad", [
    ({"allow": "claude-*"}, "list"),
    ({"only": ["x"]}, "unknown"),
])
def test_validate_models(raw, bad):
    assert any(bad in e for e in budgets.validate_models(raw))
    assert budgets.validate_models({"allow": ["claude-*"], "deny": ["*opus*"]}) == []


@pytest.mark.parametrize("raw, bad", [
    ({"scope": "team", "usd": 5}, "scope"),
    ({"scope": "user", "usd": -1}, "usd"),
    ({"scope": "user", "usd": True}, "usd"),
    ({"scope": "session", "usd": 5, "period": "daily"}, "period"),
    ({"scope": "user", "usd": 5, "period": "yearly"}, "period"),
    ({"scope": "device", "usd": 5, "match": "x"}, "match"),
    ({"scope": "user", "usd": 5, "cap": 1}, "unknown"),
])
def test_validate_budgets(raw, bad, tmp_path):
    assert any(bad in e for e in budgets.validate_budgets([raw]))
    assert budgets.validate_budgets("nope")
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump({"version": "1.0", "rules": [], "settings": {"spend_budgets": [raw]}}))
    assert any("spend_budgets" in e and bad in e for e in validate_policy(path))
    path.write_text(yaml.safe_dump({"version": "1.0", "rules": [], "settings": {
        "spend_budgets": [{"scope": "user", "usd": 5}], "models": {"deny": ["*opus*"]}}}))
    assert validate_policy(path) == []


def test_model_report_deny_wins_and_normalizes():
    m = {"allow": ["claude-sonnet-*", "gpt-5*"], "deny": ["*opus*"]}
    assert budgets.model_report(m, "claude-sonnet-4-5")["allowed"]
    assert budgets.model_report(m, "anthropic/claude-sonnet-4-5")["allowed"]  # normalized name
    assert not budgets.model_report(m, "claude-opus-4-1")["allowed"]
    assert budgets.model_report(m, "gemini-2.5-pro")["reason"] == "not on the allow list"
    assert budgets.model_report({"deny": ["*opus*"]}, "gemini-2.5-pro")["allowed"]  # no allow = any
    assert budgets.model_report(m, "") is None and budgets.model_report(None, "x") is None


def test_period_starts_are_utc_calendar_boundaries():
    t = datetime(2026, 11, 18, 15, 30, tzinfo=timezone.utc)  # a Wednesday
    assert budgets.period_start("daily", t) == datetime(2026, 11, 18, tzinfo=timezone.utc)
    assert budgets.period_start("weekly", t) == datetime(2026, 11, 16, tzinfo=timezone.utc)
    assert budgets.period_start("monthly", t) == datetime(2026, 11, 1, tzinfo=timezone.utc)


def test_each_scope_counts_its_own_seat_and_tightest_wins(tmp_path):
    usage(tmp_path, "s1", usd=3, agent="claude-code", subject="alice")
    usage(tmp_path, "s2", usd=4, agent="codex", subject="bob")
    usage(tmp_path, "s1", usd=2, agent="claude-code", subject="alice",
          ts=NOW - timedelta(days=40))  # outside this month, inside the session
    b = [{"scope": "session", "usd": 10}]
    assert budgets.budget_report(b, session_id="s1", agent="claude-code", user="")["used"] == 5
    b = [{"scope": "agent", "usd": 10, "period": "monthly"}]
    assert budgets.budget_report(b, session_id="x", agent="codex", user="")["used"] == 4
    b = [{"scope": "user", "usd": 10}]
    assert budgets.budget_report(b, session_id="x", agent="", user="alice")["used"] == 3
    # no verified user: the device is the user
    assert budgets.budget_report(b, session_id="x", agent="", user="")["used"] == 7
    b = [{"scope": "device", "usd": 100}, {"scope": "agent", "usd": 4, "match": "codex"},
         {"scope": "agent", "usd": 1, "match": "other"}]
    worst = budgets.budget_report(b, session_id="x", agent="codex", user="")
    assert (worst["scope"], worst["used"], worst["limit"]) == ("agent", 4, 4)  # 100% beats 7%
    assert budgets.budget_report(b[2:], session_id="x", agent="codex", user="") is None


def test_unknown_model_is_never_free(tmp_path):
    store.record_token_usage(workspace=tmp_path, session_id="s", message_id="m1", ts=NOW.isoformat(),
                             model="made-up-model-9", input_tokens=1_000_000, output_tokens=0)
    used = budgets.budget_report([{"scope": "session", "usd": 100}], session_id="s", agent="", user="")["used"]
    assert used == pytest.approx(5.0)


def test_gate_blocks_next_hook_call_once_over_budget(tmp_path):
    policy(tmp_path, {"spend_budgets": [{"scope": "session", "usd": 5}]})
    usage(tmp_path, "sess", usd=4.99)
    assert "spend-budget-exceeded" not in ids(decide(tmp_path, session_id="sess"))
    usage(tmp_path, "sess", usd=0.02, mid="m2")
    d = decide(tmp_path, session_id="sess")
    assert "spend-budget-exceeded" in ids(d) and d.blocking is not None
    f = next(f for f in d.findings if f["ruleId"] == "spend-budget-exceeded")
    assert "$5.01 of $5.00" in f["evidence"] and f["spend"]["scope"] == "session"
    assert "spend-budget-exceeded" not in ids(decide(tmp_path, session_id="other"))


def test_gate_checks_prompts_and_observe_never_blocks(tmp_path):
    policy(tmp_path, {"spend_budgets": [{"scope": "session", "usd": 0}]}, mode="observe")
    d = decide(tmp_path, event={"type": "prompt", "prompt": "hi", "agent_event": "UserPromptSubmit"},
               session_id="s")
    assert "spend-budget-exceeded" in ids(d) and d.blocking is None


def test_hook_model_check_uses_the_sessions_last_model(tmp_path):
    policy(tmp_path, {"models": {"deny": ["*opus*"]}})
    usage(tmp_path, "s", model="claude-opus-4-1", usd=0.1)
    d = decide(tmp_path, session_id="s")
    assert "model-not-allowed" in ids(d) and d.blocking is not None
    assert "model-not-allowed" not in ids(decide(tmp_path, session_id="fresh"))


def test_proxy_llm_request_is_checked_before_upstream(tmp_path):
    from prismor.runtime import proxy
    policy(tmp_path, {"models": {"allow": ["gpt-5*"]}})
    screen = proxy.Screen(tmp_path, "enforce", "proxy-s")
    ok = screen.evaluate(screen.prompt_event("openai", "gpt-5-mini", "hi", None))
    assert screen.blocking(ok) is None
    bad = screen.evaluate(screen.prompt_event("openai", "claude-opus-4-1", "hi", None))
    assert screen.blocking(bad)["ruleId"] == "model-not-allowed"
    observe = proxy.Screen(tmp_path, "observe", "proxy-o")
    assert observe.blocking(observe.evaluate(observe.prompt_event("openai", "claude-opus-4-1", "hi", None))) is None


def test_invalid_settings_report_unavailable_instead_of_silently_passing(tmp_path):
    policy(tmp_path, {"spend_budgets": [{"scope": "team", "usd": 1}]})
    engine = PolicyEngine(workspace=tmp_path)
    assert engine.spend_budgets is None and "scope" in engine.spend_error
    assert "spend-budget-unavailable" in ids(decide(tmp_path, session_id="s"))


def test_no_settings_no_accounting(tmp_path, monkeypatch):
    called = []
    monkeypatch.setattr(budgets, "budget_report", lambda *a, **k: called.append(1))
    decide(tmp_path, session_id="s")
    assert not called


def test_summary_and_cli_status(tmp_path, capsys):
    from prismor.runtime import cli
    policy(tmp_path, {"spend_budgets": [{"scope": "device", "usd": 50, "period": "daily"},
                                        {"scope": "session", "usd": 5}]})
    usage(tmp_path, "s1", usd=2, latency_ms=900)
    usage(tmp_path, "s1", usd=1, latency_ms=300, mid="m2")
    usage(tmp_path, "s2", usd=4, model="gpt-5-mini", latency_ms=100)
    d = budgets.summary(PolicyEngine(workspace=tmp_path).spend_budgets, days=7)
    assert d["today"] == 7 and d["month"] == 7
    claude = next(m for m in d["models"] if m["model"] == "claude-sonnet-4-5")
    assert claude["requests"] == 2 and claude["usd"] == 3 and claude["latency_ms"] == 900
    assert d["budgets"][0]["used"] == 7 and d["budgets"][1]["top"][0]["used"] in (3, 4)
    cli.main(["spend", "status", "--workspace", str(tmp_path), "--json"])
    out = json.loads(capsys.readouterr().out)
    assert out["configured"] and out["modes"]["spend-budget-exceeded"] == "enforce"


def test_default_rules_conform_to_published_schema():
    jsonschema = pytest.importorskip("jsonschema")
    from prismor.runtime import policy_engine
    here = Path(policy_engine.__file__)
    schema = json.loads(here.with_name("policy_schema.json").read_text())
    raw = yaml.safe_load(here.with_name("default_policy.yaml").read_text())
    rules = [r for r in raw["rules"] if r["category"] == "spend_limit"]
    assert {r["id"] for r in rules} == {"model-not-allowed", "spend-budget-exceeded", "spend-budget-unavailable"}
    jsonschema.validate({"version": "1.0", "rules": rules, "settings": {
        "models": {"allow": ["claude-*"]},
        "spend_budgets": [{"scope": "user", "usd": 200, "period": "monthly"}]}}, schema)
