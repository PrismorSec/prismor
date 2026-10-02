"""Tests for the per-rule `when:` attribute expression.

`when:` narrows a rule by who is asking (principal), what for (resource) and
with which arguments (args) — Cerbos-style conditions on an agent tool call.

Pinned hardest:
  1. Fail toward detection: a path the event lacks, or a type mismatch, makes
     the expression hold, so the rule still fires.
  2. Core rules refuse `when` (narrowing is disabling).
  3. The grammar is a whitelist — no Python evaluation.
  4. Python and the console's TS port agree (shared golden vectors).
"""

import json
import pathlib

import pytest

from prismor.runtime.policy_engine import (
    _CORE_BLOCK_CATEGORIES,
    AttrCondition,
    CompiledRule,
    ConditionError,
    PolicyEngine,
    validate_policy,
)
from prismor.runtime.policy_test import run_cases

GOLDEN = json.loads(
    (pathlib.Path(__file__).parent / "fixtures" / "when_expr_golden.json").read_text())

_REFUND = {
    "id": "refund-cap", "severity": "HIGH", "category": "custom-authz",
    "title": "Large refunds need finance", "event_types": ["shell"],
    "fields": ["tool_name"], "patterns": ["^refund_order$"], "action": "block",
    "mode": "enforce",
    "when": "args.amount >= 500 and 'finance' not in principal.roles",
}


@pytest.mark.parametrize("case", GOLDEN["valid"], ids=lambda c: c["expr"])
def test_golden_valid(case):
    assert AttrCondition(case["expr"]).evaluate(GOLDEN["context"]) is case["result"]


@pytest.mark.parametrize("expr", GOLDEN["invalid"])
def test_golden_invalid(expr):
    with pytest.raises(ConditionError):
        AttrCondition(expr)


def test_attribute_lookup_is_dict_only():
    # A dunder name is just a dict key: never getattr on a Python object.
    assert AttrCondition("args.__class__ == 'x'").evaluate({"args": {"__class__": "x"}})
    assert AttrCondition("args.__class__ == 'x'").evaluate({"args": {}})  # missing -> holds


def _engine(tmp_path, *rules):
    pol = tmp_path / "policy.yaml"
    import yaml
    pol.write_text(yaml.safe_dump({"version": "1.0", "rules": list(rules)}))
    return PolicyEngine(workspace=tmp_path, policy_path=pol)


def _event(tool, args, resource=None):
    return {"type": "shell", "command": " ".join(map(str, args.values())),
            "metadata": {"tool_name": tool, "kwargs": args, "resource": resource or {}}}


def _hit(engine, event, subject=None):
    return [f["ruleId"] for f in engine.evaluate(event, 0, subject=subject)
            if f["ruleId"] == "refund-cap"]


def test_rule_fires_only_when_attributes_hold(tmp_path):
    from prismor.runtime.principal import Subject
    eng = _engine(tmp_path, _REFUND)
    big = _event("refund_order", {"amount": 900})
    small = _event("refund_order", {"amount": 50})
    finance = Subject(user_id="carol", source="jwt", roles=("finance",), verified=True)
    assert _hit(eng, big)
    assert not _hit(eng, small)
    assert not _hit(eng, big, finance)
    assert not _hit(eng, _event("list_orders", {"amount": 900}))


def test_asserted_subject_carries_no_roles(tmp_path):
    from prismor.runtime.principal import resolve_subject
    eng = _engine(tmp_path, _REFUND)
    # A caller can claim a user id, never a role: still blocked.
    assert _hit(eng, _event("refund_order", {"amount": 900}), resolve_subject("user:carol"))


def test_missing_args_fail_toward_detection(tmp_path):
    eng = _engine(tmp_path, _REFUND)
    ev = {"type": "shell", "command": "", "metadata": {"tool_name": "refund_order"}}
    assert _hit(eng, ev)


def test_hook_events_expose_tool_input_as_args(tmp_path):
    eng = _engine(tmp_path, _REFUND)
    ev = {"type": "shell", "command": "x",
          "metadata": {"tool_name": "refund_order", "raw": {"tool_input": {"amount": 10}}}}
    assert not _hit(eng, ev)


def test_when_only_rule_matches_on_attributes(tmp_path):
    rule = {k: v for k, v in _REFUND.items() if k not in ("patterns", "fields")}
    rule["when"] = "tool.name == 'refund_order' and args.amount >= 500"
    eng = _engine(tmp_path, rule)
    assert _hit(eng, _event("refund_order", {"amount": 900}))
    assert not _hit(eng, _event("refund_order", {"amount": 9}))
    assert not _hit(eng, _event("other", {"amount": 900}))


def test_when_only_rule_with_broken_expression_matches_nothing(tmp_path):
    rule = {k: v for k, v in _REFUND.items() if k not in ("patterns", "fields")}
    rule["when"] = "args.amount >="
    eng = _engine(tmp_path, rule)
    assert "refund-cap" not in {r.id for r in eng.rules}


def test_broken_when_on_patterned_rule_keeps_detection(tmp_path):
    eng = _engine(tmp_path, {**_REFUND, "when": "args.amount >="})
    assert _hit(eng, _event("refund_order", {"amount": 1}))


def test_core_rules_refuse_when():
    cat = sorted(_CORE_BLOCK_CATEGORIES)[0]
    rule = CompiledRule({**_REFUND, "category": cat, "when": "args.x == 1"})
    assert rule.when is None


def test_validate_policy_lints_when_and_condition(tmp_path):
    import yaml
    pol = tmp_path / "p.yaml"
    pol.write_text(yaml.safe_dump({"version": "1.0", "rules": [
        {**_REFUND, "when": "nope.x == 1"},
        {**_REFUND, "id": "b", "when": None, "condition": "patterns and ghost"},
        {k: v for k, v in _REFUND.items() if k != "patterns"} | {"id": "c"},
    ]}))
    errs = validate_policy(pol)
    assert any("rules[0].when" in e for e in errs)
    assert any("rules[1].condition" in e for e in errs)
    assert not any(e.startswith("rules[2]") for e in errs)  # when-only needs no patterns


def test_policy_test_tool_cases(tmp_path):
    import yaml
    (tmp_path / ".prismor").mkdir()
    (tmp_path / ".prismor" / "policy.yaml").write_text(
        yaml.safe_dump({"version": "1.0", "rules": [_REFUND]}))
    out = run_cases([
        {"name": "big", "type": "tool", "tool": "refund_order", "args": {"amount": 900},
         "principal": {"id": "bob", "roles": ["support"], "verified": True},
         "expect": "block", "expect_rule": "refund-cap"},
        {"name": "finance", "type": "tool", "tool": "refund_order", "args": {"amount": 900},
         "principal": {"id": "carol", "roles": ["finance"], "verified": True},
         "expect": "pass"},
    ], workspace=tmp_path)
    assert out["failed"] == 0, out
