"""Policy-merge transparency: which layer defined a rule, and why it resolves
to observe or enforce.

A rule can carry ``action: block`` and still only warn, and working out which
of five levers decided that previously meant reading policy_engine._resolve_mode,
hooks.should_block and the policy YAML together. ``explain_mode`` is the single
source of truth for both the decision and the reason, so these tests pin the
reason text as much as the verdict.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

from prismor.runtime.policy_engine import PolicyEngine  # noqa: E402

PROJECT_POLICY = """rules:
  - id: house-style-guard
    severity: HIGH
    category: prompt_injection
    title: House rule
    event_types: [shell]
    fields: [command]
    patterns:
      - 'zzmarker'
    action: block
%s
"""


def _engine(tmp_path: Path, extra: str = "") -> PolicyEngine:
    d = tmp_path / ".prismor"
    d.mkdir(parents=True, exist_ok=True)
    (d / "policy.yaml").write_text(PROJECT_POLICY % extra, encoding="utf-8")
    return PolicyEngine(workspace=tmp_path)


def _rule(engine: PolicyEngine, rule_id: str):
    rule = next((r for r in engine.rules if r.id == rule_id), None)
    assert rule is not None, f"{rule_id} not loaded"
    return rule


def test_resolve_mode_and_explain_mode_never_disagree(tmp_path):
    engine = _engine(tmp_path)
    for rule in engine.rules:
        assert engine.explain_mode(rule)[0] == engine._resolve_mode(rule)


def test_project_rule_is_attributed_to_the_project_layer(tmp_path):
    engine = _engine(tmp_path)
    assert _rule(engine, "house-style-guard").layer == "project"


def test_builtin_rule_is_attributed_to_the_default_layer(tmp_path):
    engine = _engine(tmp_path)
    assert _rule(engine, "remote-execution").layer == "default"


def test_block_action_outside_the_floor_only_warns_and_says_so(tmp_path):
    """The case that is genuinely confusing: action: block, verdict WARN."""
    engine = _engine(tmp_path)
    mode, why = engine.explain_mode(_rule(engine, "house-style-guard"))
    assert mode == "observe"
    assert "default_mode" in why


def test_per_rule_mode_is_the_lever_and_is_named(tmp_path):
    engine = _engine(tmp_path, extra="    mode: enforce")
    mode, why = engine.explain_mode(_rule(engine, "house-style-guard"))
    assert mode == "enforce"
    assert "rule sets mode" in why


def test_floor_rule_explains_which_floor_caught_it(tmp_path):
    engine = _engine(tmp_path)
    mode, why = engine.explain_mode(_rule(engine, "remote-execution"))
    assert mode == "enforce"
    assert "safety floor" in why and "remote_execution" in why


# ── allowlist attribution ────────────────────────────────────────────────────

ALLOWLISTED = """rules:
  - id: zz-guard
    severity: HIGH
    category: prompt_injection
    title: House rule
    event_types: [shell]
    fields: [command]
    patterns:
      - 'zzmarker'
    action: block
    mode: enforce
allowlists:
  - id: allow-zz-known
    rule_ids: [zz-guard]
    reason: reviewed by security, known safe
    patterns:
      - 'zzmarker'
%s
"""

VETO = """  - id: veto-zz-danger
    rule_ids: [zz-guard]
    type: veto
    reason: never allow the dangerous spelling
    patterns:
      - 'zzmarker --force'
"""


def _allow_engine(tmp_path: Path, extra: str = "") -> PolicyEngine:
    d = tmp_path / ".prismor"
    d.mkdir(parents=True, exist_ok=True)
    (d / "policy.yaml").write_text(ALLOWLISTED % extra, encoding="utf-8")
    return PolicyEngine(workspace=tmp_path)


def test_enforcement_path_is_unchanged_by_the_explain_plumbing(tmp_path):
    engine = _allow_engine(tmp_path)
    event = {"type": "shell", "command": "echo zzmarker"}
    assert engine.evaluate(event, 1) == []          # allowlist still hides it


def test_explaining_shows_the_allowlist_that_swallowed_the_finding(tmp_path):
    engine = _allow_engine(tmp_path)
    event = {"type": "shell", "command": "echo zzmarker"}
    found = engine.evaluate(event, 1, include_suppressed=True)
    assert len(found) == 1
    assert found[0]["suppressedBy"]["id"] == "allow-zz-known"
    assert "known safe" in found[0]["suppressedBy"]["reason"]


def test_allowlist_match_returns_the_entry_and_the_bool_wrapper_agrees(tmp_path):
    engine = _allow_engine(tmp_path)
    entry = engine.allowlist_match("zz-guard", "echo zzmarker")
    assert entry is not None and entry.id == "allow-zz-known"
    assert engine._is_allowlisted("zz-guard", "echo zzmarker") is True
    assert engine.allowlist_match("zz-guard", "nothing here") is None
    assert engine._is_allowlisted("zz-guard", "nothing here") is False


def test_a_veto_means_nothing_is_suppressed(tmp_path):
    engine = _allow_engine(tmp_path, extra=VETO)
    event = {"type": "shell", "command": "echo zzmarker --force"}
    found = engine.evaluate(event, 1, include_suppressed=True)
    assert len(found) == 1
    # the veto disqualified the allowlist, so this is a real finding
    assert "suppressedBy" not in found[0]
    assert engine.evaluate(event, 1) != []
