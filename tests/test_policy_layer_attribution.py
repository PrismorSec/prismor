"""Telemetry names the policy layer that decided a finding's mode, not just
"org" for everything (prismor-web#333 follow-up)."""
from __future__ import annotations

import pytest

from prismor.runtime.enterprise import remote_policy, workspace_scope
from prismor.runtime.enterprise.telemetry import build_record
from prismor.runtime.policy_engine import PolicyEngine

RULE = """
  - id: guides-prod-kubectl
    title: kubectl against prod
    severity: high
    category: infra
    action: block
    event_types: [shell]
    patterns: ['kubectl\\s+--context\\s+prod']
"""


@pytest.fixture
def ws(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / "home"))
    w = tmp_path / "ws"
    (w / ".prismor").mkdir(parents=True)
    return w


def _engine(ws, monkeypatch, project: str, org=None):
    (ws / ".prismor" / "policy.yaml").write_text(project, encoding="utf-8")
    monkeypatch.setattr(workspace_scope, "is_managed", lambda _w: org is not None)
    monkeypatch.setattr(remote_policy, "verify_and_load", lambda: org)
    return PolicyEngine(workspace=ws)


def _finding(engine, cmd="kubectl --context prod delete ns web"):
    fs = [f for f in engine.evaluate({"type": "shell", "command": cmd}, 0) if f["ruleId"] == "guides-prod-kubectl"]
    assert fs, "rule did not fire"
    return fs[0]


def test_project_mode_wins_attribution_even_after_org_merges_the_rule(ws, monkeypatch):
    # The guide's case: the project sets mode: enforce; the org layer carries
    # the same rule without a mode. The org merged last, but the project decided.
    org = {"rules": [{"id": "guides-prod-kubectl", "add_patterns": ["kubectl\\s+-n\\s+prod"]}],
           "settings": {"default_mode": "observe"}}
    e = _engine(ws, monkeypatch, "rules:" + RULE + "    mode: enforce\n", org)
    f = _finding(e)
    assert f["mode"] == "enforce"
    assert f["policyLayer"] == "project"


def test_inherited_mode_is_attributed_to_the_layer_that_set_default_mode(ws, monkeypatch):
    e = _engine(ws, monkeypatch, "rules:" + RULE, {"settings": {"default_mode": "enforce"}})
    assert _finding(e)["policyLayer"] == "org"


def test_floor_is_builtin_and_record_carries_layer_when_redacted(ws, monkeypatch):
    e = _engine(ws, monkeypatch, "settings:\n  default_mode: observe\n")
    fs = [f for f in e.evaluate({"type": "shell", "command": "rm -rf /"}, 0) if f["mode"] == "enforce"]
    assert fs and all(f["policyLayer"] == "builtin" for f in fs)
    rec = build_record(fs[0], {"type": "shell"}, {}, full_capture=False)
    assert rec["policy_layer"] == "builtin"
