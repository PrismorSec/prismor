"""A local policy file can tighten a rule the org sets, never loosen it."""
from __future__ import annotations

import pytest
import yaml

from prismor.runtime.enterprise import remote_policy, workspace_scope
from prismor.runtime.policy_engine import PolicyEngine

RULE = {"id": "org-prod-kubectl", "title": "kubectl against prod", "severity": "high",
        "category": "infra", "action": "block", "event_types": ["shell"],
        "patterns": ["kubectl\\s+--context\\s+prod"], "mode": "enforce"}
CMD = "kubectl --context prod delete ns web"


@pytest.fixture
def engine(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / "home"))
    ws = tmp_path / "ws"
    (ws / ".prismor").mkdir(parents=True)

    def make(project: str, org=None):
        (ws / ".prismor" / "policy.yaml").write_text(project, encoding="utf-8")
        monkeypatch.setattr(workspace_scope, "is_managed", lambda _w: org is not None)
        monkeypatch.setattr(remote_policy, "verify_and_load", lambda: None if org is None else dict(org))
        return PolicyEngine(workspace=ws)
    return make


def _modes(e, rid="org-prod-kubectl", cmd=CMD):
    return [f["mode"] for f in e.evaluate({"type": "shell", "command": cmd}, 0) if f["ruleId"] == rid]


LOCAL_ALLOW = """allowlists:
  - id: my-exception
    rule_ids: [org-prod-kubectl]
    patterns: ['kubectl']
"""


def test_local_allowlist_does_not_excuse_an_org_rule(engine):
    assert _modes(engine(LOCAL_ALLOW, {"rules": [RULE]})) == ["enforce"]


def test_local_allowlist_still_works_on_unmanaged_workspace(engine):
    project = "rules:\n  - " + "\n    ".join(f"{k}: {v!r}" if not isinstance(v, list) else f"{k}: {v}" for k, v in RULE.items()) + "\n" + LOCAL_ALLOW
    assert _modes(engine(project)) == []


def test_org_exemption_allowlist_still_applies(engine, monkeypatch):
    org = {"rules": [RULE], "allowlists": [{"id": "org-ok", "rule_ids": ["org-prod-kubectl"], "patterns": ["kubectl"]}]}
    assert _modes(engine("", org)) == []


# A shipped rule outside the safety floor, so only this change protects it.
SHIPPED, SHIPPED_CMD = "db-modification", "psql -c 'UPDATE users SET a=1'"


def _shipped_patterns():
    from prismor.runtime.policy_engine import _DEFAULT_POLICY_PATH
    raw = yaml.safe_load(_DEFAULT_POLICY_PATH.read_text())
    return next(r["patterns"] for r in raw["rules"] if r["id"] == SHIPPED)


@pytest.mark.parametrize("field", ["enabled", "mode", "disable_patterns", "patterns"])
def test_local_fields_cannot_weaken_a_shipped_rule_the_org_sets(engine, field):
    # The org sends a sparse entry on a shipped rule: only mode. Every field it
    # leaves out must come from the shipped rule, not the local file.
    value = {"enabled": False, "mode": "observe", "disable_patterns": _shipped_patterns(),
             "patterns": ["never-matches-xyz"]}[field]
    local = yaml.safe_dump({"rules": [{"id": SHIPPED, field: value}]})
    org = {"rules": [{"id": SHIPPED, "mode": "enforce"}]}
    assert _modes(engine("", org), SHIPPED, SHIPPED_CMD) == ["enforce"]
    assert _modes(engine(local), SHIPPED, SHIPPED_CMD) != ["enforce"]  # it did loosen without the org
    assert _modes(engine(local, org), SHIPPED, SHIPPED_CMD) == ["enforce"]


def test_local_tightening_survives_a_sparse_org_entry(engine):
    rid, cmd = SHIPPED, SHIPPED_CMD
    local = f"rules:\n  - id: {rid}\n    mode: enforce\n"
    assert set(_modes(engine(local, {"rules": [{"id": rid, "add_patterns": ["zzz-never"]}]}), rid, cmd)) == {"enforce"}
