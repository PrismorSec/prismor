"""Evidence fields on the signed trail + re-check of an approval before it runs.

- action records carry ``resource`` and the org ``policy_version``
- approval records carry the approver and the requesting agent's name
- an approved step-up is refused if policy/state changed while it waited
Run: python3 -m pytest tests/test_evidence_and_recheck.py
"""
from __future__ import annotations

import sys
import types
from pathlib import Path
from unittest import mock

import pytest

_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO))


@pytest.fixture()
def trail(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path))
    for mod in (
        "prismor.runtime.enterprise.audit_trail",
        "prismor.runtime.enterprise.receipt_signing",
        "prismor.runtime.enterprise.identity",
    ):
        sys.modules.pop(mod, None)
    from prismor.runtime.enterprise import audit_trail
    return audit_trail


RESOURCE = {"kind": "account", "id": "ACC-1042", "attr": {"status": "active"}}


def test_action_record_has_resource_and_policy_version(trail):
    from prismor.runtime.enterprise import remote_policy
    event = {"type": "shell", "command": "get_account account=ACC-1042",
             "metadata": {"tool_name": "get_account", "resource": RESOURCE}}
    with mock.patch.object(remote_policy, "current_version", lambda: 5), \
         mock.patch.object(remote_policy, "current_profile_id", lambda: "prof_1"):
        rec = trail.append_action_record(event=event, findings=[], blocking=None,
                                         workspace=Path("."), agent="python-sdk")
    assert rec["resource"] == RESOURCE
    assert rec["policy_version"] == 5 and rec["policy_profile_id"] == "prof_1"


def test_approval_record_names_approver_and_agent(trail):
    rec = trail.append_approval_record(
        status="approved", approval_id="a1", tool="freeze_account", agent="python-sdk",
        agent_name="account-freezer", approver={"id": "u1", "email": "a@bank.test", "via": "console"},
    )
    assert rec["approver"]["email"] == "a@bank.test"
    assert rec["agent_name"] == "account-freezer"


# ── re-check after approval ──────────────────────────────────────────────────

def _step_up(recheck=None):
    return types.SimpleNamespace(
        blocking={"action": "step_up", "ruleId": "freeze-needs-human", "title": "needs a human",
                  "evidence_hash": "h"},
        recheck=recheck,
    )


def _now(allow, action=None, rule=None):
    return types.SimpleNamespace(allow=allow, reason=f"{rule} fired" if rule else None, rule_id=rule,
                                 blocking={"action": action, "ruleId": rule} if action else None)


@pytest.fixture()
def approvals(monkeypatch):
    from prismor.runtime.enterprise import approvals, remote_policy
    monkeypatch.setenv("PRISMOR_APPROVAL_POLL", "0.01")
    monkeypatch.setenv("PRISMOR_APPROVAL_TIMEOUT", "2")
    monkeypatch.delenv("PRISMOR_APPROVALS", raising=False)
    monkeypatch.setattr(approvals._identity, "load_identity", lambda: {"device_key": "k", "api_base": "https://cp.test"})
    monkeypatch.setattr(approvals._identity, "revoked_backoff_active", lambda: False)
    monkeypatch.setattr(approvals, "_post_request", lambda ident, body, timeout: {"id": "a1", "status": "pending"})
    monkeypatch.setattr(approvals, "_get_status_ex",
                        lambda ident, aid, timeout: ("approved", "full", {"id": "u2", "email": "b@bank.test"}))
    monkeypatch.setattr(remote_policy, "check_and_refresh", lambda interval=None: False)
    recorded = []
    monkeypatch.setattr(approvals, "_audit_outcome", lambda body, **kw: recorded.append({**kw, "reason": body.get("reason")}))
    approvals._recorded = recorded
    return approvals


def test_approved_and_unchanged_runs(approvals):
    out = approvals.await_step_up(_step_up(lambda r: _now(False, "step_up", "freeze-needs-human")))
    assert out and out.status == "approved"
    assert approvals._recorded[-1]["approver"]["email"] == "b@bank.test"


def test_restricted_while_waiting_is_refused(approvals):
    out = approvals.await_step_up(_step_up(lambda r: _now(False, "block", "nw-restricted-account")))
    assert not out and out.status == "revoked_after_approval"
    last = approvals._recorded[-1]
    assert last["status"] == "revoked_after_approval" and "nw-restricted-account" in last["reason"]


def test_fresh_resource_reaches_the_recheck(approvals):
    seen = []
    approvals.await_step_up(_step_up(lambda r: seen.append(r) or _now(True)),
                            resource={"kind": "account", "id": "X", "attr": {"status": "restricted"}})
    assert seen[0]["attr"]["status"] == "restricted"


def test_recheck_error_fails_closed(approvals):
    def boom(r):
        raise RuntimeError("engine down")
    assert not approvals.await_step_up(_step_up(boom))


def test_no_recheck_keeps_old_behavior(approvals):
    assert approvals.await_step_up(_step_up(None))


def test_step_up_decision_carries_a_working_recheck(tmp_path, monkeypatch):
    """End to end through evaluate_tool_call: the restriction arriving after
    the step-up turns the re-check into a block."""
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / "home"))
    ws = tmp_path / "ws"
    (ws / ".prismor").mkdir(parents=True)
    (ws / ".prismor" / "policy.yaml").write_text(
        'version: "1.0"\nrules:\n'
        "  - id: t-restricted\n    title: restricted account\n    severity: CRITICAL\n"
        "    category: custom-authz\n    event_types: [shell]\n"
        "    when: \"resource.attr.status == 'restricted'\"\n    action: block\n    mode: enforce\n"
        "  - id: t-freeze-human\n    title: freeze needs a human\n    severity: HIGH\n"
        "    category: custom-authz\n    event_types: [shell]\n"
        "    when: \"tool.name == 'freeze_account'\"\n    action: step_up\n    mode: enforce\n"
    )
    from prismor.runtime.runtime import evaluate_tool_call
    event = {"type": "shell", "command": "freeze_account account=ACC-1",
             "agent": "python-sdk", "agent_event": "PreToolUse",
             "metadata": {"tool_name": "freeze_account", "framework": "python-sdk"}}
    d = evaluate_tool_call(event=event, workspace=ws, agent="python-sdk", agent_name="account-freezer",
                           session_id="s1", resource={"kind": "account", "id": "ACC-1", "attr": {"status": "active"}},
                           register_agent=False, flush_at_exit=False)
    assert d.verdict == "step_up" and d.recheck is not None
    assert d.recheck(None).verdict == "step_up"
    after = d.recheck({"kind": "account", "id": "ACC-1", "attr": {"status": "restricted"}})
    assert after.verdict == "block" and after.rule_id == "t-restricted"
