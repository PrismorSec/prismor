"""Policy changes are recorded in the signed audit trail (issue #826).

Before this, `prismor allow` and dashboard allow/ask/deny decisions edited
policy without leaving any record of who changed what, and when. Each edit now
appends one `record_type: "policy"` entry to the hash-chained trail.

Runs against an isolated $PRISMOR_HOME.
Run: python3 -m pytest tests/test_policy_change_audit.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO))


@pytest.fixture()
def env(tmp_path, monkeypatch):
    """(audit_trail, workspace) bound to a fresh $PRISMOR_HOME."""
    home = tmp_path / "home"
    ws = tmp_path / "ws"
    home.mkdir()
    ws.mkdir()
    monkeypatch.setenv("PRISMOR_HOME", str(home))
    monkeypatch.delenv("PRISMOR_AUDIT_TRAIL", raising=False)
    for mod in (
        "prismor.runtime.enterprise.audit_trail",
        "prismor.runtime.enterprise.receipt_signing",
        "prismor.runtime.enterprise.identity",
    ):
        sys.modules.pop(mod, None)
    from prismor.runtime.enterprise import audit_trail
    return audit_trail, ws


def _policy_records(trail):
    path = trail.trail_path()
    if not path.exists():
        return []
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    return [r for r in rows if r.get("record_type") == "policy"]


def test_policy_record_fields_and_chain(env):
    trail, ws = env
    rec = trail.append_policy_record(
        event="rule_mode_changed", rule_id="risky-write", workspace=ws,
        before="enforce", after="observe", reason="noisy in this repo",
    )
    assert rec["record_type"] == "policy"
    assert rec["event"] == "rule_mode_changed"
    assert rec["rules"] == ["risky-write"]
    assert (rec["before"], rec["after"]) == ("enforce", "observe")
    assert rec["workspace"] == str(ws)
    assert rec["source"] == "cli"
    assert rec["changed_by"]  # the OS user
    assert rec["ts"]
    assert trail.compute_hash(rec) == rec["hash"]
    assert trail.verify_trail()["status"] == "ok"


def test_allow_add_and_undo_are_recorded(env):
    trail, ws = env
    from prismor.runtime import allow

    entry = allow.add_allowlist(ws, "risky-write", "echo hi", reason="demo")
    assert allow.undo(ws, entry["id"]) is True

    added, removed = _policy_records(trail)
    assert added["event"] == "allowlist_added"
    assert added["rules"] == ["risky-write"]
    assert added["after"]["patterns"] == ["echo hi"]
    assert added["reason"] == "demo"
    assert removed["event"] == "allowlist_removed"
    assert removed["rules"] == ["risky-write"]
    assert removed["before"]["id"] == entry["id"]
    assert trail.verify_trail()["status"] == "ok"


def test_folded_allow_records_only_real_changes(env):
    trail, ws = env
    from prismor.runtime import allow

    allow.add_allowlist(ws, "risky-write", "echo one")
    allow.add_allowlist(ws, "risky-write", "echo two")   # folds into the entry
    allow.add_allowlist(ws, "risky-write", "echo two")   # already there: no change
    records = _policy_records(trail)
    assert len(records) == 2
    assert records[1]["after"]["pattern"] == "echo two"


def test_undo_one_pattern_is_recorded(env):
    trail, ws = env
    from prismor.runtime import allow

    allow.add_allowlist(ws, "risky-write", "echo one")
    allow.add_allowlist(ws, "risky-write", "echo two")
    assert allow.undo(ws, "echo one") is True
    last = _policy_records(trail)[-1]
    assert last["event"] == "allowlist_removed"
    assert last["before"]["pattern"] == "echo one"
    assert last["rules"] == ["risky-write"]


def test_undo_of_unknown_target_records_nothing(env):
    trail, ws = env
    from prismor.runtime import allow

    assert allow.undo(ws, "no-such-entry") is False
    assert _policy_records(trail) == []


def test_rule_mode_and_enabled_capture_before_and_after(env):
    trail, ws = env
    from prismor.runtime import allow

    allow.set_rule_mode(ws, "risky-write", "observe")
    allow.set_rule_mode(ws, "risky-write", "enforce")
    allow.set_rule_enabled(ws, "risky-write", False)
    mode1, mode2, enabled = _policy_records(trail)
    assert (mode1["event"], mode1["before"], mode1["after"]) == ("rule_mode_changed", None, "observe")
    assert (mode2["before"], mode2["after"]) == ("observe", "enforce")
    assert (enabled["event"], enabled["before"], enabled["after"]) == ("rule_enabled_changed", None, False)


def test_dashboard_decisions_are_recorded(env):
    trail, ws = env
    from prismor.runtime import decisions

    rec = decisions.add({
        "target": "rule", "ruleId": "risky-write", "action": "deny",
        "scope": "workspace", "workspace": str(ws), "reason": "locked down",
    })
    assert decisions.remove(rec["id"]) is True
    assert decisions.remove(rec["id"]) is False  # already gone: no second record

    added, removed = _policy_records(trail)
    assert (added["event"], added["source"]) == ("decision_added", "dashboard")
    assert added["after"]["action"] == "deny"
    assert added["reason"] == "locked down"
    assert (removed["event"], removed["source"]) == ("decision_removed", "dashboard")
    assert removed["before"]["id"] == rec["id"]


def test_replacing_a_decision_records_the_old_one(env):
    trail, ws = env
    from prismor.runtime import decisions

    base = {"target": "rule", "ruleId": "risky-write", "scope": "workspace", "workspace": str(ws)}
    decisions.add({**base, "action": "deny"})
    decisions.add({**base, "action": "ask"})
    second = _policy_records(trail)[-1]
    assert second["before"]["action"] == "deny"
    assert second["after"]["action"] == "ask"


def test_audit_failure_never_blocks_the_edit(env, monkeypatch, capsys):
    trail, ws = env
    from prismor.runtime import allow

    def boom(**_kw):
        raise OSError("disk full")

    monkeypatch.setattr(trail, "append_policy_record", boom)
    entry = allow.add_allowlist(ws, "risky-write", "echo hi")
    assert [e["id"] for e in allow.list_allows(ws)] == [entry["id"]]
    assert "policy audit error" in capsys.readouterr().err


def test_disabled_trail_writes_nothing(env, monkeypatch):
    trail, ws = env
    from prismor.runtime import allow

    monkeypatch.setenv("PRISMOR_AUDIT_TRAIL", "0")
    allow.add_allowlist(ws, "risky-write", "echo hi")
    assert not trail.trail_path().exists()


def test_registered_secret_in_pattern_is_scrubbed(env, tmp_path, monkeypatch):
    trail, ws = env
    from prismor.runtime import allow

    secrets = tmp_path / "secrets"
    secrets.mkdir()
    (secrets / "demo_key").write_text("s3cr3t-value-123", encoding="utf-8")
    monkeypatch.setenv("PRISMOR_SECRETS_DIR", str(secrets))
    allow.add_allowlist(ws, "risky-write", "curl -H s3cr3t-value-123 example.com")
    text = trail.trail_path().read_text(encoding="utf-8")
    assert "s3cr3t-value-123" not in text


def test_default_reason_names_the_rule(env):
    trail, ws = env
    from prismor.runtime import allow

    allow.set_rule_mode(ws, "risky-write", "observe")
    assert _policy_records(trail)[0]["reason"] == "rule mode changed: risky-write"


def test_trail_show_renders_policy_records(env, capsys):
    trail, ws = env
    from argparse import Namespace
    from prismor.runtime import allow, cli

    allow.set_rule_mode(ws, "risky-write", "observe")
    cli._run_trail(Namespace(trail_command="show", last=5))
    line = capsys.readouterr().out.strip()
    assert "policy" in line and "rule_mode_changed" in line and "risky-write" in line
    assert "?" not in line.split("policy", 1)[0]  # no unknown-verdict placeholder
