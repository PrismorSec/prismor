"""Cross-repo contract fixes found by the OSS-vs-console audit (2026-11-15)."""
import json
import time

import pytest

from prismor.runtime.enterprise import identity, remote_policy
from prismor.runtime.enterprise.workspace_scope import _normalize_remote


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / ".prismor"))
    monkeypatch.delenv("PRISMOR_AGENT_KEY", raising=False)
    (tmp_path / ".prismor").mkdir()
    monkeypatch.setattr(identity, "keyless_identity", lambda: None)
    return tmp_path / ".prismor"


def _bound(**ids):
    return {"_signed": {"issued_at": time.time(), **ids}}


def test_agent_key_identity_accepts_a_policy_the_console_bound(home, monkeypatch):
    # The console binds ids server-side from the key; the env identity has none.
    monkeypatch.setenv("PRISMOR_AGENT_KEY", "prism_agent_test")
    assert remote_policy._signed_binding_ok(_bound(device_id="d1", org_id="o1"))


def test_system_install_user_checks_the_public_identity(home, monkeypatch):
    monkeypatch.setattr(identity, "keyless_identity", lambda: {"device_id": "d1", "org_id": "o1"})
    assert remote_policy._signed_binding_ok(_bound(device_id="d1", org_id="o1"))
    assert not remote_policy._signed_binding_ok(_bound(device_id="other", org_id="o1"))


def test_enrolled_device_still_rejects_another_devices_policy(home):
    (home / "identity.json").write_text(json.dumps({"device_key": "k", "device_id": "d1", "org_id": "o1"}))
    assert remote_policy._signed_binding_ok(_bound(device_id="d1", org_id="o1"))
    assert not remote_policy._signed_binding_ok(_bound(device_id="d2", org_id="o1"))
    assert not remote_policy._signed_binding_ok(_bound(device_id="d1", org_id="o2"))


@pytest.mark.parametrize("url,want", [
    ("https://ci-bot:ghp_fake@github.com/Org/Repo.git", "github.com/org/repo"),
    ("https://x-access-token@github.com/o/r", "github.com/o/r"),
    ("git@github.com:acme/repo.git", "github.com/acme/repo"),
    ("https://github.com/acme/repo/", "github.com/acme/repo"),
    ("ssh://git@gitlab.example.com:2222/acme/repo", "gitlab.example.com/acme/repo"),
    ("/some/local/path", None),
])
def test_remote_url_never_carries_credentials(url, want):
    assert _normalize_remote(url) == want


# --- a queued (inference-hook) approval is usable on retry -----------------
from prismor.runtime.enterprise import approvals  # noqa: E402

_FINDING = {"action": "step_up", "toolName": "prompt", "title": "t", "ruleId": "r", "evidence_hash": "h"}


@pytest.fixture
def cp(monkeypatch):
    monkeypatch.delenv("PRISMOR_APPROVALS", raising=False)
    monkeypatch.setattr(approvals._identity, "load_identity", lambda: {"device_key": "k", "api_base": "https://cp.invalid"})
    monkeypatch.setattr(approvals._identity, "revoked_backoff_active", lambda: False)
    monkeypatch.setattr(approvals, "_audit_outcome", lambda *a, **k: None)
    reply = {}
    monkeypatch.setattr(approvals, "_post_request", lambda ident, body, timeout: dict(reply) or None)
    return reply


def test_first_post_is_queued_not_approved(cp):
    cp.update(id="a1", status="pending")
    out = approvals.enqueue_step_up(_FINDING, session_id="s")
    assert not out and out.approval_id == "a1" and out.status == "queued"


def test_retry_after_full_approval_lets_the_call_through(cp):
    cp.update(id="a1", status="approved", decision_mode="full")
    out = approvals.enqueue_step_up(_FINDING, session_id="s")
    assert out and out.status == "approved"


def test_redacted_or_unstated_mode_stays_denied(cp):
    # This channel cannot strip values, and a missing mode reads as redacted.
    cp.update(id="a1", status="approved", decision_mode="redacted")
    assert not approvals.enqueue_step_up(_FINDING, session_id="s")
    cp.pop("decision_mode")
    assert not approvals.enqueue_step_up(_FINDING, session_id="s")


def test_post_failure_has_no_id(cp):
    out = approvals.enqueue_step_up(_FINDING, session_id="s")
    assert not out and out.approval_id is None and out.status == "request_failed"
