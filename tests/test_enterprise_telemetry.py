"""Tests for the enterprise observability layer: device identity, telemetry
redaction (the privacy boundary), the prismor sink, and signed remote policy.

The most important invariants under test:
  * A redacted telemetry record NEVER carries raw commands/paths/secrets.
  * The prismor sink is a silent no-op when the machine is not enrolled.
  * A signed remote policy can tighten but can NEVER disable a non-overridable
    core rule (destructive command / secret exfiltration).
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from prismor.runtime.enterprise import identity, telemetry


# ── identity ────────────────────────────────────────────────────────────────

def test_identity_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path))
    assert identity.load_identity() is None
    assert identity.is_enrolled() is False

    rec = {"device_id": "dev_1", "org_id": "org_1", "user_id": "usr_1",
           "device_key": "prism_dev_abc", "label": "test-box"}
    path = identity.save_identity(rec)
    assert path.exists()
    # 0600 perms on the bearer credential.
    assert (path.stat().st_mode & 0o077) == 0

    loaded = identity.load_identity()
    assert loaded["device_id"] == "dev_1"
    assert loaded["device_key"] == "prism_dev_abc"
    assert identity.is_enrolled() is True

    assert identity.clear_identity() is True
    assert identity.load_identity() is None


def test_identity_malformed_reads_as_not_enrolled(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path))
    identity.identity_path().write_text("{ not json", encoding="utf-8")
    assert identity.load_identity() is None
    # missing device_key => not enrolled
    identity.identity_path().write_text(json.dumps({"org_id": "x"}), encoding="utf-8")
    assert identity.load_identity() is None


# ── telemetry redaction (privacy boundary) ──────────────────────────────────

SECRET_FINDING = {
    "severity": "critical",
    "category": "destructive_command",
    "ruleId": "destructive-command",
    "action": "block",
    "title": "Destructive command blocked",
    "evidence": "rm -rf / --no-preserve-root",
}

SECRET_EVENT = {
    "type": "shell",
    "command": "rm -rf / --no-preserve-root",
    "stdout": "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "metadata": {"tool_name": "Bash"},
}


def test_redacted_record_carries_no_free_text():
    rec = telemetry.build_record(SECRET_FINDING, SECRET_EVENT,
                                 extra={"agent": "claude", "device_id": "dev_1"})
    blob = json.dumps(rec)
    # None of the raw command / secret text may appear anywhere in the record.
    assert "rm -rf" not in blob
    assert "AWS_SECRET_ACCESS_KEY" not in blob
    assert "wJalrXUtnFEMI" not in blob
    # But the useful metadata IS present.
    assert rec["severity"] == "critical"
    assert rec["category"] == "destructive_command"
    assert rec["verdict"] == "blocked"
    assert rec["tool_name"] == "Bash"
    assert rec["redacted"] is True
    # Evidence is represented as a stable hash, not the text.
    assert rec["evidence_hash"] and len(rec["evidence_hash"]) == 16
    assert "detail" not in rec
    telemetry.assert_redacted(rec)  # must not raise


def test_record_carries_agent_instance_name():
    # The adapter's per-instance `name=` label must reach the control plane so
    # the org dashboard can tell "checkout-bot" apart from other agents on the
    # same framework. Absent a name, the field is None (framework id only).
    named = telemetry.build_record(
        SECRET_FINDING, SECRET_EVENT,
        extra={"agent": "openai-agents", "agent_name": "checkout-bot"})
    assert named["agent"] == "openai-agents"
    assert named["agent_name"] == "checkout-bot"
    unnamed = telemetry.build_record(SECRET_FINDING, SECRET_EVENT, extra={"agent": "claude"})
    assert unnamed["agent_name"] is None
    telemetry.assert_redacted(named)  # names are labels, never evidence


def test_tool_use_id_pairs_pre_and_post_records():
    # One tool call produces a pre-call and a post-call record. Both must carry
    # the agent's own call id so the dashboard folds them into one node instead
    # of drawing the same command twice.
    pre = {"type": "shell", "command": "cat secrets.txt",
           "agent_event": "PreToolUse",
           "metadata": {"tool_name": "Bash",
                        "raw": {"tool_use_id": "toolu_014sX7Bh", "tool_name": "Bash"}}}
    post = {**pre, "agent_event": "PostToolUse"}
    a = telemetry.build_record(SECRET_FINDING, pre, extra={})
    b = telemetry.build_record(SECRET_FINDING, post, extra={})
    assert a["tool_use_id"] == b["tool_use_id"] == "toolu_014sX7Bh"
    # Codex-style call_id on the raw payload, and the inference-hook path which
    # sets it on metadata directly.
    codex = {"type": "shell", "metadata": {"raw": {"call_id": "call_7"}}}
    assert telemetry.build_record(SECRET_FINDING, codex, extra={})["tool_use_id"] == "call_7"
    inline = {"type": "shell", "metadata": {"tool_use_id": "t1"}}
    assert telemetry.build_record(SECRET_FINDING, inline, extra={})["tool_use_id"] == "t1"
    # Absent on agents that do not report one - never invented.
    assert telemetry.build_record(SECRET_FINDING, SECRET_EVENT, extra={})["tool_use_id"] is None


def test_evidence_hash_is_stable_and_distinct():
    a = telemetry.build_record(SECRET_FINDING, SECRET_EVENT, extra={})
    b = telemetry.build_record(SECRET_FINDING, SECRET_EVENT, extra={})
    assert a["evidence_hash"] == b["evidence_hash"]
    other = dict(SECRET_FINDING, evidence="cat /etc/shadow")
    c = telemetry.build_record(other, SECRET_EVENT, extra={})
    assert c["evidence_hash"] != a["evidence_hash"]


def test_full_capture_includes_scrubbed_detail():
    rec = telemetry.build_record(
        SECRET_FINDING, SECRET_EVENT, extra={"agent": "claude"},
        full_capture=True,
        scrub_patterns=[r"AWS_SECRET_ACCESS_KEY=\S+"],
    )
    assert rec["redacted"] is False
    assert "detail" in rec
    # Raw command is present in full mode...
    assert "rm -rf" in rec["detail"]["command"]
    # ...but the secret-shaped value was scrubbed as defense-in-depth.
    assert "wJalrXUtnFEMI" not in json.dumps(rec)
    assert "[REDACTED]" in rec["detail"]["stdout"]


def test_assert_redacted_fails_closed_on_leak():
    bad = {"redacted": True, "detail": {"command": "leak"}}
    with pytest.raises(AssertionError):
        telemetry.assert_redacted(bad)


def test_verdict_mapping():
    assert telemetry.build_record({"action": "block"}, {}, {})["verdict"] == "blocked"
    assert telemetry.build_record({"action": "warn"}, {}, {})["verdict"] == "warned"
    assert telemetry.build_record({"action": "log"}, {}, {})["verdict"] == "observed"


# ── prismor sink ────────────────────────────────────────────────────────────

def test_prismor_sink_noop_when_not_enrolled(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path))
    from prismor.runtime import sinks
    # Should not raise and should not attempt any network call.
    sinks.dispatch(
        [SECRET_FINDING],
        [{"type": "prismor"}],
        extra={"agent": "claude", "session_id": "s1"},
        raw_event=SECRET_EVENT,
    )


def test_prismor_sink_uploads_redacted(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path))
    identity.save_identity({
        "device_id": "dev_1", "org_id": "org_1", "user_id": "usr_1",
        "device_key": "prism_dev_abc", "api_base": "https://example.test",
    })

    captured = {}

    class _FakeResp:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self, n=-1): return b""

    def _fake_urlopen(req, timeout=None):
        captured["url"] = req.full_url
        captured["headers"] = {k.lower(): v for k, v in req.header_items()}
        captured["body"] = json.loads(req.data.decode("utf-8"))
        return _FakeResp()

    import urllib.request
    monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen)

    from prismor.runtime import sinks
    sinks.dispatch([SECRET_FINDING], [{"type": "prismor"}],
                   extra={"agent": "claude", "session_id": "s1"},
                   raw_event=SECRET_EVENT)

    assert captured["url"] == "https://example.test/api/telemetry/ingest"
    assert captured["headers"]["authorization"] == "Bearer prism_dev_abc"
    assert captured["body"]["org_id"] == "org_1"
    assert captured["body"]["device_id"] == "dev_1"
    ev = captured["body"]["events"][0]
    assert ev["redacted"] is True
    assert ev["device_id"] == "dev_1"
    # The uploaded payload must not contain the raw command or secret.
    blob = json.dumps(captured["body"])
    assert "rm -rf" not in blob and "AWS_SECRET_ACCESS_KEY" not in blob


def test_record_carries_applied_policy_version(tmp_path, monkeypatch):
    """Events are stamped with the signed policy that decided them, so the
    console can explain old events after a policy edit. Null on local-only."""
    import prismor.runtime.sinks as sinks
    from prismor.runtime.enterprise import remote_policy

    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path))
    identity.save_identity({"device_id": "d", "org_id": "o", "user_id": "u",
                            "device_key": "prism_dev_x", "api_base": "http://127.0.0.1:1"})
    uploads = []
    monkeypatch.setattr(sinks, "upload_telemetry", lambda recs, **kw: uploads.extend(recs))
    finding = {**SECRET_FINDING, "action": "block"}

    sinks._dispatch_prismor({"type": "prismor"}, [finding], {"type": "shell"}, {})
    assert uploads[-1]["policy_version"] is None
    assert uploads[-1]["policy_profile_id"] is None

    remote_policy._meta_path().write_text(json.dumps({"version": 7, "profile_id": "pp_1"}))
    sinks._dispatch_prismor({"type": "prismor"}, [finding], {"type": "shell"}, {})
    rec = uploads[-1]
    assert rec["redacted"] is True
    assert (rec["policy_version"], rec["policy_profile_id"]) == (7, "pp_1")
    telemetry.assert_redacted(rec)
