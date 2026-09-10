"""Tests for the per-tool-call volume heartbeat (prismor/runtime/enterprise/heartbeat.py).

Invariants:
  * Not enrolled → record_call is a no-op (zero files, zero cost).
  * Calls accumulate per agent instance (<framework>|<name>); maybe_flush
    respects the debounce window.
  * A due flush emits one agent_activity record PER non-zero instance key,
    resets the counters, and never double-sends.
  * Upload failure → the records land in the offline spool (counts preserved).
  * v1 (flat) counter files migrate into the framework-level key.
  * >MAX_COUNTER_KEYS instances on one device fold into the framework key.
"""
from __future__ import annotations

import json
import time

import pytest


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / ".prismor"))
    yield


def _enroll(api_base="http://127.0.0.1:1"):
    from prismor.runtime.enterprise import identity
    identity.save_identity({
        "device_id": "d1", "org_id": "o1", "user_id": "u1",
        "device_key": "prism_dev_x", "api_base": api_base,
    })


def test_record_call_noop_when_not_enrolled():
    from prismor.runtime.enterprise import heartbeat
    heartbeat.record_call(agent="claude", session_id="s1")
    assert not heartbeat._counter_path().exists()


def test_calls_accumulate_and_flush_debounces(monkeypatch):
    from prismor.runtime.enterprise import heartbeat
    _enroll()

    sent = []
    monkeypatch.setattr("prismor.runtime.sinks.upload_telemetry", lambda recs, **kw: sent.extend(recs))

    for _ in range(5):
        heartbeat.record_call(agent="claude", session_id="s1")
    data = json.loads(heartbeat._counter_path().read_text())
    assert data["counters"]["claude|"]["count"] == 5

    # Within the debounce window (last_flush was set on first record) → no flush.
    assert heartbeat.maybe_flush() is False
    assert sent == []

    # Past the window → exactly one record with the accumulated count.
    assert heartbeat.maybe_flush(now=time.time() + heartbeat.FLUSH_INTERVAL + 1) is True
    assert len(sent) == 1
    rec = sent[0]
    assert rec["type"] == "agent_activity"
    assert rec["count"] == 5
    assert rec["agent"] == "claude"
    assert "agent_name" not in rec  # unnamed instance
    assert rec["redacted"] is True

    # Counter reset — the next tick still calls through (it is what drains the
    # telemetry spool that findings now ride) but has no counts to send.
    assert heartbeat.maybe_flush(now=time.time() + 2 * heartbeat.FLUSH_INTERVAL + 2) is True
    assert len(sent) == 1


def test_per_instance_keying(monkeypatch):
    """Two named agents + one unnamed on the same framework → three records."""
    from prismor.runtime.enterprise import heartbeat
    _enroll()

    sent = []
    monkeypatch.setattr("prismor.runtime.sinks.upload_telemetry", lambda recs, **kw: sent.extend(recs))

    for _ in range(4):
        heartbeat.record_call(agent="openai-agents", agent_name="checkout-bot", session_id="s1")
    for _ in range(2):
        heartbeat.record_call(agent="openai-agents", agent_name="support-bot", session_id="s2")
    heartbeat.record_call(agent="openai-agents", session_id="s3")  # unnamed

    counters = json.loads(heartbeat._counter_path().read_text())["counters"]
    assert counters["openai-agents|checkout-bot"]["count"] == 4
    assert counters["openai-agents|support-bot"]["count"] == 2
    assert counters["openai-agents|"]["count"] == 1

    assert heartbeat.maybe_flush(now=time.time() + heartbeat.FLUSH_INTERVAL + 1) is True
    by_name = {r.get("agent_name", ""): r for r in sent}
    assert by_name["checkout-bot"]["count"] == 4 and by_name["checkout-bot"]["agent"] == "openai-agents"
    assert by_name["support-bot"]["count"] == 2
    assert by_name[""]["count"] == 1 and "agent_name" not in by_name[""]


def test_v1_file_migrates_to_framework_key(monkeypatch):
    """A pre-existing v1 flat counter file is read as a framework-level key."""
    from prismor.runtime.enterprise import heartbeat
    _enroll()
    # Simulate a v1 file left by an older runtime.
    heartbeat._counter_path().parent.mkdir(parents=True, exist_ok=True)
    heartbeat._counter_path().write_text(json.dumps(
        {"count": 7, "agent": "cursor", "session_id": "s9", "last_flush": 0}
    ))

    sent = []
    monkeypatch.setattr("prismor.runtime.sinks.upload_telemetry", lambda recs, **kw: sent.extend(recs))
    assert heartbeat.maybe_flush(now=time.time() + heartbeat.FLUSH_INTERVAL + 1) is True
    assert len(sent) == 1
    assert sent[0]["agent"] == "cursor" and sent[0]["count"] == 7
    assert "agent_name" not in sent[0]


def test_key_cap_folds_into_framework_key():
    """More than MAX_COUNTER_KEYS instances on one device fold into the
    framework key so volume is preserved past the cap."""
    from prismor.runtime.enterprise import heartbeat
    _enroll()
    for i in range(heartbeat.MAX_COUNTER_KEYS + 20):
        heartbeat.record_call(agent="langchain", agent_name=f"bot-{i}", session_id="s")
    counters = json.loads(heartbeat._counter_path().read_text())["counters"]
    # At most MAX_COUNTER_KEYS named instances plus the framework fold bucket.
    assert len(counters) <= heartbeat.MAX_COUNTER_KEYS + 1
    # Overflow landed on the framework-level key.
    assert counters.get("langchain|", {}).get("count", 0) >= 20
    total = sum(v["count"] for v in counters.values())
    assert total == heartbeat.MAX_COUNTER_KEYS + 20  # nothing lost


def test_failed_flush_lands_in_spool():
    from prismor.runtime.enterprise import heartbeat, telemetry_spool
    _enroll(api_base="http://127.0.0.1:1")  # dead endpoint

    for _ in range(3):
        heartbeat.record_call(agent="codex", session_id="s2")
    assert heartbeat.maybe_flush(now=time.time() + heartbeat.FLUSH_INTERVAL + 1) is True

    spooled = telemetry_spool.drain(limit=10)
    assert len(spooled) == 1
    assert spooled[0]["type"] == "agent_activity"
    assert spooled[0]["count"] == 3
    # Counters were reset — the count lives in the spool, not both places.
    assert json.loads(heartbeat._counter_path().read_text())["counters"] == {}
