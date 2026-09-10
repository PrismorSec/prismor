"""The prismor control-plane sink batches through the offline spool.

One POST per finding was affordable while findings were rare. Under the org's
full_capture opt-in every evaluated call becomes a finding (runtime.py
synthesizes `audit-allowed` for the unflagged ones), so that shape means one
request per tool call. These tests pin the batching contract:

  * observed/warned records are spooled, not posted;
  * a blocked verdict still goes immediately;
  * a full spool flushes without waiting for the heartbeat tick;
  * the heartbeat tick drains the spool even with no counts of its own.
"""
import prismor.runtime.sinks as sinks
import prismor.runtime.enterprise.identity as ident
import prismor.runtime.enterprise.telemetry as telem
import prismor.runtime.enterprise.telemetry_spool as spool


def _setup(monkeypatch, tmp_path, verdict):
    # A real identity file rather than a patched load_identity: tests/test_defer.py
    # pops the identity module out of sys.modules, so modules that imported it by
    # reference keep the old object and never observe an attribute patch.
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path))
    ident.save_identity({
        "device_id": "d", "org_id": "o", "user_id": "u",
        "device_key": "prism_dev_x", "api_base": "http://127.0.0.1:1",
    })
    monkeypatch.setattr(telem, "build_record", lambda *a, **k: {"ts": None, "verdict": verdict})
    monkeypatch.setattr(telem, "assert_redacted", lambda rec: None)
    uploads = []
    monkeypatch.setattr(sinks, "upload_telemetry", lambda recs, **kw: uploads.append(recs))
    return uploads


def _finding():
    return {"severity": "HIGH", "category": "x", "ruleId": "r", "title": "t", "id": "s:f"}


def test_observed_findings_spool_instead_of_posting(monkeypatch, tmp_path):
    uploads = _setup(monkeypatch, tmp_path, "observed")

    for _ in range(3):
        sinks._dispatch_prismor({"type": "prismor"}, [_finding()], {"type": "shell"}, {})

    assert uploads == [], "observed findings must not POST per event"
    assert spool.pending_count() == 3


def test_blocked_finding_uploads_immediately(monkeypatch, tmp_path):
    """An alert 60s late is not an alert."""
    uploads = _setup(monkeypatch, tmp_path, "blocked")

    sinks._dispatch_prismor({"type": "prismor"}, [_finding()], {"type": "shell"}, {})

    assert len(uploads) == 1 and len(uploads[0]) == 1
    assert spool.pending_count() == 0


def test_full_spool_forces_a_flush(monkeypatch, tmp_path):
    uploads = _setup(monkeypatch, tmp_path, "observed")
    monkeypatch.setattr(sinks, "FLUSH_BATCH", 5)

    for _ in range(5):
        sinks._dispatch_prismor({"type": "prismor"}, [_finding()], {"type": "shell"}, {})

    # The last append crossed the threshold: one drain call carrying no new
    # records of its own (upload_telemetry pulls the batch out of the spool).
    assert uploads == [[]]


def test_heartbeat_tick_drains_the_spool_with_no_counts(monkeypatch, tmp_path):
    """The 60s tick is what ships spooled findings, so it must call through
    even when the device recorded no tool calls in the window."""
    import time
    from prismor.runtime.enterprise import heartbeat

    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path))
    ident.save_identity({
        "device_id": "d", "org_id": "o", "user_id": "u",
        "device_key": "prism_dev_x", "api_base": "http://127.0.0.1:1",
    })
    sent = []
    monkeypatch.setattr("prismor.runtime.sinks.upload_telemetry",
                        lambda recs, **kw: sent.append(recs))

    heartbeat.record_call(agent="claude", session_id="s1")
    # Drop the counter so the tick has nothing of its own to report.
    import json
    heartbeat._counter_path().write_text(
        json.dumps({"v": 2, "last_flush": 0, "counters": {}}), encoding="utf-8")

    assert heartbeat.maybe_flush(now=time.time() + heartbeat.FLUSH_INTERVAL + 1) is True
    assert sent == [[]], "the tick must still call upload_telemetry to drain the spool"
