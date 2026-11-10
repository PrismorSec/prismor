"""`prismor enroll-status` said "N event(s) spooled for upload (control plane
unreachable)" right after a successful enroll: events also sit in the spool
between batch uploads. "Unreachable" now needs a recorded upload failure or a
verification that could not reach the control plane (demo finding #5)."""
import time

import prismor.runtime.enterprise.telemetry_spool as spool
from prismor.runtime.cli import _spool_status_line


def test_batched_events_after_a_good_verify_are_not_called_unreachable():
    line = _spool_status_line(3, 0, {"ok": True})
    assert "unreachable" not in line
    assert line.startswith("3 event(s) queued")


def test_a_failed_upload_says_unreachable():
    assert "unreachable" in _spool_status_line(3, 2, {"ok": True})


def test_an_unreachable_verify_says_unreachable():
    assert "unreachable" in _spool_status_line(3, 0, {"ok": False, "error": "control plane unreachable"})


def test_upload_failures_tracks_the_backoff_state(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path))
    monkeypatch.delenv("PRISMOR_AGENT_KEY", raising=False)
    assert spool.upload_failures() == 0
    spool.note_upload_failure(time.time())
    spool.note_upload_failure(time.time())
    assert spool.upload_failures() == 2
    spool.clear_backoff()
    assert spool.upload_failures() == 0
