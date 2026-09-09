"""Under full_capture every evaluated call ships to the control-plane sink,
not just the flagged ones; redacted orgs keep findings-only."""
from unittest import mock

from prismor.runtime import runtime as rt
from prismor.runtime.enterprise import telemetry


def _run(full_capture, findings, tmp_path):
    engine = mock.Mock(outputs=[{"type": "prismor"}], workspace_managed=False, active_exemption=None)
    sent = []
    with mock.patch("prismor.runtime.enterprise.remote_policy.current_full_capture", return_value=full_capture), \
         mock.patch("prismor.runtime.sinks.dispatch", side_effect=lambda f, *a, **k: sent.extend(f)):
        rt._dispatch_telemetry(
            engine=engine, findings=findings, event={"type": "shell", "command": "ls"},
            workspace=tmp_path, agent="claude", mode="observe", session_id="s1",
            subject=mock.Mock(as_dict=lambda: {}),
        )
    return sent


def test_clean_call_ships_under_full_capture(tmp_path):
    sent = _run(True, [], tmp_path)
    assert len(sent) == 1 and telemetry._verdict(sent[0]) == "allowed"


def test_clean_call_dropped_when_redacted(tmp_path):
    assert _run(False, [], tmp_path) == []


def test_findings_still_ship(tmp_path):
    f = [{"action": "block", "title": "x"}]
    assert _run(False, f, tmp_path) == f
