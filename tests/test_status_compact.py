"""`prismor status`: pause state and time left, policy layers, no session dump."""
import time

import pytest

from prismor.runtime import cli, pause


@pytest.mark.parametrize("state,expected", [
    (None, "Paused:      no"),
    ({"source": "local", "until": "soon"}, "yes, 1h 30m left (auto-resumes"),
    ({"source": "local", "until": None}, "yes, no end time; run `prismor resume`"),
    ({"source": "org", "until": None}, "by your organization, no end time"),
])
def test_status_pause_policy_and_no_session(tmp_path, monkeypatch, capsys, state, expected):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / ".prismor-home"))
    if state and state["until"]:
        state = {**state, "until": time.time() + 90 * 60}
    monkeypatch.setattr(pause, "active_state", lambda: state)
    cli._print_status_overview(tmp_path)
    out = capsys.readouterr().out
    assert expected in out
    assert "Policy:" in out and "built-in defaults" in out
    assert "session=" not in out and "atest session" not in out.lower()
