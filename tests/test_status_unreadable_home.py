import os

import pytest

from prismor.runtime import cli


@pytest.mark.skipif(os.name == "nt" or os.geteuid() == 0, reason="needs POSIX permissions")
def test_status_reports_unreadable_state_dir(tmp_path, monkeypatch, capsys):
    home = tmp_path / ".prismor"
    (home / "sessions").mkdir(parents=True)
    monkeypatch.setenv("PRISMOR_HOME", str(home))
    monkeypatch.setenv("HOME", str(tmp_path))
    home.chmod(0)
    try:
        cli._print_status_overview(tmp_path)
    finally:
        home.chmod(0o700)
    out = capsys.readouterr().out
    assert "cannot read" in out
    assert "unavailable" in out
    assert "workspace is clean" not in out
