"""`prismor status` must report the org policy's mode on an enrolled device,
not the hook's local --mode (PrismorSec/prismor#504)."""
from __future__ import annotations

import json

from prismor.runtime import cli
from prismor.runtime.enterprise import identity, remote_policy


def test_status_shows_org_mode(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text(json.dumps({"hooks": {"PreToolUse": [
        {"hooks": [{"type": "command", "command": "x hook-dispatch --agent claude --mode observe"}]}]}}))
    monkeypatch.setattr(identity, "is_enrolled", lambda: True)
    monkeypatch.setattr(remote_policy, "verify_and_load", lambda: {"settings": {"default_mode": "enforce"}})
    monkeypatch.setattr(remote_policy, "current_version", lambda: 4)
    cli._print_status_overview(tmp_path)
    out = capsys.readouterr().out
    assert "enforce" in out and "org policy v4" in out
    assert "setup --mode enforce" not in out
