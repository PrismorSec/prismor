"""Copilot skips .github/hooks in an untrusted folder: say so at install and in status."""
import json

from prismor.runtime import cli
from prismor.runtime.hooks import install_hooks


def _install(ws):
    install_hooks(repo_root=ws, workspace=ws, agent="copilot", scope="project", mode="enforce")


def test_warns_when_folder_not_trusted(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".copilot").mkdir(parents=True)
    (home / ".copilot" / "config.json").write_text(
        "// comment\n" + json.dumps({"trusted_folders": [str(tmp_path / "other")]}))
    monkeypatch.setattr(cli.Path, "home", classmethod(lambda c: home))
    ws = tmp_path / "ws"
    ws.mkdir()
    _install(ws)
    assert "trusted_folders" in cli.copilot_trust_line(ws)


def test_silent_when_trusted_or_not_installed(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".copilot").mkdir(parents=True)
    ws = tmp_path / "ws"
    (ws / "sub").mkdir(parents=True)
    (home / ".copilot" / "config.json").write_text(json.dumps({"trusted_folders": [str(ws)]}))
    monkeypatch.setattr(cli.Path, "home", classmethod(lambda c: home))
    assert cli.copilot_trust_line(ws) is None          # nothing installed
    _install(ws / "sub")
    assert cli.copilot_trust_line(ws / "sub") is None  # parent is trusted


def test_unknown_trust_still_warns(tmp_path, monkeypatch):
    monkeypatch.setattr(cli.Path, "home", classmethod(lambda c: tmp_path / "nohome"))
    ws = tmp_path / "ws"
    ws.mkdir()
    _install(ws)
    assert "cannot tell" in cli.copilot_trust_line(ws)
