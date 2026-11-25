"""supplychain: pip.ini/PowerShell hint on Windows, docs-matching marker, unknown manager rejected."""
from __future__ import annotations

import pytest

from supplychain import hardener
from supplychain.cli import run_supply
from supplychain.ecosystems.detector import is_known_manager


def _project(tmp_path):
    (tmp_path / "requirements.txt").write_text("flask\n")
    return tmp_path


def test_pip_conf_on_posix_with_docs_marker(tmp_path, monkeypatch):
    monkeypatch.setattr(hardener, "_is_windows", lambda: False)
    (r,) = [r for r in hardener.harden_project(_project(tmp_path)) if r.ecosystem == "pip"]
    assert r.path.name == "pip.conf" and "# prismor supplychain harden" in r.path.read_text()
    assert "export PIP_CONFIG_FILE=pip.conf" in r.notes[0]


def test_pip_ini_and_powershell_note_on_windows(tmp_path, monkeypatch):
    monkeypatch.setattr(hardener, "_is_windows", lambda: True)
    (r,) = [r for r in hardener.harden_project(_project(tmp_path)) if r.ecosystem == "pip"]
    assert r.path.name == "pip.ini" and r.path.exists()
    assert '$env:PIP_CONFIG_FILE = "pip.ini"' in r.notes[0] and "export" not in r.notes[0]


def test_existing_pip_conf_is_kept_on_windows(tmp_path, monkeypatch):
    monkeypatch.setattr(hardener, "_is_windows", lambda: True)
    (tmp_path / "pip.conf").write_text("[global]\n")
    (r,) = [r for r in hardener.harden_project(_project(tmp_path)) if r.ecosystem == "pip"]
    assert r.path.name == "pip.conf"


@pytest.mark.parametrize("argv", [["npm", "install", "x"], ["pip3", "install", "x"], ["python", "-m", "pip", "install", "x"],
                                  ["mvn.cmd", "dependency:get"], ["cargo", "add", "serde"], ["poetry", "add", "x"]])
def test_known_managers(argv):
    assert is_known_manager(argv)


def test_unknown_manager_exits_2(capsys):
    with pytest.raises(SystemExit) as e:
        run_supply(["bogus", "install", "x"])
    assert e.value.code == 2 and "unknown package manager" in capsys.readouterr().err
