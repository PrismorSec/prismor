"""Workspace discovery from a subdirectory, and BOM-aware policy loading."""
import pytest

from prismor.runtime import cli
from prismor.runtime.policy_engine import PolicyEngine, validate_policy
from prismor.runtime.store import infer_default_workspace

POLICY = (
    'version: "1.0"\nsettings:\n  default_mode: enforce\nrules:\n'
    "  - id: no-psql\n    severity: HIGH\n    category: custom\n    title: no psql\n"
    "    event_types: [shell]\n    fields: [command]\n    patterns: ['psql -h prod']\n    action: block\n"
)


@pytest.fixture
def ws(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    w = tmp_path / "proj" / "ws"
    (w / ".prismor").mkdir(parents=True)
    (w / "sub" / "deep").mkdir(parents=True)
    return w


def test_workspace_found_from_subdirectory_via_prismor_dir(ws):
    (ws / ".prismor" / "policy.yaml").write_text(POLICY)
    assert infer_default_workspace(ws / "sub" / "deep") == ws.resolve()


def test_workspace_found_from_subdirectory_via_git(ws):
    (ws / ".prismor" / "policy.yaml").unlink(missing_ok=True)
    (ws / ".prismor").rmdir()
    (ws / ".git").mkdir()
    assert infer_default_workspace(ws / "sub") == ws.resolve()


def test_nearest_marker_wins(ws):
    (ws / ".git").mkdir()
    inner = ws / "sub"
    (inner / ".prismor").mkdir()
    (inner / ".prismor" / "policy.yaml").write_text(POLICY)
    assert infer_default_workspace(inner / "deep") == inner.resolve()


def test_home_state_dir_is_not_a_workspace(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".prismor").mkdir(parents=True)
    (home / ".prismor" / "policy.yaml").write_text(POLICY)
    (home / "scratch").mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    assert infer_default_workspace(home / "scratch") == (home / "scratch").resolve()


@pytest.mark.parametrize("encoding", ["utf-8-sig", "utf-16", "utf-16-le"])
def test_policy_loads_with_bom_or_utf16(ws, encoding):
    p = ws / ".prismor" / "policy.yaml"
    p.write_bytes(POLICY.encode(encoding))
    assert validate_policy(p) == []
    eng = PolicyEngine(workspace=ws)
    assert not eng.project_policy_error
    assert any(f["ruleId"] == "no-psql" for f in eng.check_command("psql -h prod-db"))


def test_check_exits_nonzero_when_project_policy_is_unreadable(ws, monkeypatch, capsys):
    (ws / ".prismor" / "policy.yaml").write_bytes(b"\xff\xfe\x00\x00 not: [valid")
    monkeypatch.chdir(ws)
    with pytest.raises(SystemExit) as exc:
        cli.main(["check", "echo hello"])
    assert exc.value.code == 2
    assert "project policy is invalid" in capsys.readouterr().err


def test_check_from_subdirectory_applies_project_policy(ws, monkeypatch):
    (ws / ".prismor" / "policy.yaml").write_text(POLICY)
    monkeypatch.chdir(ws / "sub")
    with pytest.raises(SystemExit) as exc:
        cli.main(["check", "psql -h prod-db"])
    assert exc.value.code == 2
