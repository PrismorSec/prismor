"""Hook-coverage detection + self-heal: an enrolled device must not have
unguarded agents, and a removed/absent GLOBAL hook is re-asserted."""
from pathlib import Path
from unittest import mock

import pytest

from prismor.runtime import hooks

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def env(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    ws = tmp_path / "ws"
    ws.mkdir()
    (home / ".claude").mkdir()  # makes _detect_agents see 'claude'
    monkeypatch.setattr(Path, "home", staticmethod(lambda: home))
    # Pin detection to claude only, so the test is deterministic regardless of
    # what's installed on the CI host (which() would otherwise vary).
    monkeypatch.setattr(
        "prismor.runtime.setup_wizard._detect_agents",
        lambda target: {"claude": True},
    )
    return home, ws


def test_coverage_flags_unguarded_agent(env):
    _home, ws = env
    cov = hooks.coverage(ws)
    assert cov == {"claude": {"project": False, "global": False, "foreign": False}}
    assert hooks.unguarded_agents(ws) == ["claude"]


def test_ensure_global_coverage_installs_and_is_idempotent(env):
    home, ws = env
    repaired = hooks.ensure_global_coverage(repo_root=REPO_ROOT, workspace=ws)
    assert repaired == ["claude"]
    gp = home / ".claude" / "settings.json"
    assert gp.exists() and "hook-dispatch" in gp.read_text()
    assert hooks.coverage(ws)["claude"]["global"] is True
    assert hooks.unguarded_agents(ws) == []
    # re-run heals nothing (already guarded)
    assert hooks.ensure_global_coverage(repo_root=REPO_ROOT, workspace=ws) == []


def test_self_heal_reasserts_after_removal(env):
    home, ws = env
    hooks.ensure_global_coverage(repo_root=REPO_ROOT, workspace=ws)
    # simulate the user removing the global hook config entirely
    (home / ".claude" / "settings.json").unlink()
    assert hooks.unguarded_agents(ws) == ["claude"]
    assert hooks.ensure_global_coverage(repo_root=REPO_ROOT, workspace=ws) == ["claude"]
    assert hooks.coverage(ws)["claude"]["global"] is True


def test_project_hook_counts_as_guarded_no_reassert(env):
    home, ws = env
    # a project-scoped install (e.g. the demo repo) — not machine-wide, but the
    # agent isn't fully unguarded, so self-heal leaves it alone.
    hooks.install_hooks(repo_root=REPO_ROOT, workspace=ws, agent="claude", scope="project", mode="observe")
    assert hooks.coverage(ws)["claude"] == {"project": True, "global": False, "foreign": False}
    assert hooks.unguarded_agents(ws) == []
    assert hooks.ensure_global_coverage(repo_root=REPO_ROOT, workspace=ws) == []
