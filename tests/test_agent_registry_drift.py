"""Every agent in ``_SUPPORTED_AGENTS`` must be reachable from every surface
that lists agents: the registry, the install/uninstall CLI, setup's detection,
and the status/doctor scans. Each of these used to keep its own hand-written
list, and agents added later (gemini, opencode, ...) silently went missing."""

import json
from pathlib import Path

import pytest

from prismor.runtime import hooks
from prismor.runtime.cli import _hooks_by_scope, build_parser
from prismor.runtime.hooks import _SUPPORTED_AGENTS, install_hooks
from prismor.runtime.integrations.registry import BLOCKING, get

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_registry_schema_blocking_modes_match_runtime():
    schema = json.loads(
        (REPO_ROOT / "prismor/runtime/integrations/registry.schema.json").read_text()
    )
    blocking = schema["definitions"]["integration"]["properties"]["blocking"]["enum"]
    assert set(blocking) == BLOCKING


@pytest.mark.parametrize("agent", _SUPPORTED_AGENTS)
def test_registry_marks_every_supported_agent_shipped(agent):
    entry = get(agent)
    assert entry is not None, f"{agent} missing from registry.yaml"
    assert entry.status == "shipped", f"{agent} is implemented but registry says {entry.status!r}"
    assert entry.normalizer and hasattr(hooks, entry.normalizer), (
        f"{agent}: registry normalizer {entry.normalizer!r} is not a hooks.py function"
    )


@pytest.mark.parametrize("subcommand", ["install-hooks", "uninstall-hooks"])
@pytest.mark.parametrize("agent", [*_SUPPORTED_AGENTS, "all"])
def test_install_and_uninstall_accept_every_supported_agent(subcommand, agent):
    args = build_parser().parse_args([subcommand, "--agent", agent])
    assert args.agent == agent


def test_setup_detects_every_supported_agent(tmp_path):
    from prismor.runtime.setup_wizard import _detect_agents
    assert set(_SUPPORTED_AGENTS) <= set(_detect_agents(tmp_path))


@pytest.mark.parametrize("agent,marker", [
    ("copilot", (".github", "hooks")),
    ("gemini", (".gemini",)),
    ("opencode", (".opencode",)),
])
def test_setup_detects_project_markers(tmp_path, agent, marker):
    from prismor.runtime.setup_wizard import _detect_agents
    tmp_path.joinpath(*marker).mkdir(parents=True)
    assert _detect_agents(tmp_path)[agent] is True


def test_bare_github_dir_is_not_copilot(tmp_path, monkeypatch):
    from prismor.runtime import setup_wizard
    monkeypatch.setattr(setup_wizard.shutil, "which", lambda _name: None)
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    assert setup_wizard._detect_agents(tmp_path)["copilot"] is False


@pytest.mark.parametrize("agent", ["gemini", "opencode", "continue", "antigravity"])
def test_status_scan_sees_agents_outside_the_old_hardcoded_list(tmp_path, agent):
    install_hooks(repo_root=REPO_ROOT, workspace=tmp_path, agent=agent, scope="project", mode="enforce")
    by_scope = _hooks_by_scope(tmp_path)
    assert by_scope["project"].get(agent) == "enforce"


def test_prismor_hook_file_alone_is_not_an_install(tmp_path, monkeypatch):
    # Installing the Windsurf hook creates ~/.codeium/windsurf/hooks.json; that
    # file alone made Windsurf look installed, so coverage counted it as covered.
    from prismor.runtime import hooks
    from prismor.runtime.setup_wizard import _detect_agents
    home = tmp_path / "home"
    monkeypatch.setattr(Path, "home", staticmethod(lambda: home))
    monkeypatch.setattr("shutil.which", lambda _name: None)
    cfg = hooks._config_path("windsurf", "global", home)
    cfg.parent.mkdir(parents=True)
    cfg.write_text("{}")
    assert _detect_agents(home)["windsurf"] is False
    (home / ".codeium" / "windsurf" / "user_settings.pb").write_text("x")
    assert _detect_agents(home)["windsurf"] is True


def test_home_gemini_dir_is_not_gemini_cli(tmp_path, monkeypatch):
    # Coverage scans with the home dir as the workspace; ~/.gemini belongs to
    # Antigravity, so it must not count as Gemini CLI's project marker there.
    from prismor.runtime.setup_wizard import _detect_agents
    home = tmp_path / "home"
    (home / ".gemini" / "antigravity").mkdir(parents=True)
    (home / ".gemini" / "antigravity" / "state.json").write_text("{}")
    monkeypatch.setattr(Path, "home", staticmethod(lambda: home))
    monkeypatch.setattr("shutil.which", lambda _name: None)
    assert _detect_agents(home)["gemini"] is False
