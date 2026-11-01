"""Which agents setup installs into without being asked, and how it reports
an install where only some of them took.

OpenClaw was pre-selected because /usr/bin/openclaw exists; its project-scope
plugin is not loaded by OpenClaw (it reads its own workspace), so setup ended
"did not finish: these agents are NOT protected" with Claude Code installed
fine. And `prismor enroll` then offered a machine-wide install defaulting to
Yes.
"""
import os
import sys
import tempfile
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prismor.runtime import setup_wizard as wizard  # noqa: E402


def test_agents_needing_activation_are_detected_but_not_defaulted():
    det = {"claude": True, "openclaw": True, "hermes": True, "cursor": False, "codex": True}
    assert wizard._default_agents(det) == ["claude", "codex"]


def test_noninteractive_setup_skips_openclaw_unless_named(tmp_path, monkeypatch):
    seen = {}
    monkeypatch.setattr(wizard, "_detect_agents",
                        lambda t: {"claude": True, "openclaw": True})
    monkeypatch.setattr(wizard, "_do_install",
                        lambda target, mode, rules, agents, **kw: seen.setdefault("agents", agents))
    wizard.run_non_interactive(tmp_path, mode="observe")
    assert seen["agents"] == ["claude"]
    seen.clear()
    wizard.run_non_interactive(tmp_path, mode="observe", agents=["claude", "openclaw"])
    assert seen["agents"] == ["claude", "openclaw"]


def test_agent_step_shows_openclaw_detected_but_unselected(tmp_path, monkeypatch):
    monkeypatch.setattr(wizard, "_detect_agents",
                        lambda t: {"claude": True, "openclaw": True})
    monkeypatch.setattr(wizard, "_render", lambda lines: None)
    monkeypatch.setattr(wizard, "_read_key", lambda: wizard._ENTER)
    result = wizard._step_agents(tmp_path)
    assert result["agents"] == ["claude"]


def _install_with_one_failure(tmp_path, monkeypatch, capsys, warning):
    home = tempfile.mkdtemp(prefix="prismor-partial-home-")
    monkeypatch.setenv("HOME", home)

    def fake_install_hooks(*, agent, **kw):
        if agent == "openclaw":
            return [{"agent": agent, "loadWarning": warning}]
        return [{"agent": agent}]

    monkeypatch.setattr("prismor.runtime.hooks.install_hooks", fake_install_hooks)
    with mock.patch.object(wizard, "_REPO_ROOT", Path("/nonexistent")), \
            pytest.raises(SystemExit) as exc:
        wizard._do_install(tmp_path, "observe", rules=[], agents=["claude", "openclaw"],
                           cloak=False, scope="project")
    return exc.value.code, capsys.readouterr().out


def test_partial_install_names_protected_and_unprotected_agents(tmp_path, monkeypatch, capsys):
    code, out = _install_with_one_failure(
        tmp_path, monkeypatch, capsys,
        "OpenClaw does not list the Prismor plugin (openclaw plugins list).")
    assert code == 1  # scripts still see that something they asked for failed
    assert "finished only partly" in out
    protected = next(l for l in out.splitlines() if "Protected:" in l and "NOT" not in l)
    unprotected = next(l for l in out.splitlines() if "NOT protected:" in l)
    assert "claude" in protected and "openclaw" not in protected
    assert "openclaw" in unprotected and "claude" not in unprotected
    assert "did not finish" not in out
    assert "--scope global" in out


def test_all_failed_keeps_the_not_finished_message(tmp_path, monkeypatch, capsys):
    home = tempfile.mkdtemp(prefix="prismor-partial-home-")
    monkeypatch.setenv("HOME", home)
    monkeypatch.setattr("prismor.runtime.hooks.install_hooks",
                        lambda **kw: (_ for _ in ()).throw(PermissionError("read-only")))
    with mock.patch.object(wizard, "_REPO_ROOT", Path("/nonexistent")), \
            pytest.raises(SystemExit):
        wizard._do_install(tmp_path, "observe", rules=[], agents=["claude"],
                           cloak=False, scope="project")
    out = capsys.readouterr().out
    assert "did not finish" in out and "partly" not in out


class TestPostEnrollPrompt:
    def _offer(self, tmp_path, monkeypatch, answer):
        from prismor.runtime import cli
        from prismor.runtime import system_install
        calls = []
        prompts = []
        monkeypatch.setattr(system_install, "is_system_managed", lambda: False)
        monkeypatch.setattr(wizard, "_detect_agents", lambda t: {"claude": True, "cursor": False})
        monkeypatch.setattr(wizard, "run_non_interactive", lambda *a, **kw: calls.append(kw))
        monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True, raising=False)
        monkeypatch.setattr("builtins.input", lambda p: (prompts.append(p), answer)[1])
        cli._offer_post_enroll_install(tmp_path)
        return calls, prompts

    def test_enter_does_not_install_machine_wide(self, tmp_path, monkeypatch):
        calls, prompts = self._offer(tmp_path, monkeypatch, "")
        assert calls == []
        assert "[y/N]" in prompts[0]

    def test_explicit_yes_installs_globally(self, tmp_path, monkeypatch):
        calls, _ = self._offer(tmp_path, monkeypatch, "y")
        assert calls and calls[0]["scope"] == "global" and calls[0]["agents"] == ["claude"]
