"""Codex runs no hook it has not been told to trust; Prismor must know and say so."""
from pathlib import Path

from prismor.runtime.hooks import codex_hook_trust
from prismor.runtime.cli import codex_trust_line

EVENTS = ("user_prompt_submit", "pre_tool_use", "permission_request", "post_tool_use")


def _workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "repo"
    (ws / ".codex").mkdir(parents=True)
    (ws / ".codex" / "hooks.json").write_text('{"hooks": {"PostToolUse": [{"hooks": [{"command": "python hook-dispatch --agent codex"}]}]}}')
    return ws


def _codex_home(tmp_path: Path, hooks_json: Path, events) -> Path:
    home = tmp_path / "codex-home"
    home.mkdir()
    body = 'model = "gpt-5.6-sol"\n\n[hooks.state]\n'
    for ev in events:
        body += f'[hooks.state."{hooks_json}:{ev}:0:0"]\ntrusted_hash = "sha256:abc"\n\n'
    (home / "config.toml").write_text(body)
    return home


def test_no_hooks_file_means_nothing_to_trust(tmp_path):
    assert codex_hook_trust(tmp_path, codex_home=tmp_path)["status"] == "not-installed"


def test_installed_but_never_trusted_is_reported_as_untrusted(tmp_path):
    ws = _workspace(tmp_path)
    home = _codex_home(tmp_path, ws / ".codex" / "hooks.json", events=())
    trust = codex_hook_trust(ws, codex_home=home)
    assert trust["status"] == "untrusted"
    assert set(trust["missing"]) == set(EVENTS)


def test_every_event_trusted_means_the_hooks_will_run(tmp_path):
    ws = _workspace(tmp_path)
    home = _codex_home(tmp_path, (ws / ".codex" / "hooks.json").resolve(), events=EVENTS)
    trust = codex_hook_trust(ws, codex_home=home)
    assert (trust["status"], trust["missing"]) == ("trusted", [])


def test_global_scope_hooks_are_checked_too(tmp_path):
    ws = tmp_path / "repo"
    ws.mkdir()                                     # no project hooks at all
    home = _codex_home(tmp_path, tmp_path / "unused", events=())
    (home / "hooks.json").write_text('{"hooks": {"PostToolUse": [{"hooks": [{"command": "hook-dispatch --agent codex"}]}]}}')
    trust = codex_hook_trust(ws, codex_home=home)
    assert trust["status"] == "untrusted" and "global" in trust["scopes"]


def test_a_users_own_global_hooks_are_not_judged(tmp_path):
    ws = tmp_path / "repo"
    ws.mkdir()
    home = _codex_home(tmp_path, tmp_path / "unused", events=())
    (home / "hooks.json").write_text('{"hooks": {"PostToolUse": [{"hooks": [{"command": "my-own-linter"}]}]}}')
    assert codex_hook_trust(ws, codex_home=home)["status"] == "not-installed"


def test_one_untrusted_event_is_still_a_gap(tmp_path):
    ws = _workspace(tmp_path)
    home = _codex_home(tmp_path, (ws / ".codex" / "hooks.json").resolve(),
                       events=("user_prompt_submit", "pre_tool_use", "permission_request"))
    trust = codex_hook_trust(ws, codex_home=home)
    assert trust["status"] == "untrusted" and trust["missing"] == ["post_tool_use"]


def test_the_warning_names_the_consequence_and_the_fix(tmp_path, monkeypatch):
    ws = _workspace(tmp_path)
    home = _codex_home(tmp_path, ws / ".codex" / "hooks.json", events=())
    monkeypatch.setenv("CODEX_HOME", str(home))
    line = codex_trust_line(ws)
    assert line and "unscreened" in line and "hook-trust" in line
    assert "--dangerously-bypass-hook-trust" in line


def test_no_warning_once_trusted(tmp_path, monkeypatch):
    ws = _workspace(tmp_path)
    home = _codex_home(tmp_path, (ws / ".codex" / "hooks.json").resolve(), events=EVENTS)
    monkeypatch.setenv("CODEX_HOME", str(home))
    assert codex_trust_line(ws) is None
