"""#539: Codex's global hook config is $CODEX_HOME/hooks.json, not always ~/.codex."""
from pathlib import Path

from prismor.runtime.hooks import _config_path, hook_installed

HOOK = '{"hooks": {"PreToolUse": [{"hooks": [{"command": "python -m x hook-dispatch --agent codex"}]}]}}'


def test_global_codex_path_follows_codex_home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "user"))
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "cx"))
    assert _config_path("codex", "global", tmp_path) == tmp_path / "cx" / "hooks.json"


def test_hooks_in_default_home_do_not_count_when_codex_home_is_elsewhere(tmp_path, monkeypatch):
    user = tmp_path / "user"
    (user / ".codex").mkdir(parents=True)
    (user / ".codex" / "hooks.json").write_text(HOOK)
    (tmp_path / "cx").mkdir()
    monkeypatch.setenv("HOME", str(user))
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "cx"))
    assert not hook_installed("codex", "global", tmp_path)
    (tmp_path / "cx" / "hooks.json").write_text(HOOK)
    assert hook_installed("codex", "global", tmp_path)
