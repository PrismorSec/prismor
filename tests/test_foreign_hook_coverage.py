"""A global hook that runs another Prismor home's dispatcher is not this install's coverage.

Found on a box with two installs: a fresh PRISMOR_HOME that declined global
install still reported claude "(all projects)" because ~/.claude/settings.json
carried the other install's hook.
"""
import json

from prismor.runtime import hooks


def _write_global_hook(home, shim):
    cfg = home / ".claude" / "settings.json"
    cfg.parent.mkdir(parents=True)
    cmd = f'"/usr/bin/python3" "{shim}" hook-dispatch --agent claude --mode observe'
    cfg.write_text(json.dumps({"hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": cmd}]}]}}))


def test_other_installs_shim_is_foreign(tmp_path, monkeypatch):
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / "mine"))
    _write_global_hook(home, home / ".prismor" / "hook-dispatch.py")
    assert hooks.hook_installed("claude", "global", tmp_path)
    assert hooks._hook_is_foreign("claude", "global", tmp_path)


def test_own_shim_is_not_foreign(tmp_path, monkeypatch):
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / "mine"))
    _write_global_hook(home, tmp_path / "mine" / "hook-dispatch.py")
    assert not hooks._hook_is_foreign("claude", "global", tmp_path)
