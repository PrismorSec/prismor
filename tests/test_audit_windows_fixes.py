"""audit: real hook entries only, exit codes shared by text and JSON, no .sh on Windows without sh."""
from __future__ import annotations

import pytest

from prismor.runtime import audit as au
from prismor.runtime.cli import main


def test_mcp_mention_of_dispatcher_is_not_a_hook():
    assert not au._json_has_hook({"mcpServers": {"x": {"args": ["hook-dispatch"]}}})
    assert au._json_has_hook({"hooks": {"PreToolUse": [{"hooks": [{"command": "py hook-dispatch.py"}]}]}})


def test_has_hook_entry_checks_the_file(tmp_path, monkeypatch):
    from prismor.runtime import hooks
    cfg = tmp_path / "hooks.json"
    monkeypatch.setattr(hooks, "_config_path", lambda a, s, w: cfg)
    assert not au._has_hook_entry("cursor", "global", tmp_path)  # file missing
    cfg.write_text('{"mcpServers": {"x": {"command": "hook-dispatch"}}}')
    assert not au._has_hook_entry("cursor", "global", tmp_path)
    cfg.write_text('{"hooks": {"preToolUse": [{"command": "python hook-dispatch.py"}]}}')
    assert au._has_hook_entry("cursor", "global", tmp_path)


@pytest.mark.parametrize("sev,code", [("CRITICAL", 2), ("HIGH", 1), ("MEDIUM", 1), ("LOW", 0), ("PASS", 0)])
def test_json_and_text_exit_codes_match(tmp_path, monkeypatch, sev, code):
    monkeypatch.setattr(au, "run_audit", lambda workspace, repo_root: [au.AuditFinding(sev, "hooks", "m")])
    for extra in ([], ["--json"]):
        try:
            main(["audit", "--workspace", str(tmp_path), *extra])
            got = 0
        except SystemExit as e:
            got = e.code or 0
        assert got == code, extra


def test_cloak_fix_not_offered_on_windows_without_shell(tmp_path, monkeypatch):
    import shutil
    monkeypatch.setattr(au, "_is_windows", lambda: True)
    monkeypatch.setattr(shutil, "which", lambda *_: None)
    monkeypatch.setattr("prismor.runtime.cloaking.status", lambda **k: {"installed": False})
    monkeypatch.setattr("prismor.runtime.cloaking.list_secrets", lambda: [])
    found = au._check_cloaking(tmp_path)
    assert not any(f.fixable for f in found) and "Git Bash" in found[0].message
