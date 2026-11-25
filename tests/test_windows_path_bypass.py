"""Windows spellings of protected paths and PowerShell/cmd verbs (v1.80.1 Windows test).

Backslash, case, ``:stream``, trailing dot/space, ``\\\\?\\``/UNC prefixes and
``%VAR%`` spellings of a protected path must hit the same rules as the POSIX
spelling; so must the PowerShell and cmd verbs that rm/cp/mv/write them.
"""
import tempfile
from pathlib import Path
from unittest import mock

import pytest

from prismor.runtime.hooks import should_block
from prismor.runtime.policy_engine import PolicyEngine, _SELF_PROTECTION_RULE_IDS, _winpath_canon
from prismor.runtime.setup_wizard import _render_selection_policy

PRE = {"agent_event": "PreToolUse"}


def _engine(selection_empty: bool) -> PolicyEngine:
    d = Path(tempfile.mkdtemp())
    (d / ".prismor").mkdir()
    if selection_empty:
        (d / ".prismor" / "policy.yaml").write_text(_render_selection_policy([]))
    with mock.patch("prismor.runtime.enterprise.workspace_scope.is_managed", return_value=False):
        return PolicyEngine(workspace=d)


@pytest.fixture(scope="module")
def floor():
    return _engine(True)


@pytest.fixture(scope="module")
def default():
    return _engine(False)


def _blocked_by(eng, event):
    findings = eng.evaluate(event, index=0)
    hit = should_block(findings, {**PRE, "type": event["type"]})
    return hit["ruleId"] if hit else None


PROTECTED_PATHS = [
    r"C:\ws\.claude\settings.json",
    r"C:\ws\.prismor\policy.yaml",
    r"C:\ws\.prismor\pause.json",
    r"C:\ws\.claude\hooks\hook-dispatch.py",
    r"C:\Users\u\.prismor\identity.json",
    r"C:\ws\.CLAUDE\Settings.JSON",
    r"C:\ws\.claude\settings.json:stream",
    r"C:\ws\.claude\settings.json::$DATA",
    "C:\\ws\\.claude\\settings.json ",
    r"C:\ws\.claude\settings.json.",
    r"\\?\C:\ws\.claude\settings.json",
    r"\\?\UNC\srv\share\ws\.claude\settings.json",
    r"\\srv\share\ws\.claude\settings.json",
    r"%USERPROFILE%\.claude\settings.json",
    r"$env:USERPROFILE\.claude\settings.json",
    r"~\.claude\settings.json",
]


@pytest.mark.parametrize("path", PROTECTED_PATHS)
def test_protected_file_writes_block_in_any_spelling(floor, path):
    rule = _blocked_by(floor, {"type": "file_write", "path": path})
    assert rule in _SELF_PROTECTION_RULE_IDS | {"agent-config-tampering-path"}, path


@pytest.mark.parametrize("path", [
    r"C:\ws\.env", "C:\\ws\\.env ", r"C:\ws\.env:x", r"C:\ws\.env::$DATA", r"C:\ws\.env.",
    r"C:\Users\u\.aws\credentials", r"C:\Users\u\.ssh\id_rsa", "C:\\Users\\u\\.ssh\\id_rsa ",
    r"%USERPROFILE%\.ssh\id_rsa", r"$env:USERPROFILE\.ssh\id_rsa", r"~\.ssh\id_rsa",
])
def test_secret_reads_match_in_any_spelling(default, path):
    posix = default.evaluate({"type": "file_read", "path": "/home/u/" + path.split("\\")[-1].strip(" .:$DATA")}, index=0)
    findings = default.evaluate({"type": "file_read", "path": path}, index=0)
    assert any(f["ruleId"] == "secret-access" for f in findings), path
    assert posix is not None


@pytest.mark.parametrize("path", [r"C:\ws\README.md", r"C:\ws\src\app.py", r"C:\Users\u\notes.txt"])
def test_ordinary_windows_paths_stay_quiet(floor, default, path):
    assert _blocked_by(floor, {"type": "file_write", "path": path}) is None
    assert not default.evaluate({"type": "file_read", "path": path}, index=0)


def test_canon_keeps_drive_and_dot_components():
    assert _winpath_canon(r"C:\a\..\b.\c ") == "C:/a/../b/c"
    assert _winpath_canon("") == ""


BLOCKED_SHELL = [
    r"Remove-Item .claude\settings.json",
    "Remove-Item .claude/settings.json",
    r"del .claude\settings.json",
    r"erase C:\ws\.claude\settings.json",
    r"Set-Content .prismor\policy.yaml x",
    r"echo x > .prismor\policy.yaml",
    r"echo x >> .claude\settings.json",
    r"Copy-Item evil.json .claude\settings.json",
    r"Remove-Item -Path .claude\settings.json -Force",
    r"Remove-Item -LiteralPath:.claude\settings.json",
    r"ri -Force .claude\settings.json",
    r"Remove-Item .claude\settings.json:stream",
    r"Remove-Item .claude\settings.json::$DATA",
    r"Remove-Item '.claude\settings.json'",
    r'"x" | Out-File .prismor\policy.yaml',
    r"Add-Content .prismor\policy.yaml x",
    r"Move-Item .claude\settings.json x",
    r"Rename-Item .claude\settings.json s.bak",
    r"New-Item -Force .claude\settings.json",
    r"Clear-Content .claude\settings.json",
    r"copy evil.json C:\ws\.claude\settings.json",
    r"Set-Content -Value x -Path .prismor\pause.json",
    r"del .prismor\identity.json",
    r"Remove-Item .claude\hooks\hook-dispatch.py",
    r"Remove-Item .codex\hooks.json",
]


@pytest.mark.parametrize("cmd", BLOCKED_SHELL)
def test_powershell_and_cmd_file_ops_on_protected_files_block(floor, cmd):
    assert _blocked_by(floor, {"type": "shell", "command": cmd}) in (
        _SELF_PROTECTION_RULE_IDS | {"agent-config-tampering-path"}
    ), cmd


@pytest.mark.parametrize("cmd", [
    r"Get-Content .claude\settings.json",
    r"type .prismor\policy.yaml",
    r"dir .claude",
    r"Get-ChildItem .claude\hooks",
    r"Set-Content notes.txt x",
    r"Remove-Item build\out.txt",
    r"del dist\app.exe",
    r"Copy-Item src\a.py src\b.py",
    r"echo hi > out.txt",
    r"cp x .claude/settings.json.bak",
])
def test_reading_and_unrelated_file_ops_are_not_self_protection_hits(floor, cmd):
    findings = floor.evaluate({"type": "shell", "command": cmd}, index=0)
    assert not [f for f in findings if f["ruleId"] in _SELF_PROTECTION_RULE_IDS], cmd
