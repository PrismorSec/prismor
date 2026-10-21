"""recursive-delete-home covers PowerShell and cmd.exe, not just rm -rf."""
import re
from pathlib import Path

import pytest
import yaml

_RULE = next(r for r in yaml.safe_load(
    (Path(__file__).resolve().parent.parent / "prismor/runtime/default_policy.yaml").read_text())["rules"]
    if r["id"] == "recursive-delete-home")


def _hit(cmd: str) -> bool:
    return any(re.search(p, cmd, re.I) for p in _RULE["patterns"])


@pytest.mark.parametrize("cmd", [
    r"Remove-Item -Recurse -Force $HOME\canary",
    r"Remove-Item C:\Users\dev\Documents -Recurse",
    r"rm -r -fo ~\projects",
    r"ri -r $env:USERPROFILE\Desktop",
    r'Remove-Item -Path "C:\Users\dev\work" -Recurse -Force',
    r'powershell -c "Remove-Item -Recurse -Force $HOME\canary"',
    r"cmd /c rmdir /s /q C:\Users\dev\canary",
    r"rd /s /q %USERPROFILE%\Documents",
    r"del /s /q C:\Users\dev\Documents\*",
    "rm -rf ~/canary",
])
def test_flags(cmd):
    assert _hit(cmd)


@pytest.mark.parametrize("cmd", [
    r"Remove-Item C:\Users\dev\canary\file.txt",
    r"Remove-Item -Recurse -Force C:\Users\dev\proj\node_modules",
    r"Remove-Item -Recurse $env:TEMP\x",
    r"Remove-Item -Recurse C:\Users\dev\AppData\Local\Temp\x",
    r"rmdir C:\Users\dev\empty",
    r"Remove-Item -Recurse .\build",
    r"del C:\Users\dev\a.txt",
    r"Remove-Item -Recurse -Force C:\work\build\out",
])
def test_leaves_alone(cmd):
    assert not _hit(cmd)
