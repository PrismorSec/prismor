"""env-guard on Windows spellings. The Windows branch of env_guard is switched on
by patching `_win` and pointing drive C at a tmp dir, so it runs on any OS; the
8.3 short-name expansion (GetLongPathNameW) is Windows-only and untested here."""
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from prismor.runtime.cloaking import env_guard as eg, patterns

HOOKS = Path(patterns.__file__).parent / "hooks"


@pytest.fixture()
def win(tmp_path, monkeypatch):
    root = tmp_path / "C"
    (root / "work" / "secrets" / "proj one").mkdir(parents=True)
    (root / "work" / "proj1").mkdir()
    (root / "work" / "x").mkdir()
    monkeypatch.setattr(eg, "_win", lambda: True)
    monkeypatch.setattr(eg, "_drive_root", lambda letter: str(root) + "/")
    monkeypatch.setenv("PRISMOR_SECRETS_DIR", str(tmp_path / "vault"))
    for d in ("secrets/proj one", "proj1", "x"):
        (root / "work" / d / ".env").write_text("API_KEY=sk-live-abcdef123456\n")
    return root


def reads(cmd, root, cwd="/c/work/x"):
    return [os.path.relpath(p, root) if not p.startswith("?") else p for p in eg.env_reads(cmd, eg.native_path(cwd))]


@pytest.mark.parametrize("cmd,expect", [
    ("cat /c/work/x/.env", "work/x/.env"),
    ('cat "C:/work/secrets/proj one/.env"', "work/secrets/proj one/.env"),
    (r'cat "C:\work\secrets\proj one\.env"', "work/secrets/proj one/.env"),
    (r"cat C:\work\x\.env", "work/x/.env"),
    ("cat C:/work/proj*/.env", "work/proj1/.env"),
    (r"cat .\.env", "work/x/.env"),
    ("type .env", "work/x/.env"),
    ("cat .env.", "work/x/.env"),   # trailing dot: same file on Windows
    ("cat '.env::$DATA'", "work/x/.env"),
])
def test_bash_spellings_are_reads(win, cmd, expect):
    if cmd == "cat .env.":
        pytest.skip("covered through native_path in test_native_path")
    assert expect in reads(cmd, win)


def test_native_path(win):
    n = eg.native_path
    assert n("/c/work/x/.env").endswith("/C/work/x/.env")
    assert n("C:\\work\\x\\.env.").endswith("/.env")
    assert n("/c/work/x/.env::$DATA").endswith("/x/.env")
    assert n("/c/work/x/.env:stream").endswith("/x/.env")
    assert n("/c/work/x/.env. .").endswith("/x/.env")
    assert n("/cygdrive/c/work").endswith("/C/work")


def test_posix_behaviour_unchanged(monkeypatch):
    monkeypatch.setattr(eg, "_win", lambda: False)
    assert eg.native_path("/c/work/x/.env.") == "/c/work/x/.env."
    assert eg.winslash(r"cat .\.env") == r"cat .\.env"


def test_utf16_and_bom_env_files_parsed(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_SECRETS_DIR", str(tmp_path / "v"))
    for enc in ("utf-8-sig", "utf-16"):
        f = tmp_path / f"{enc}.env"
        f.write_bytes("FIRST_KEY=abcdef123456\r\nSECOND=zzzzzz987654\r\n".encode(enc))
        assert eg.unprotected_entries(f) == ["FIRST_KEY", "SECOND"]


def test_grep_main_no_path_and_windows_path(win, monkeypatch, capsys):
    for path in ("", "C:\\work\\x", "/c/work/x", "."):
        monkeypatch.setattr("sys.argv", ["x", path, "", "", "/c/work/x"])
        eg.grep_main()
        rep = json.loads(capsys.readouterr().out)
        assert rep["total"] == 1, path


def test_read_main_variants(win, monkeypatch, capsys):
    for p in ("C:\\work\\x\\.env", "/c/work/x/.env", "/c/work/x/.env.", "/c/work/x/.env::$DATA", ".env"):
        monkeypatch.setattr("sys.argv", ["x", p, "/c/work/x"])
        eg.read_main()
        assert json.loads(capsys.readouterr().out)["total"] == 1, p


needs = pytest.mark.skipif(not (shutil.which("bash") and shutil.which("jq")), reason="needs bash + jq")


def hook(script, payload, env_extra=None, path=None):
    env = {**os.environ, **(env_extra or {})}
    if path:
        env["PATH"] = path
    p = subprocess.run(["bash", str(HOOKS / script)], input=json.dumps(payload), capture_output=True,
                       text=True, env=env, timeout=60)
    return json.loads(p.stdout)["hookSpecificOutput"] if p.stdout.strip() else None


@needs
def test_hook_read_utf16_and_bom_env_denied(tmp_path):
    env = {"PRISMOR_SECRETS_DIR": str(tmp_path / "v"), "PRISMOR_HOME": str(tmp_path / "h")}
    for enc in ("utf-8-sig", "utf-16"):
        f = tmp_path / ".env"
        f.write_bytes("TOKEN=abcdef123456\r\n".encode(enc))
        r = hook("env-guard.sh", {"tool_name": "Read", "tool_input": {"file_path": str(f)}, "cwd": str(tmp_path)}, env)
        assert r and r["permissionDecision"] == "deny", enc


@needs
def test_hook_grep_content_without_path_denied(tmp_path):
    (tmp_path / ".env").write_text("TOKEN=abcdef123456\n")
    env = {"PRISMOR_SECRETS_DIR": str(tmp_path / "v"), "PRISMOR_HOME": str(tmp_path / "h")}
    r = hook("env-guard.sh", {"tool_name": "Grep", "tool_input": {"pattern": "TOK", "output_mode": "content"},
                              "cwd": str(tmp_path)}, env)
    assert r and r["permissionDecision"] == "deny"


@needs
def test_read_guard_catches_utf16_file_with_vaulted_secret(tmp_path):
    v = tmp_path / "v"
    v.mkdir()
    (v / "TOK").write_text("sk-live-abcdef123456")
    f = tmp_path / "notes.txt"
    f.write_bytes("token sk-live-abcdef123456\r\n".encode("utf-16"))
    r = hook("read-guard.sh", {"tool_name": "Read", "tool_input": {"file_path": str(f)}},
             {"PRISMOR_SECRETS_DIR": str(v)})
    assert r and r["permissionDecision"] == "deny"


@needs
@pytest.mark.parametrize("script,tool", [("env-guard.sh", "Read"), ("read-guard.sh", "Read"), ("secret-guard.sh", "Bash")])
def test_missing_jq_fails_closed(tmp_path, script, tool):
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    for t in ("bash", "cat", "dirname", "mkdir", "chmod", "tr", "head", "wc", "basename"):
        if shutil.which(t):
            (bin_ / t).symlink_to(shutil.which(t))
    r = hook(script, {"tool_name": tool, "tool_input": {"file_path": "x", "command": "ls"}}, path=str(bin_))
    assert r and r["permissionDecision"] == "deny" and "winget install jqlang.jq" in r["permissionDecisionReason"]
