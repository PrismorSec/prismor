"""Regressions for the 2026-11-14 cloak findings (H7, M2-M5, L2, L3).

Every secret here is a fake written to a tmp vault. Placeholders are built
in-process ("@@" + "SECRET:" + name + "@@") so no Bash hook resolves them.
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from prismor.runtime.cloaking.runtime import unwrap_decloak

HOOKS = Path(__file__).resolve().parent.parent / "prismor" / "runtime" / "cloaking" / "hooks"


def ph(name: str) -> str:
    return "@@" + "SECRET:" + name + "@@"


@pytest.fixture()
def vault(tmp_path, monkeypatch):
    v = tmp_path / "vault"
    v.mkdir()
    monkeypatch.setenv("PRISMOR_SECRETS_DIR", str(v))
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / "home"))

    def add(name, value):
        (v / name).write_text(value, encoding="utf-8")
        return value
    add.dir = v
    return add


def hook(script: str, payload: dict, cwd=None) -> dict | None:
    out = subprocess.run(["bash", str(HOOKS / script)], input=json.dumps(payload),
                         capture_output=True, text=True, cwd=cwd).stdout.strip()
    return json.loads(out) if out else None


def denied(res) -> bool:
    return bool(res) and res["hookSpecificOutput"].get("permissionDecision") == "deny"


# ── M3: the command can't close decloak.sh's wrapper ─────────────────────────

def _wrapped(cmd: str) -> str:
    res = hook("decloak.sh", {"tool_name": "Bash", "tool_input": {"command": cmd}})
    return res["hookSpecificOutput"]["updatedInput"]["command"]


def test_command_cannot_escape_the_scrub_pipe(vault, tmp_path):
    secret = vault("tok", "fake-TOKEN-0123456789abcdef")
    (tmp_path / "f").write_text(secret)
    cmd = "true\n}\ncat f; echo\n{ :"
    run = subprocess.run(["bash", "-c", _wrapped(cmd)], capture_output=True, text=True, cwd=tmp_path)
    assert secret not in run.stdout + run.stderr


@pytest.mark.parametrize("cmd,rc,out", [
    ("echo hi; exit 7", 7, "hi\n"),
    ("# only a comment", 0, ""),
    ("echo hi \\", 0, "hi\n"),          # trailing backslash continuation
    ("cat <<'EOF'\n$HOME\nEOF", 0, "$HOME\n"),
])
def test_wrapper_keeps_status_and_shape(vault, cmd, rc, out):
    vault("tok", "fake-TOKEN-0123456789abcdef")
    w = _wrapped(cmd)
    run = subprocess.run(["bash", "-c", w], capture_output=True, text=True)
    assert (run.returncode, run.stdout) == (rc, out)
    assert unwrap_decloak(w) == cmd   # rules still judge the agent's own command


# ── M4 / L3: decloak-exec.sh ─────────────────────────────────────────────────

def _exec(vault, cmd, cwd, **env):
    e = {**os.environ, "PRISMOR_SECRETS_DIR": str(vault.dir), "PRISMOR_CLOAK_CMD": cmd, **env}
    return subprocess.run(["bash", str(HOOKS / "decloak-exec.sh")], env=e, cwd=cwd,
                          capture_output=True, text=True)


def test_decloaked_value_is_not_exported_to_children(vault, tmp_path):
    vault("tok", "fake-TOKEN-0123456789abcdef")
    run = _exec(vault, f"printf '[%s]' {ph('tok')}; env | grep -c 'fake-TOK''EN-0123' || true", tmp_path)
    assert run.stdout == "[fake-TOKEN-0123456789abcdef]0\n"
    # mirror.py pre-binds the variable in the environment: un-exported too.
    run = _exec(vault, f"printf '[%s]' {ph('tok')}; env | grep -c 'fake-TOK''EN-0123' || true", tmp_path,
                _PRISMOR_SECRET_tok="fake-TOKEN-0123456789abcdef")
    assert run.stdout == "[fake-TOKEN-0123456789abcdef]0\n"


def test_env_assignment_still_reaches_its_command(vault, tmp_path):
    vault("tok", "fake-TOKEN-0123456789abcdef")
    run = _exec(vault, f"T={ph('tok')} bash -c 'printf %s \"$T\"'", tmp_path)
    assert run.stdout == "fake-TOKEN-0123456789abcdef"


EVIL = "$(touch pwned1)`touch pwned2`'; touch pwned3; '\nEOF\ntouch pwned4"


@pytest.mark.parametrize("cmd", [
    "echo x # cat <<'EOF'\nprintf %s {p}\n",          # L3: heredoc in a comment
    "# <<EOF\nprintf %s \"{p}\"\n",
    "cat <<'EOF'\n{p}\nEOF",                            # quoted heredoc: never inlined
    "cat <<'E\"OF'\n{p}\nEOF",                         # unsure delimiter
])
def test_heredoc_misreads_never_run_secret_content(vault, tmp_path, cmd):
    vault("evil", "$(touch pwned1)`touch pwned2`")   # no delimiter line: old code inlined it
    _exec(vault, cmd.format(p=ph("evil")), tmp_path)
    assert not list(tmp_path.glob("pwned*"))


def test_quoted_heredoc_body_is_verbatim(vault, tmp_path):
    vault("evil", EVIL)
    run = _exec(vault, f"cat <<'EOF'\nk={ph('evil')} $HOME `x` \\n\nEOF", tmp_path)
    assert run.stdout == f"k={EVIL} $HOME `x` \\n\n"


# ── L2: longest secret first ─────────────────────────────────────────────────

def test_scrub_stream_replaces_longest_first(vault):
    vault("a", "abcdefgh12")
    vault("b", "abcdefgh12345678XYZ")
    run = subprocess.run(["bash", str(HOOKS / "scrub-stream.sh")], input="v=abcdefgh12345678XYZ\n",
                         capture_output=True, text=True, env=os.environ)
    assert run.stdout == f"v={ph('b')}\n"


# ── M5: MCP recloak of secrets with JSON-special characters ─────────────────

@pytest.mark.parametrize("secret", ['pa"ss\\word-12345', "line1-abc\nline2-xyz9", "tab\there-0123456"])
def test_recloak_matches_json_special_secrets(vault, secret):
    vault("s", secret)
    response = {"content": [{"type": "text", "text": f"value={secret}"},
                            {"type": "text", "text": json.dumps({"k": secret})}]}
    res = hook("recloak-mcp.sh", {"tool_name": "mcp__x__y", "tool_response": response})
    out = res["hookSpecificOutput"]["updatedMCPToolOutput"]
    assert isinstance(out, dict)   # same shape back
    dumped = json.dumps(out)
    assert secret not in json.dumps(out, ensure_ascii=False) and json.dumps(secret)[1:-1] not in dumped
    assert out["content"][0]["text"] == f"value={ph('s')}"


def test_recloak_longest_first(vault):
    vault("a", "abcdefgh12")
    vault("b", "abcdefgh12345678XYZ")
    res = hook("recloak-mcp.sh", {"tool_name": "mcp__x__y", "tool_response": "v=abcdefgh12345678XYZ"})
    assert res["hookSpecificOutput"]["updatedMCPToolOutput"] == f"v={ph('b')}"


# ── H7: Grep / Edit built-ins ───────────────────────────────────────────────

def test_read_guard_covers_grep_content_and_edit(vault, tmp_path):
    secret = vault("tok", "fake-TOKEN-0123456789abcdef")
    src = tmp_path / "src"
    src.mkdir()
    (src / "config.py").write_text(f"TOKEN = '{secret}'\n")
    (src / "app.js").write_text("console.log(1)\n")
    g = lambda **ti: hook("read-guard.sh", {"tool_name": "Grep", "tool_input": {"pattern": "TOKEN", **ti}})  # noqa: E731
    assert denied(g(path=str(src), output_mode="content"))
    assert g(path=str(src)) is None                                   # files_with_matches
    assert g(path=str(src), output_mode="count") is None
    assert g(path=str(src), output_mode="content", glob="*.js") is None
    for tool in ("Edit", "MultiEdit"):
        assert denied(hook("read-guard.sh", {"tool_name": tool, "tool_input": {"file_path": str(src / "config.py")}}))
        assert hook("read-guard.sh", {"tool_name": tool, "tool_input": {"file_path": str(src / "app.js")}}) is None


def test_env_guard_covers_grep_content(vault, tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / ".env").write_text("API_KEY=fake-unimported-0123456789\n")
    (ws / "a.py").write_text("x = 1\n")
    g = lambda **ti: hook("env-guard.sh", {"tool_name": "Grep", "cwd": str(ws), "tool_input": {"pattern": "K", **ti}})  # noqa: E731
    assert denied(g(output_mode="content"))
    assert denied(g(output_mode="content", path=str(ws / ".env")))
    assert g() is None
    assert g(output_mode="content", glob="*.py") is None
    assert g(output_mode="content", type="py") is None


def test_installer_matchers_cover_grep_and_replace_old_ones(tmp_path, monkeypatch):
    from prismor.runtime.cloaking import installer
    monkeypatch.setenv("HOME", str(tmp_path))
    cfg = tmp_path / ".claude" / "settings.json"
    cfg.parent.mkdir()
    old = {"hooks": {"PreToolUse": [
        {"matcher": "Read", "hooks": [installer._hook_entry(installer._READ_GUARD)]},
        {"matcher": "Read|Bash", "hooks": [installer._hook_entry(installer._ENV_GUARD)]}]}}
    cfg.write_text(json.dumps(old))
    installer.install(workspace=tmp_path, scope="project")
    pre = json.loads(cfg.read_text())["hooks"]["PreToolUse"]
    by = {e["matcher"]: e for e in pre}
    assert "Read" not in by and "Read|Bash" not in by
    assert "read-guard.sh" in json.dumps(by["Read|Grep|Edit|MultiEdit"])
    assert "env-guard.sh" in json.dumps(by["Read|Bash|Grep"])


# ── M2: env-guard tokenizes instead of matching reader names ─────────────────

@pytest.fixture()
def envws(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_SECRETS_DIR", str(tmp_path / "vault"))
    (tmp_path / "vault").mkdir()
    ws = tmp_path / "ws"
    (ws / "src").mkdir(parents=True)
    (ws / "sub").mkdir()
    line = "API_KEY=fake-unimported-0123456789\n"
    (ws / ".env").write_text(line)
    (ws / ".envrc").write_text("export " + line)
    (ws / "sub" / ".env").write_text(line)
    (ws / "README.md").write_text("# hi\n")
    (ws / "src" / "a.py").write_text("foo = 1\n")
    os.symlink(ws / ".env", ws / "notes")
    clean = tmp_path / "clean"           # no .env itself; holds sub/.env
    (clean / "sub").mkdir(parents=True)
    (clean / "sub" / ".env").write_text(line)
    return ws, clean


def _bash(cmd, cwd):
    return hook("env-guard.sh", {"tool_name": "Bash", "cwd": str(cwd), "tool_input": {"command": cmd}})


BYPASSES = [
    "cat${IFS}.env", "cat$IFS.env", '"cat" .env', "\\cat .env", 'c""at .env', "/bin/cat .env",
    ". ./.env", "source .env", "bash -x .env", "sh .env", "dd if=.env", "jq -R . .env",
    "awk 1 .env", "base64 .env", "cp .env /tmp/x", "cat .en?", "cat .e*", "cat .env*",
    "F=.env; cat $F", 'cat "$F"', "cat notes", "cat .envrc", "echo .env | xargs cat",
    'echo "$(cat .env)"', "echo `cat .env`", "ls\ncat .env", "ls # c\ncat .env",
    "grep -r API_KEY .", "git diff .env", "cat < .env", "sudo cat .env", "env cat .env",
]
CD_BYPASSES = [
    "{ cd sub; cat .env; }", "if cd sub; then cat .env; fi", "command cd sub && cat .env",
    "X=1 cd sub && cat .env", "true && cd sub && cat .env", "cd sub\ncat .env",
]
CONTROLS = [
    "cat README.md", "ls -la", "grep foo src/", "ls -la .env", "test -f .env && echo yes",
    "[ -f .env ] && echo yes", "grep -q '^API_KEY=' .env", "grep -c API_KEY .env",
    "echo 'K=V' >> .env", "printf 'K=V\\n' >> .env", "prismor cloak add --env-file .env",
    "wc -l < .env", "git status", "git add .env", "find . -name .env", "echo $HOME",
    "rm -f .env.bak", "stat .env", "cat README.md | head -1", "grep -rn '.env' src/",
]


@pytest.mark.parametrize("cmd", BYPASSES)
def test_env_guard_bypasses_are_denied(envws, cmd):
    ws, _ = envws
    assert denied(_bash(cmd, ws)), cmd


@pytest.mark.parametrize("cmd", CD_BYPASSES)
def test_env_guard_cd_anywhere_is_followed(envws, cmd):
    _, clean = envws
    assert denied(_bash(cmd, clean)), cmd


def test_env_guard_read_follows_symlinks(envws):
    ws, _ = envws
    res = hook("env-guard.sh", {"tool_name": "Read", "cwd": str(ws), "tool_input": {"file_path": str(ws / "notes")}})
    assert denied(res)


@pytest.mark.parametrize("cmd", CONTROLS)
def test_env_guard_controls_pass(envws, cmd):
    ws, _ = envws
    assert _bash(cmd, ws) is None, cmd
