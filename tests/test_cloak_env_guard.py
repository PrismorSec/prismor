"""Tests for env-guard.sh — the unimported-.env bootstrap guard.

read-guard.sh and the decloak output scrub only protect values already in the
vault, so the first `cat .env` / Read(.env) in a fresh workspace leaks every
secret before any placeholder exists. env-guard.sh denies content access to a
dotenv-style file while it holds unimported values, points the model at
`prismor cloak add --env-file`, and stands down once every entry is imported.
These tests exercise both the Read and Bash decision paths in isolation.

Run:  python3 tests/test_cloak_env_guard.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO))

_HOME = Path(tempfile.mkdtemp(prefix="prismor-test-"))
_SECRETS = _HOME / "secrets"
_SECRETS.mkdir(parents=True)
os.environ["PRISMOR_HOME"] = str(_HOME)
os.environ["PRISMOR_SECRETS_DIR"] = str(_SECRETS)

_GUARD = _REPO / "prismor" / "runtime" / "cloaking" / "hooks" / "env-guard.sh"

_API_KEY = "sk-live-CANARY-0123456789abcdef0123456789abcdef"
_DB_PASS = "hunter2-not-really-a-password"

_WS = _HOME / "ws"
_WS.mkdir()
(_WS / ".env").write_text(
    f"API_KEY={_API_KEY}\n"
    f'DB_PASSWORD="{_DB_PASS}"\n'
    "DEBUG=1\n"                       # < MIN_VALUE_LEN — never counted
)
(_WS / ".env.example").write_text("API_KEY=your-key-here\nDB_PASSWORD=changeme\n")
(_WS / "prod.env").write_text(f"TOKEN={_API_KEY}\n")
(_WS / "notes.txt").write_text("harmless notes\n")

_passed = 0
_failed = 0


def check(name: str, ok: bool, detail: str = "") -> None:
    global _passed, _failed
    if ok:
        _passed += 1
        print(f"  PASS  {name}")
    else:
        _failed += 1
        print(f"  FAIL  {name}  {detail}")


def run(payload: dict) -> dict | None:
    proc = subprocess.run(["bash", str(_GUARD)], input=json.dumps(payload),
                          capture_output=True, text=True, env=os.environ)
    out = proc.stdout.strip()
    return json.loads(out) if out else None


def read_call(file_path: str) -> dict | None:
    return run({"tool_name": "Read", "tool_input": {"file_path": file_path},
                "cwd": str(_WS)})


def bash_call(command: str) -> dict | None:
    return run({"tool_name": "Bash", "tool_input": {"command": command},
                "cwd": str(_WS)})


def denied(res) -> bool:
    return bool(res) and (
        res.get("hookSpecificOutput", {}).get("permissionDecision") == "deny"
    )


def reason(res) -> str:
    return (res or {}).get("hookSpecificOutput", {}).get(
        "permissionDecisionReason", "")


def _clear_vault() -> None:
    for child in _SECRETS.iterdir():
        child.unlink()


# ── Read path ───────────────────────────────────────────────────────────────

def test_read_unimported_env_denied():
    res = read_call(str(_WS / ".env"))
    check("Read of unimported .env is denied",
          denied(res) and "cloak add --env-file" in reason(res), str(res))
    check("deny reason names the unimported keys, not values",
          "API_KEY" in reason(res) and _API_KEY not in reason(res), str(res))


def test_read_example_env_allowed():
    res = read_call(str(_WS / ".env.example"))
    check("Read of .env.example is allowed", res is None, str(res))


def test_read_plain_file_allowed():
    res = read_call(str(_WS / "notes.txt"))
    check("Read of a non-env file is allowed", res is None, str(res))


def test_read_suffixed_env_denied():
    res = read_call(str(_WS / "prod.env"))
    check("Read of unimported prod.env is denied", denied(res), str(res))


# ── Bash path ───────────────────────────────────────────────────────────────

def test_bash_cat_env_denied():
    res = bash_call("cat .env")
    check("`cat .env` is denied",
          denied(res) and "cloak add --env-file" in reason(res), str(res))


def test_bash_sed_env_denied():
    res = bash_call("sed -n 1p .env")
    check("`sed -n 1p .env` is denied", denied(res), str(res))


def test_bash_grep_content_denied():
    res = bash_call("grep API_KEY .env")
    check("content `grep API_KEY .env` is denied", denied(res), str(res))


def test_bash_redirect_read_denied():
    res = bash_call("while read -r l; do :; done < .env")
    check("`< .env` input redirection is denied", denied(res), str(res))


def test_bash_presence_grep_allowed():
    res = bash_call("grep -q '^API_KEY=' .env")
    check("presence check `grep -q` is allowed", res is None, str(res))


def test_bash_append_allowed():
    res = bash_call("echo 'NEW_KEY=@@SECRET:NEW_KEY@@' >> .env")
    check("append-only write to .env is allowed", res is None, str(res))


def test_bash_ingest_command_allowed():
    res = bash_call("prismor cloak add --env-file .env")
    check("`prismor cloak add --env-file` is allowed", res is None, str(res))


def test_bash_path_invoked_ingest_allowed():
    for cmd in (
        "/venv/bin/prismer cloak add --env-file .env",
        "/Users/x/.local/pipx/venvs/prismer/bin/prismer cloak add --env-file .env",
        "~/.local/bin/prismer cloak list",
        "./venv/bin/prismer cloak add --env-file .env",
    ):
        res = bash_call(cmd)
        check(f"path-invoked `{cmd}` is allowed", res is None, str(res))


def test_bash_unrelated_command_allowed():
    res = bash_call("cat notes.txt")
    check("`cat notes.txt` is allowed", res is None, str(res))


def test_bash_absolute_path_denied():
    res = bash_call(f"cat {_WS}/.env")
    check("absolute-path `cat` of unimported .env is denied", denied(res), str(res))


def test_bash_prismer_mention_negative_denied():
    for cmd in (
        f"echo prismer cloaking is nice; cat {_WS}/.env",
        f"/bin/cat {_WS}/.env",
    ):
        res = bash_call(cmd)
        check(f"non-exempt read denied: `{cmd}`", denied(res), str(res))


# ── stand-down after import ─────────────────────────────────────────────────

def test_stands_down_once_imported():
    from prismor.runtime.cloaking.secrets_store import add_env_secrets
    # Reset the fixture — the append test above added a placeholder line.
    (_WS / ".env").write_text(
        f"API_KEY={_API_KEY}\n"
        f'DB_PASSWORD="{_DB_PASS}"\n'
        "DEBUG=1\n"
    )
    created = add_env_secrets(_WS / ".env")
    check("importer registers the two long values",
          {e["name"] for e in created} >= {"API_KEY", "DB_PASSWORD"}, str(created))
    res = read_call(str(_WS / ".env"))
    check("Read of fully imported .env passes env-guard", res is None, str(res))
    res = bash_call("cat .env")
    check("`cat .env` of fully imported file passes env-guard", res is None, str(res))
    # prod.env shares API_KEY's value but TOKEN is the same value → imported too.
    res = bash_call("cat prod.env")
    check("file whose values are all vaulted passes env-guard", res is None, str(res))
    _clear_vault()
    res = bash_call("cat .env")
    check("guard re-arms when the vault is cleared", denied(res), str(res))


def main() -> int:
    for fn in [
        test_read_unimported_env_denied,
        test_read_example_env_allowed,
        test_read_plain_file_allowed,
        test_read_suffixed_env_denied,
        test_bash_cat_env_denied,
        test_bash_sed_env_denied,
        test_bash_grep_content_denied,
        test_bash_redirect_read_denied,
        test_bash_presence_grep_allowed,
        test_bash_append_allowed,
        test_bash_ingest_command_allowed,
        test_bash_path_invoked_ingest_allowed,
        test_bash_unrelated_command_allowed,
        test_bash_absolute_path_denied,
        test_bash_prismer_mention_negative_denied,
        test_stands_down_once_imported,
    ]:
        fn()
    print(f"\n{_passed} passed, {_failed} failed")
    return 1 if _failed else 0


if __name__ == "__main__":
    sys.exit(main())
