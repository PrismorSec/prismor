"""Tests for the cloaking output-scrub layer.

Covers the leak path where a secret enters context without ever passing
through an ``@@SECRET@@`` placeholder:

  A. scrub-stream.sh — masks registered secret values on a stdin stream.
  B. decloak.sh      — wraps *every* Bash command so its output is scrubbed,
                       not only commands that reference a placeholder; still
                       substitutes placeholders and preserves exit codes.
  C. read-guard.sh   — denies a Read of a file that holds a registered secret.

Each test runs against an isolated $PRISMOR_HOME so the developer's real vault
is never touched. Run:  python3 tests/test_cloak_output_scrub.py
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

_HOOKS = _REPO / "prismor" / "runtime" / "cloaking" / "hooks"
_DECLOAK = _HOOKS / "decloak.sh"
_SCRUB = _HOOKS / "scrub-stream.sh"
_READ_GUARD = _HOOKS / "read-guard.sh"

# A high-entropy canary registered as a secret named CANARY.
_CANARY = "sk-live-CANARY-0123456789abcdef0123456789abcdef"
(_SECRETS / "CANARY").write_text(_CANARY)
_PLACEHOLDER = "@@SECRET:CANARY@@"

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


def run_hook(script: Path, payload: dict) -> dict | None:
    proc = subprocess.run(
        ["bash", str(script)],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        env={**os.environ, "PRISMOR_HOME": str(_HOME), "PRISMOR_SECRETS_DIR": str(_SECRETS)},
    )
    out = proc.stdout.strip()
    return json.loads(out) if out else None


def run_scrub(stdin_text: str) -> str:
    proc = subprocess.run(
        ["bash", str(_SCRUB)],
        input=stdin_text,
        capture_output=True,
        text=True,
        env={**os.environ, "PRISMOR_HOME": str(_HOME), "PRISMOR_SECRETS_DIR": str(_SECRETS)},
    )
    return proc.stdout


def bash_payload(command: str) -> dict:
    return {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "session_id": "test",
    }


def execute_wrapped(command: str) -> tuple[str, int]:
    """Run a command through decloak's wrapper and return (output, exit_code),
    exactly as Claude Code would after applying updatedInput."""
    res = run_hook(_DECLOAK, bash_payload(command))
    wrapped = res["hookSpecificOutput"]["updatedInput"]["command"] if res else command
    proc = subprocess.run(["bash", "-c", wrapped], capture_output=True, text=True, env=os.environ)
    return proc.stdout, proc.returncode


# ── A. scrub-stream.sh ────────────────────────────────────────────────────
def test_scrub_masks_secret():
    out = run_scrub(f"the key is {_CANARY} ok\n")
    check("scrub masks a registered secret value",
          _CANARY not in out and _PLACEHOLDER in out, out.strip())


def test_scrub_passthrough_no_secret():
    out = run_scrub("nothing sensitive here\n")
    check("scrub leaves non-secret text unchanged", out == "nothing sensitive here\n", out)


def test_scrub_secret_with_regex_metacharacters():
    # Regression: a secret containing regex metacharacters ([](){}.*+?^$|) used
    # to be interpolated into a `sed -E` pattern, which aborted with
    # "unterminated substitute pattern" (dropping ALL output) or silently
    # mangled the text. Literal substring replacement must handle it exactly.
    meta = "sk_live_9f8[a|b](c).d*+?e^$again"
    (_SECRETS / "META").write_text(meta)
    try:
        out = run_scrub(f"before {meta} after\n")
        check(
            "scrub masks a secret full of regex metacharacters",
            out == "before @@SECRET:META@@ after\n",
            repr(out),
        )
    finally:
        (_SECRETS / "META").unlink()


def test_scrub_preserves_trailing_and_missing_newline():
    # The output must be byte-exact: no added or stripped trailing newline.
    check(
        "scrub preserves a missing trailing newline",
        run_scrub("plain text no newline") == "plain text no newline",
        "trailing newline was altered",
    )


# ── B. decloak.sh output scrubbing (no placeholder) ───────────────────────
def test_grep_output_scrubbed():
    # Model reads the secret out of a file via grep — never uses a placeholder.
    env_file = _HOME / "app.env"
    env_file.write_text(f"CANARY_API_KEY={_CANARY}\n")
    out, _ = execute_wrapped(f"grep CANARY {env_file}")
    check("grep output is scrubbed (no placeholder used)",
          _CANARY not in out and _PLACEHOLDER in out, out.strip())


def test_source_echo_scrubbed():
    env_file = _HOME / "creds.env"
    env_file.write_text(f"CANARY_API_KEY={_CANARY}\n")
    out, _ = execute_wrapped(f'set -a; . {env_file}; set +a; echo "$CANARY_API_KEY"')
    check("sourced env var echo is scrubbed",
          _CANARY not in out and _PLACEHOLDER in out, out.strip())


def test_no_secret_in_wrapped_command():
    # The wrapped command string must never contain the raw secret value —
    # it would otherwise land in the transcript via tool_input.command.
    env_file = _HOME / "app2.env"
    env_file.write_text(f"K={_CANARY}\n")
    res = run_hook(_DECLOAK, bash_payload(f"cat {env_file}"))
    wrapped = res["hookSpecificOutput"]["updatedInput"]["command"]
    check("wrapped command contains no raw secret", _CANARY not in wrapped, wrapped)


def test_exit_code_preserved():
    _, code_true = execute_wrapped("true")
    _, code_false = execute_wrapped("bash -c 'exit 7'")
    check("exit code preserved through the scrub pipe", code_true == 0 and code_false == 7,
          f"true={code_true} false={code_false}")


def test_command_with_trailing_comment():
    # Regression (#381): commands ending in an inline comment (# ...) used to
    # swallow the trailing '; }' on a single-line brace group, causing EOF syntax errors.
    out, code = execute_wrapped("echo hello # build step")
    check("command with trailing comment executes cleanly", code == 0 and "hello" in out,
          f"code={code} out={out.strip()}")


def test_command_with_heredoc():
    # Regression (#381): commands ending in a heredoc delimiter (EOF) used to have
    # '; }' appended to the delimiter line, preventing bash from recognizing the end of heredoc.
    heredoc_cmd = "cat << 'EOF'\nheredoc line\nEOF"
    out, code = execute_wrapped(heredoc_cmd)
    check("command ending with heredoc executes cleanly", code == 0 and "heredoc line" in out,
          f"code={code} out={out.strip()}")


# ── B'. decloak.sh placeholder substitution still works ───────────────────
def test_placeholder_substituted_and_output_scrubbed():
    out, _ = execute_wrapped(f'echo "using {_PLACEHOLDER}"')
    check("placeholder use runs with real value but output is re-masked",
          _CANARY not in out and _PLACEHOLDER in out, out.strip())


def test_leading_env_assignment_decloaked_and_scrubbed():
    out, code = execute_wrapped(
        f"OPENAI_API_KEY={_PLACEHOLDER} python3 -c 'import os; print(os.environ[\"OPENAI_API_KEY\"])'"
    )
    check(
        "leading env assignment is decloaked and output is re-masked",
        code == 0 and _CANARY not in out and _PLACEHOLDER in out,
        out.strip(),
    )


def test_unregistered_placeholder_denied():
    res = run_hook(_DECLOAK, bash_payload("echo @@SECRET:NOPE@@"))
    dec = (res or {}).get("hookSpecificOutput", {}).get("permissionDecision")
    check("unknown placeholder is denied (fail closed)", dec == "deny", str(res))


def test_escaped_placeholder_not_substituted():
    # The escaped form @@SECRET\:CANARY@@ must be skipped by the placeholder
    # regex and pass through verbatim — never substituted with the real value,
    # even though CANARY is registered. This is how docs/commit messages write
    # the literal syntax without tripping the guard.
    res = run_hook(_DECLOAK, bash_payload('echo "@@SECRET\\:CANARY@@"'))
    dec = (res or {}).get("hookSpecificOutput", {}).get("permissionDecision")
    wrapped = (res or {}).get("hookSpecificOutput", {}).get("updatedInput", {}).get("command", "")
    check("escaped placeholder is not substituted",
          dec != "deny" and "@@SECRET\\:CANARY@@" in wrapped and _CANARY not in wrapped,
          str(res))


def test_escaped_unregistered_placeholder_not_denied():
    # An escaped name that is not registered must NOT be denied: the escape
    # signals "literal text", not "resolve this secret".
    res = run_hook(_DECLOAK, bash_payload('echo "@@SECRET\\:NOPE@@"'))
    dec = (res or {}).get("hookSpecificOutput", {}).get("permissionDecision")
    wrapped = (res or {}).get("hookSpecificOutput", {}).get("updatedInput", {}).get("command", "")
    check("escaped unregistered placeholder is not denied",
          dec != "deny" and "@@SECRET\\:NOPE@@" in wrapped,
          str(res))


# ── C. read-guard.sh ──────────────────────────────────────────────────────
def read_payload(fp: str) -> dict:
    return {"hook_event_name": "PreToolUse", "tool_name": "Read",
            "tool_input": {"file_path": fp}, "session_id": "test"}


def test_read_of_secret_file_denied():
    secret_file = _HOME / "prod.env"
    secret_file.write_text(f"CANARY_API_KEY={_CANARY}\n")
    res = run_hook(_READ_GUARD, read_payload(str(secret_file)))
    dec = (res or {}).get("hookSpecificOutput", {}).get("permissionDecision")
    check("Read of a secret-bearing file is denied", dec == "deny", str(res))


def test_read_of_clean_file_allowed():
    clean = _HOME / "readme.txt"
    clean.write_text("no secrets here\n")
    res = run_hook(_READ_GUARD, read_payload(str(clean)))
    check("Read of a clean file is allowed (no-op)", res is None, str(res))


def test_no_secret_in_wrapped_command_when_placeholder_used():
    # Regression (transcript leak): when a command references a placeholder,
    # decloak.sh used to substitute the REAL value into the command string it
    # handed back — and Claude Code records that string verbatim in
    # ~/.claude/projects/*.jsonl. The value never reached the model but did
    # reach disk. The wrapped command must now carry the placeholder, with
    # resolution deferred to the child (decloak-exec.sh).
    res = run_hook(_DECLOAK, bash_payload(f"echo using {_PLACEHOLDER}"))
    wrapped = res["hookSpecificOutput"]["updatedInput"]["command"]
    check("placeholder command: wrapped string holds no raw secret",
          _CANARY not in wrapped and _PLACEHOLDER in wrapped, wrapped)


def main() -> int:
    for fn in [
        test_scrub_masks_secret, test_scrub_passthrough_no_secret,
        test_scrub_secret_with_regex_metacharacters,
        test_scrub_preserves_trailing_and_missing_newline,
        test_grep_output_scrubbed, test_source_echo_scrubbed,
        test_no_secret_in_wrapped_command, test_exit_code_preserved,
        test_command_with_trailing_comment, test_command_with_heredoc,
        test_placeholder_substituted_and_output_scrubbed,
        test_no_secret_in_wrapped_command_when_placeholder_used,
        test_leading_env_assignment_decloaked_and_scrubbed,
        test_unregistered_placeholder_denied,
        test_escaped_placeholder_not_substituted,
        test_escaped_unregistered_placeholder_not_denied,
        test_read_of_secret_file_denied, test_read_of_clean_file_allowed,
    ]:
        fn()
    print(f"\n{_passed} passed, {_failed} failed")
    return 1 if _failed else 0


if __name__ == "__main__":
    sys.exit(main())
