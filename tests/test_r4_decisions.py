"""End-to-end tests for R4 authorization verdicts at the hook-dispatch boundary.

Phase 1 extends the binary allow/block emission into four honored outcomes on
the Claude surface:

    ALLOW    — no enforce finding (not exercised here; covered elsewhere)
    DENY     — action: block            → SystemExit(2)
    STEP_UP  — action: step_up          → hookSpecificOutput.permissionDecision "ask"
    MODIFY   — action: modify+transform → hookSpecificOutput.updatedInput

Plus the fail-closed rule: STEP_UP / MODIFY on a surface that can't honor them
degrades to DENY, never to ALLOW.

Each test drives the real CLI (`prismor hook-dispatch`) as a subprocess against
an isolated $PRISMOR_HOME and a temp workspace whose project policy adds rules
using the new actions. Run:  python3 tests/test_r4_decisions.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent

_POLICY = """
rules:
  - id: r4-stepup
    severity: HIGH
    category: test_r4
    title: Step-up required for the step-up marker
    event_types: [shell]
    fields: [command]
    mode: enforce
    action: step_up
    patterns:
      - "R4_STEPUP_MARKER"
  - id: r4-modify
    severity: HIGH
    category: test_r4
    title: Modify (sandbox) the modify marker
    event_types: [shell]
    fields: [command]
    mode: enforce
    action: modify
    transform: sandbox
    patterns:
      - "R4_MODIFY_MARKER"
  - id: r4-deny
    severity: HIGH
    category: test_r4
    title: Deny the deny marker
    event_types: [shell]
    fields: [command]
    mode: enforce
    action: block
    patterns:
      - "R4_DENY_MARKER"
"""


def _payload(agent: str, command: str) -> dict:
    """Build a pre-action shell payload in the shape each agent's hook sends."""
    if agent == "antigravity":
        return {"toolCall": {"name": "run_command", "args": {"CommandLine": command}},
                "conversationId": "r4-test-session"}
    if agent == "copilot":
        return {
            "hookEventName": "PreToolUse",
            "toolName": "Bash",
            "toolArgs": json.dumps({"command": command}),
            "session_id": "r4-test-session",
        }
    if agent == "cursor":
        return {
            "hookEventName": "beforeShellExecution",
            "command": command,
            "session_id": "r4-test-session",
        }
    # claude (and any Claude-shaped surface)
    return {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "session_id": "r4-test-session",
    }


def _dispatch(agent: str, command: str, workspace: Path, home: Path):
    """Invoke `hook-dispatch` with a pre-action Bash payload; return the proc."""
    payload = _payload(agent, command)
    env = dict(os.environ)
    env["PRISMOR_HOME"] = str(home)
    env["PRISMOR_SECRETS_DIR"] = str(home / "secrets")
    env["PYTHONPATH"] = str(_REPO)
    return subprocess.run(
        [
            sys.executable, "-m", "prismor.runtime.immunity_cli", "hook-dispatch",
            "--agent", agent, "--workspace", str(workspace), "--mode", "enforce",
        ],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        env=env,
    )


class R4Decisions(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp(prefix="prismor-r4-home-"))
        self.ws = Path(tempfile.mkdtemp(prefix="prismor-r4-ws-"))
        policy_dir = self.ws / ".prismor"
        policy_dir.mkdir(parents=True, exist_ok=True)
        (policy_dir / "policy.yaml").write_text(_POLICY)

    def _stdout_json(self, proc):
        line = proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else ""
        self.assertTrue(line, f"expected JSON on stdout; got stdout={proc.stdout!r} stderr={proc.stderr!r}")
        return json.loads(line)

    def test_deny_exits_2(self):
        proc = _dispatch("claude", "echo R4_DENY_MARKER", self.ws, self.home)
        self.assertEqual(proc.returncode, 2, proc.stderr)

    def test_multiple_blockers_reach_text_and_json_hooks(self):
        policy = self.ws / ".prismor" / "policy.yaml"
        second = _POLICY[_POLICY.index("  - id: r4-deny"):].replace("id: r4-deny", "id: r4-deny-second")
        policy.write_text(_POLICY + second)
        for agent in ("claude", "copilot", "antigravity"):
            with self.subTest(agent=agent):
                proc = _dispatch(agent, "echo R4_DENY_MARKER", self.ws, self.home)
                if agent == "claude":
                    self.assertEqual(proc.returncode, 2, proc.stderr)
                    reason = proc.stderr
                else:
                    out = self._stdout_json(proc)
                    self.assertEqual(out.get("permissionDecision", out.get("decision")), "deny")
                    reason = out.get("permissionDecisionReason", out.get("reason"))
                self.assertIn("Also blocked by: r4-deny-second.", reason)

    def test_step_up_claude_emits_ask(self):
        proc = _dispatch("claude", "echo R4_STEPUP_MARKER", self.ws, self.home)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out = self._stdout_json(proc)
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "ask")
        self.assertIn("R4", out["hookSpecificOutput"]["permissionDecisionReason"] or "step")

    def test_step_up_copilot_emits_ask(self):
        proc = _dispatch("copilot", "echo R4_STEPUP_MARKER", self.ws, self.home)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out = self._stdout_json(proc)
        self.assertEqual(out["permissionDecision"], "ask")

    def test_step_up_cursor_shell_emits_ask(self):
        # beforeShellExecution accepts {"permission": "ask"} (cursor.com/docs/agent/hooks).
        proc = _dispatch("cursor", "echo R4_STEPUP_MARKER", self.ws, self.home)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out = self._stdout_json(proc)
        self.assertEqual(out["permission"], "ask")
        self.assertIn("r4-stepup", out["agent_message"] + out["user_message"])

    # On exit 2 Cursor shows stdout verbatim and never parses it as JSON, so a
    # deny prints a plain-text message rather than {"permission": "deny"}.
    def _assert_plain_deny(self, proc, marker):
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertIn(marker, proc.stdout)
        self.assertFalse(proc.stdout.lstrip().startswith("{"), proc.stdout)

    def test_deny_cursor_prints_plain_message_and_exits_2(self):
        proc = _dispatch("cursor", "echo R4_DENY_MARKER", self.ws, self.home)
        self._assert_plain_deny(proc, "r4-deny")

    def test_modify_cursor_fails_closed_with_plain_deny(self):
        proc = _dispatch("cursor", "echo R4_MODIFY_MARKER", self.ws, self.home)
        self._assert_plain_deny(proc, "Prismor could not safely modify")

    def _dispatch_cursor(self, payload):
        env = dict(os.environ)
        env["PRISMOR_HOME"] = str(self.home)
        env["PRISMOR_SECRETS_DIR"] = str(self.home / "secrets")
        env["PYTHONPATH"] = str(_REPO)
        return subprocess.run(
            [sys.executable, "-m", "prismor.runtime.immunity_cli", "hook-dispatch",
             "--agent", "cursor", "--workspace", str(self.ws), "--mode", "enforce"],
            input=json.dumps(payload), capture_output=True, text=True, env=env,
        )

    def test_step_up_cursor_read_fails_closed(self):
        # beforeReadFile has no "ask": step-up must DENY, never allow.
        (self.ws / ".prismor" / "policy.yaml").write_text(_POLICY + """
  - id: r4-read-stepup
    severity: HIGH
    category: secret_access  # reads only govern for secret_access / iam
    title: Step-up on reading the marker file
    event_types: [file_read]
    fields: [path]
    mode: enforce
    action: step_up
    patterns:
      - "R4_READ_MARKER"
""")
        proc = self._dispatch_cursor({
            "hook_event_name": "beforeReadFile", "conversation_id": "r4-c",
            "file_path": str(self.ws / "R4_READ_MARKER.txt"), "content": "", "attachments": [],
        })
        self._assert_plain_deny(proc, "no approval surface")

    def test_deny_cursor_prompt_prints_plain_message(self):
        (self.ws / ".prismor" / "policy.yaml").write_text(_POLICY + """
  - id: r4-prompt-deny
    severity: HIGH
    category: test_r4
    title: Deny the prompt marker
    event_types: [prompt]
    fields: [prompt]
    mode: enforce
    action: block
    patterns:
      - "R4_PROMPT_MARKER"
""")
        proc = self._dispatch_cursor({
            "hook_event_name": "beforeSubmitPrompt", "conversation_id": "r4-c",
            "prompt": "please R4_PROMPT_MARKER", "attachments": [],
        })
        self._assert_plain_deny(proc, "r4-prompt-deny")

    def test_allow_cursor_prints_nothing(self):
        # Cursor parses stdout of permission hooks; an allow must not emit stray text.
        proc = self._dispatch_cursor({
            "hook_event_name": "beforeShellExecution", "conversation_id": "r4-c",
            "command": "echo hello", "cwd": str(self.ws), "sandbox": False,
        })
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.strip(), "")

    def test_modify_claude_rewrites_input(self):
        proc = _dispatch("claude", "echo R4_MODIFY_MARKER", self.ws, self.home)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out = self._stdout_json(proc)
        new_cmd = out["hookSpecificOutput"]["updatedInput"]["command"]
        self.assertIn("sandbox", new_cmd)
        self.assertNotEqual(new_cmd, "echo R4_MODIFY_MARKER")

    def test_modify_copilot_fails_closed(self):
        # Copilot can't rewrite tool input → fail closed to DENY.
        proc = _dispatch("copilot", "echo R4_MODIFY_MARKER", self.ws, self.home)
        self.assertEqual(proc.returncode, 2, proc.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
