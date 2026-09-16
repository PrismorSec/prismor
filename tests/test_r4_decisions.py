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

    def test_step_up_cursor_fails_closed(self):
        # No inline-approval surface → must DENY, never allow.
        proc = _dispatch("cursor", "echo R4_STEPUP_MARKER", self.ws, self.home)
        self.assertEqual(proc.returncode, 2, proc.stderr)

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


class ContextualAsk(R4Decisions):
    """A deny on a known host becomes an inline ask; the host's history lives
    in the isolated $PRISMOR_HOME store."""

    HOST = "10.0.0.9"

    def _seed_known_host(self, n: int = 5):
        from prismor.runtime.cli import analyze_events
        from prismor.runtime.store import save_session_snapshot
        old = dict(os.environ)
        os.environ["PRISMOR_HOME"] = str(self.home)
        try:
            for i in range(n):
                events = [{"type": "shell", "command": f"ssh ubuntu@{self.HOST} 'npm test'", "ts": "2026-01-01T00:00:00Z"}]
                analysis = analyze_events(events, repo_root=self.ws, workspace=self.ws)
                save_session_snapshot(workspace=self.ws, session_id=f"seed-{i}", agent="claude",
                                      source="ingest", repo_url=None, events=events, analysis=analysis)
        finally:
            os.environ.clear(); os.environ.update(old)

    def test_deny_on_known_host_becomes_ask(self):
        self._seed_known_host()
        proc = _dispatch("claude", f"ssh ubuntu@{self.HOST} 'echo R4_DENY_MARKER'", self.ws, self.home)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out = self._stdout_json(proc)
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "ask")
        self.assertIn("Asking instead of blocking", out["hookSpecificOutput"]["permissionDecisionReason"])

    def test_deny_on_unknown_host_still_denies(self):
        self._seed_known_host(n=1)
        proc = _dispatch("claude", f"ssh ubuntu@{self.HOST} 'echo R4_DENY_MARKER'", self.ws, self.home)
        self.assertEqual(proc.returncode, 2, proc.stdout)

    def test_deny_without_ask_surface_stays_deny(self):
        self._seed_known_host()
        proc = _dispatch("cursor", f"ssh ubuntu@{self.HOST} 'echo R4_DENY_MARKER'", self.ws, self.home)
        self.assertEqual(proc.returncode, 2, proc.stdout)
