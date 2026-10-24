"""One-shot human approvals: block -> `prismor approvals approve <id>` -> the
same call runs once, then blocks again. Driven through the real hook
dispatcher, because the bug that mattered (an approval spent but the call
still blocked) only showed up there.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from prismor.runtime import approvals_local  # noqa: E402

_CANARY_POLICY = """rules:
  - id: approval-canary
    severity: CRITICAL
    category: destructive_command
    title: Test canary for one-shot approvals
    event_types: [shell]
    fields: [command]
    patterns: ['approval-canary']
    action: block
"""


class TestHookApprovals(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp()
        self.ws = Path(tempfile.mkdtemp())
        (self.ws / ".prismor").mkdir()
        (self.ws / ".prismor" / "policy.yaml").write_text(_CANARY_POLICY)
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("PRISMOR_")}
        self.env.update(PRISMOR_HOME=self.home, PYTHONPATH=str(ROOT))
        os.environ["PRISMOR_HOME"] = self.home  # for approvals_local in-process

    def tearDown(self):
        os.environ.pop("PRISMOR_HOME", None)

    def _hook(self, command, agent="codex", call_id=None, workspace_flag=False):
        payload = {"hook_event_name": "PreToolUse", "session_id": "s1", "cwd": str(self.ws),
                   "tool_name": "Bash", "tool_input": {"command": command}}
        if call_id:
            payload["tool_use_id"] = call_id
        ws_args = ["--workspace", str(self.ws)] if workspace_flag else []
        return subprocess.run(
            [sys.executable, "-m", "prismor.runtime.immunity_cli", "hook-dispatch",
             "--agent", agent, "--mode", "enforce", *ws_args],
            input=json.dumps(payload), capture_output=True, text=True, cwd=self.ws,
            env=self.env, timeout=120)

    def _pending(self):
        return [r for r in approvals_local.list_requests() if r["status"] == "pending"]

    def test_block_approve_runs_once(self):
        first = self._hook("echo approval-canary")
        self.assertEqual(first.returncode, 2)
        (req,) = self._pending()
        self.assertIn(f"prismor approvals approve {req['id']}", first.stderr)

        approvals_local.decide(req["id"], approve=True)
        self.assertEqual(self._hook("echo approval-canary").returncode, 0)

        again = self._hook("echo approval-canary")
        self.assertEqual(again.returncode, 2, "an approval is spent by the call it lets through")
        self.assertNotEqual(self._pending()[0]["id"], req["id"])

    def test_global_and_project_hook_share_one_approval(self):
        # #752: a global hook (no --workspace) and a project hook both screen
        # each call. The first spent the approval, the second blocked the same
        # call under a new id, forever.
        cmd = "echo approval-canary"
        self.assertEqual(self._hook(cmd, call_id="t1").returncode, 2)
        self.assertEqual(self._hook(cmd, call_id="t1", workspace_flag=True).returncode, 2)
        (req,) = self._pending()
        approvals_local.decide(req["id"], approve=True)
        self.assertEqual(self._hook(cmd, call_id="t2").returncode, 0)
        self.assertEqual(self._hook(cmd, call_id="t2", workspace_flag=True).returncode, 0)
        self.assertEqual(self._hook(cmd, call_id="t3").returncode, 2, "still once only")

    def test_approval_is_for_that_exact_call(self):
        self._hook("echo approval-canary one")
        approvals_local.decide(self._pending()[0]["id"], approve=True)
        self.assertEqual(self._hook("echo approval-canary two").returncode, 2)

    def test_agent_cannot_approve_or_touch_the_file(self):
        for cmd in ("prismor approvals approve abc123", "cat ~/.prismor/approvals.json"):
            out = self._hook(cmd)
            self.assertEqual(out.returncode, 2, cmd)
            self.assertIn("prismor-self-edit", out.stderr)
        self.assertEqual(self._hook("prismor approvals").returncode, 0, "listing stays open")

    def test_approve_needs_a_terminal(self):
        out = subprocess.run(
            [sys.executable, "-m", "prismor.runtime.immunity_cli", "approvals", "approve", "abc123"],
            stdin=subprocess.DEVNULL, capture_output=True, text=True, env=self.env, timeout=60)
        self.assertEqual(out.returncode, 1)
        self.assertIn("in a terminal", out.stderr)

    def test_hold_open_only_where_verified_and_capped(self):
        os.environ["PRISMOR_APPROVAL_WAIT"] = "999"
        try:
            self.assertEqual(approvals_local.wait_seconds("claude"), approvals_local.MAX_WAIT)
            self.assertEqual(approvals_local.wait_seconds("goose"), 0)
        finally:
            os.environ.pop("PRISMOR_APPROVAL_WAIT")


if __name__ == "__main__":
    unittest.main()
