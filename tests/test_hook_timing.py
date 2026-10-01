"""A hook call leaves how long it took, and the dashboard APIs surface it."""
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]


class HookTiming(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp(prefix="prismor-hooktime-home-"))
        self.ws = Path(tempfile.mkdtemp(prefix="prismor-hooktime-ws-"))
        self.env = dict(os.environ)
        self.env.update({
            "PRISMOR_HOME": str(self.home),
            "PRISMOR_SECRETS_DIR": str(self.home / "secrets"),
            "PYTHONPATH": str(_REPO),
        })

    def _dispatch(self, hook_event, **fields):
        payload = {"hook_event_name": hook_event, "session_id": "hooktime-e2e", "cwd": str(self.ws), **fields}
        return subprocess.run(
            [sys.executable, "-m", "prismor.runtime.immunity_cli", "hook-dispatch",
             "--agent", "claude", "--workspace", str(self.ws), "--mode", "observe"],
            input=json.dumps(payload), capture_output=True, text=True, env=self.env,
        )

    def test_pre_and_post_are_timed_and_shown(self):
        self._dispatch("PreToolUse", tool_name="Bash", tool_input={"command": "echo hi"})
        self._dispatch("PostToolUse", tool_name="Bash", tool_input={"command": "echo hi"},
                       tool_response={"stdout": "hi"})

        os.environ.update({k: self.env[k] for k in ("PRISMOR_HOME", "PRISMOR_SECRETS_DIR")})
        from prismor.runtime import store
        rows = sqlite3.connect(store.get_db_path(self.ws)).execute(
            "SELECT hook_event, hook_ms FROM hook_timings ORDER BY ts").fetchall()
        self.assertEqual([r[0] for r in rows], ["PreToolUse", "PostToolUse"])
        self.assertTrue(all(r[1] > 0 for r in rows), rows)

        detail = store.get_session_scoped_detail(self.ws, "hooktime-e2e")
        call = next(e for e in detail["recent_events"] if e.get("type") == "shell")
        self.assertEqual(call["agentEvent"], "PreToolUse")
        self.assertGreater(call["hookMs"], 0)
        self.assertGreater(call["postHookMs"], 0)

        os.environ["PRISMOR_WORKSPACE"] = str(self.ws)
        page = store.get_events_page(limit=10)
        timed = [e for e in page["items"] if e.get("hookMs")]
        self.assertTrue(timed, page["items"])
        self.assertIn(timed[0]["agentEvent"], ("PreToolUse", "PostToolUse"))


if __name__ == "__main__":
    unittest.main()
