"""A command the OS sandbox refused is explained to the agent and recorded."""
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from prismor.runtime import sandbox

REPO = Path(__file__).resolve().parents[1]
DENIED = "cat: /Users/x/.aws/credentials: Operation not permitted"
NET = "[prismor] sandbox: blocked example.com:443 (not on the egress allowlist)"


class TestDetect(unittest.TestCase):
    def test_reads_file_and_network_refusals(self):
        out = f"ok\n{DENIED}\n{NET}\n{DENIED}\nsh: line 2: hook: Read-only file system\n"
        self.assertEqual([k for k, _ in sandbox.denials(out)], ["file", "network", "file"])

    def test_reads_python_and_node_wording(self):
        for line in ("PermissionError: [Errno 1] Operation not permitted: '/x'",
                     "Error: EPERM: operation not permitted, open '/x'",
                     "(eval):1: operation not permitted: build.txt"):
            self.assertEqual(sandbox.denials(line), [("file", line)])

    def test_ignores_prose_and_ordinary_errors(self):
        out = ("macOS says Operation not permitted when it refuses.\n"
               "cat: nope: No such file or directory\nPermission denied (publickey)\n")
        self.assertEqual(sandbox.denials(out), [])


@unittest.skipUnless(sandbox.supported(), "needs macOS or Linux")
class TestHook(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        (self.tmp / ".git").mkdir()
        (self.tmp / ".prismor").mkdir()
        self._policy("true")

    def _policy(self, enabled):
        (self.tmp / ".prismor" / "policy.yaml").write_text(
            f'version: "1.0"\nsettings:\n  sandbox:\n    enabled: {enabled}\nrules: []\n')

    def _hook(self, event, command="cat ~/.aws/credentials", **result):
        payload = {"session_id": "s1", "hook_event_name": event, "tool_name": "Bash",
                   "tool_use_id": "tu1", "cwd": str(self.tmp), "tool_input": {"command": command}, **result}
        env = dict(os.environ, PYTHONPATH=str(REPO), PRISMOR_HOME=str(self.tmp / "ph"), HOME=str(self.tmp))
        for key in ("PRISMOR_WORKSPACE", "CLAUDE_PROJECT_DIR"):
            env.pop(key, None)
        code = ("import sys; sys.argv = ['prismor','hook-dispatch','--agent','claude','--mode','enforce']; "
                "from prismor.runtime.cli import main; main()")
        r = subprocess.run([sys.executable, "-c", code], input=json.dumps(payload), cwd=self.tmp,
                           env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout

    def _recorded(self):
        for db in self.tmp.rglob("*.db"):
            with sqlite3.connect(db) as conn:
                tables = [t for (t,) in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]
                for table in tables:
                    if any("sandbox-denied" in str(row) for row in conn.execute(f'SELECT * FROM "{table}"')):
                        return True
        return False

    def test_failed_call_is_explained_and_recorded(self):
        out = self._hook("PostToolUseFailure", error=f"Exit code 1\n{DENIED}")
        spec = json.loads(out)["hookSpecificOutput"]
        self.assertEqual(spec["hookEventName"], "PostToolUseFailure")
        self.assertIn("OS sandbox", spec["additionalContext"])
        self.assertTrue(self._recorded())

    def test_successful_call_with_a_refusal_inside_is_explained(self):
        out = self._hook("PostToolUse", "npm install", tool_response={"stdout": f"added 1\n{NET}", "stderr": ""})
        self.assertIn("settings.egress", json.loads(out)["hookSpecificOutput"]["additionalContext"])
        self.assertTrue(self._recorded())

    def test_refusal_on_stderr_with_empty_stdout_is_explained(self):
        out = self._hook("PostToolUse", "touch ~/.ssh/k || true",
                         tool_response={"stdout": "", "stderr": DENIED, "interrupted": False})
        self.assertIn("OS sandbox", json.loads(out)["hookSpecificOutput"]["additionalContext"])

    def test_nothing_when_the_sandbox_is_off(self):
        self._policy("false")
        out = self._hook("PostToolUseFailure", error=f"Exit code 1\n{DENIED}")
        self.assertNotIn("OS sandbox", out)
        self.assertFalse(self._recorded())


if __name__ == "__main__":
    unittest.main()
