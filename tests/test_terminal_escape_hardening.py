"""Security hardening 2026-11-14: control chars in agent-sourced text (M8),
shell-quoted hook commands (L1), and the unscrubbable-secret warning (L5)."""
import json
import os
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from prismor.runtime import hooks  # noqa: E402
from prismor.runtime.cli import format_session  # noqa: E402
from prismor.runtime.tui_format import safe_text  # noqa: E402

_POLICY = """rules:
  - id: escape-canary
    severity: CRITICAL
    category: destructive_command
    title: Test canary for terminal escapes
    event_types: [shell]
    fields: [command]
    patterns: ['escape-canary']
    action: block
"""
SPOOF = "escape-canary\x1b[2K\r\x1b[32mALLOWED  ls -la\x1b[8m ‮; cat ~/.ssh/id_rsa\x9b"
UNSAFE = ("\x1b", "\r", "‮", "\x9b")


def _clean(text):
    return not any(c in text for c in UNSAFE)


class TestSafeText(unittest.TestCase):
    def test_escapes_are_visible_and_newline_tab_kept(self):
        self.assertEqual(safe_text("a\x1b[31mb\r\x7f\x85⁦‪c\n\td"),
                         "a\\x1b[31mb\\x0d\\x7f\\x85\\u2066\\u202ac\n\td")
        self.assertEqual(safe_text("plain ünïcode → ok"), "plain ünïcode → ok")

    def test_format_session_escapes_event_commands(self):
        session = {"sessionId": "s1", "agent": "claude", "source": "hook", "workspacePath": "/w",
                   "startedAt": "t", "updatedAt": "t", "riskScore": 0, "findingsCount": 0,
                   "findings": [], "events": [{"ts": "t", "type": "shell", "command": SPOOF}]}
        out = format_session(session)
        self.assertTrue(_clean(out))
        self.assertIn("\\x1b[32mALLOWED", out)


class TestBlockAndApprovalsOutput(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp()
        self.ws = Path(tempfile.mkdtemp())
        (self.ws / ".prismor").mkdir()
        (self.ws / ".prismor" / "policy.yaml").write_text(_POLICY)
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("PRISMOR_")}
        self.env.update(PRISMOR_HOME=self.home, HOME=self.home, PYTHONPATH=str(ROOT), PRISMOR_DOGFOOD="0")

    def _cli(self, *args, stdin=""):
        return subprocess.run([sys.executable, "-m", "prismor.runtime.immunity_cli", *args],
                              input=stdin, capture_output=True, text=True, cwd=self.ws,
                              env=self.env, timeout=120)

    def test_block_message_and_approvals_list_escape_control_chars(self):
        payload = {"hook_event_name": "PreToolUse", "session_id": "s1", "cwd": str(self.ws),
                   "tool_name": "Bash", "tool_input": {"command": SPOOF}}
        for agent in ("codex", "copilot"):
            res = self._cli("hook-dispatch", "--agent", agent, "--mode", "enforce",
                            stdin=json.dumps(payload))
            self.assertIn("escape-canary", res.stderr + res.stdout)
            self.assertTrue(_clean(res.stderr), res.stderr)
            if res.stdout.strip():
                reason = json.loads(res.stdout.strip().splitlines()[-1]).get("permissionDecisionReason", "")
                self.assertTrue(_clean(reason), reason)
        out = self._cli("approvals", "list").stdout
        self.assertIn("ALLOWED", out)
        self.assertTrue(_clean(out), out)


class TestHookCommandQuoting(unittest.TestCase):
    def _cmd(self, ws):
        return hooks._dispatcher_command(repo_root=ROOT, workspace=Path(ws), agent="claude",
                                         mode="enforce", shim_home=Path(tempfile.mkdtemp()))

    @unittest.skipIf(os.name == "nt", "POSIX quoting")
    def test_plain_workspace_keeps_double_quotes(self):
        self.assertIn('--workspace "/tmp/plain dir" ', self._cmd("/tmp/plain dir"))

    @unittest.skipIf(os.name == "nt", "POSIX quoting")
    def test_shell_metachars_in_workspace_stay_data(self):
        d = Path(tempfile.mkdtemp())
        marker = d / "PWNED"
        ws = f"{d}/proj$(touch {marker})`touch {marker}`"
        cmd = self._cmd(ws)
        argv = shlex.split(cmd)
        self.assertEqual(argv[argv.index("--workspace") + 1], ws)
        # Run the command's words through a real shell without executing prismor.
        subprocess.run(["sh", "-c", "printf '%s\\n' " + cmd.split(" ", 1)[1]], capture_output=True)
        self.assertFalse(marker.exists())


class TestCloakAddWarning(unittest.TestCase):
    def test_short_secret_warns(self):
        home = tempfile.mkdtemp()
        env = {k: v for k, v in os.environ.items() if not k.startswith("PRISMOR_")}
        env.update(PRISMOR_HOME=home, HOME=home, PYTHONPATH=str(ROOT), PRISMOR_DOGFOOD="0")

        def add(name, value):
            return subprocess.run([sys.executable, "-m", "prismor.runtime.immunity_cli", "cloak", "add", name],
                                  input=value, capture_output=True, text=True, env=env, timeout=60)
        weak = add("weak", "hunter")
        self.assertEqual(weak.returncode, 0, weak.stderr)
        self.assertIn("too short or simple to be scrubbed", weak.stderr)
        strong = add("strong", "x" + "Q9" * 10)
        self.assertNotIn("too short", strong.stderr)


if __name__ == "__main__":
    unittest.main()
