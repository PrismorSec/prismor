"""Background work in Claude Code reaches the trail.

Seen live 2026-11-17 in the Claude desktop app (5 background subagents):
task-notifications were queued into the transcript with no UserPromptSubmit
hook, failed calls had no PostToolUse row, and Monitor/ToolSearch/
SubagentHandback never reached the hook.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prismor.runtime.hooks import _CLAUDE_TOOL_MATCHER, _normalize_claude

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NOTICE = ("<task-notification>\n<task-id>a942</task-id>\n<tool-use-id>toolu_1</tool-use-id>\n"
          "<status>completed</status>\n<summary>Agent \"research\" finished</summary>\n</task-notification>")


class Matcher(unittest.TestCase):
    def test_background_tools_are_hooked(self):
        names = _CLAUDE_TOOL_MATCHER.split("|")
        for tool in ("Monitor", "TaskOutput", "TaskStop", "SendMessage", "Workflow",
                     "ToolSearch", "SubagentHandback", "CronCreate", "ScheduleWakeup"):
            self.assertIn(tool, names)

    def test_monitor_command_is_screened_as_shell(self):
        ev = _normalize_claude({"hook_event_name": "PreToolUse", "tool_name": "Monitor",
                                "tool_input": {"command": "tail -f app.log"}}, "s", Path("/w"))
        self.assertEqual((ev["type"], ev["command"]), ("shell", "tail -f app.log"))

    def test_failure_error_is_the_shell_stderr(self):
        ev = _normalize_claude({"hook_event_name": "PostToolUseFailure", "tool_name": "Bash",
                                "tool_input": {"command": "false"}, "error": "exit 1"}, "s", Path("/w"))
        self.assertEqual(ev["stderr"], "exit 1")


class Dispatch(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.ws = self.root / "ws"
        self.ws.mkdir()
        self.home = self.root / "home" / ".prismor"
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("PRISMOR_")}
        self.env.update(HOME=str(self.root / "home"), PRISMOR_HOME=str(self.home),
                        PYTHONPATH=ROOT, PRISMOR_NO_UPDATE_CHECK="1")

    def _dispatch(self, payload):
        r = subprocess.run([sys.executable, "-m", "prismor.runtime.cli", "hook-dispatch", "--agent", "claude",
                            "--workspace", str(self.ws), "--mode", "enforce"],
                           input=json.dumps({"cwd": str(self.ws), **payload}), text=True,
                           capture_output=True, env=self.env, timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r

    def _rows(self, sid):
        log = self.home / "sessions" / f"{sid}.jsonl"
        return [json.loads(l) for l in log.read_text().splitlines()] if log.exists() else []

    def _transcript(self, rows):
        path = self.root / "t.jsonl"
        path.write_text("".join(json.dumps(r) + "\n" for r in rows))
        return str(path)

    def test_queued_notification_is_recorded_once_at_stop(self):
        transcript = self._transcript([
            {"type": "user", "message": {"role": "user", "content": "start the agents"}},
            {"type": "user", "timestamp": "2026-11-18T04:21:12+00:00",
             "origin": {"kind": "task-notification"}, "message": {"role": "user", "content": NOTICE}},
        ])
        stop = {"session_id": "sn", "hook_event_name": "Stop", "transcript_path": transcript,
                "last_assistant_message": "one agent finished"}
        r = self._dispatch(stop)
        self.assertEqual(r.stdout.strip(), "")  # a Stop hook must never answer
        self._dispatch(stop)  # the next Stop sees the same transcript
        rows = self._rows("sn")
        prompts = [e for e in rows if e["type"] == "prompt"]
        self.assertEqual(len(prompts), 1)
        self.assertIn("<task-id>a942</task-id>", prompts[0]["prompt"])
        self.assertEqual([e["type"] for e in rows].count("assistant_response"), 2)

    def test_notification_seen_by_prompt_hook_is_not_recorded_again(self):
        transcript = self._transcript([
            {"type": "user", "message": {"role": "user", "content": NOTICE}}])
        self._dispatch({"session_id": "sp", "hook_event_name": "UserPromptSubmit", "prompt": NOTICE,
                        "transcript_path": transcript})
        self._dispatch({"session_id": "sp", "hook_event_name": "Stop", "transcript_path": transcript,
                        "last_assistant_message": "ok"})
        self.assertEqual([e["type"] for e in self._rows("sp")].count("prompt"), 1)

    def test_failed_call_is_recorded(self):
        self._dispatch({"session_id": "sf", "hook_event_name": "PostToolUseFailure", "tool_name": "Bash",
                        "tool_use_id": "toolu_f", "tool_input": {"command": "false"}, "error": "exit 1"})
        rows = self._rows("sf")
        self.assertEqual([(e["agent_event"], e.get("stderr")) for e in rows],
                         [("PostToolUseFailure", "exit 1")])


if __name__ == "__main__":
    unittest.main()
