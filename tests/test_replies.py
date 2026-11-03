"""The model's reply per turn, recorded for the session view (replies.py).

Payload shapes: Claude/Codex/Cursor/Gemini/Windsurf from each agent's hooks
docs; Copilot CLI 1.0.90 verified live 2026-11-03 (PascalCase Stop is
Claude-shaped with transcript_path to events.jsonl and no reply text).
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prismor.runtime import replies
from prismor.runtime.hooks import (
    _merge_claude, _merge_codex, _merge_copilot, _merge_cursor, _merge_gemini,
)
from prismor.runtime.store import event_artifacts, event_lane

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _jsonl(rows):
    f = tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False)
    f.write("\n".join(json.dumps(r) for r in rows) + "\n")
    f.close()
    return f.name


def _claude_row(kind, content, **extra):
    return {"type": kind, "message": {"role": kind, "content": content}, **extra}


class ReplyExtraction(unittest.TestCase):
    def test_claude_reply_and_only_this_turns_thinking(self):
        path = _jsonl([
            _claude_row("user", "first question"),
            _claude_row("assistant", [{"type": "thinking", "thinking": "old turn"}]),
            _claude_row("user", [{"type": "text", "text": "second question"}]),
            _claude_row("assistant", [{"type": "thinking", "thinking": "plan the edit"},
                                      {"type": "tool_use", "id": "t1", "name": "Read", "input": {}}]),
            # A tool result is a "user" row too; it must not start a new turn.
            _claude_row("user", [{"type": "tool_result", "tool_use_id": "t1", "content": "ok"}],
                        toolUseResult={"stdout": "ok"}),
            _claude_row("assistant", [{"type": "thinking", "thinking": "", "signature": "sig"},
                                      {"type": "thinking", "thinking": "now answer"}]),
        ])
        ev = replies.reply_event("claude", {"hook_event_name": "Stop", "transcript_path": path,
                                            "last_assistant_message": "All done."}, "s1")
        self.assertEqual(ev["type"], "assistant_response")
        self.assertEqual(ev["response"], "All done.")
        self.assertEqual(ev["reasoning"], "plan the edit\n\nnow answer")
        self.assertNotIn("old turn", ev["reasoning"])

    def test_claude_stop_failure_is_marked_as_an_error(self):
        ev = replies.reply_event("claude", {"hook_event_name": "StopFailure",
                                            "last_assistant_message": "API Error: overloaded"}, "s1")
        self.assertTrue(ev["metadata"]["error"])

    def test_codex_reasoning_summary_from_the_current_task(self):
        path = _jsonl([
            {"type": "event_msg", "payload": {"type": "task_started"}},
            {"type": "response_item", "payload": {"type": "reasoning", "summary": [{"type": "summary_text", "text": "earlier"}]}},
            {"type": "event_msg", "payload": {"type": "task_started"}},
            {"type": "response_item", "payload": {"type": "reasoning", "encrypted_content": "x",
                                                  "summary": [{"type": "summary_text", "text": "check the tests"}]}},
        ])
        ev = replies.reply_event("codex", {"hook_event_name": "Stop", "transcript_path": path,
                                           "last_assistant_message": "Fixed it.", "model": "gpt-5.5"}, "s2")
        self.assertEqual((ev["response"], ev["reasoning"]), ("Fixed it.", "check the tests"))
        self.assertEqual(ev["metadata"]["model"], "gpt-5.5")

    def test_copilot_reads_the_last_turn_from_events_jsonl(self):
        path = _jsonl([
            {"type": "user.message", "data": {"content": "old"}},
            {"type": "assistant.message", "data": {"content": "old answer"}},
            {"type": "user.message", "data": {"content": "new"}},
            {"type": "assistant.message", "data": {"content": "", "reasoningText": "look first",
                                                   "outputTokens": 7, "model": "gpt-4.1"}},
            {"type": "assistant.message", "data": {"content": "new answer", "outputTokens": 5}},
        ])
        ev = replies.reply_event("copilot", {"hook_event_name": "Stop", "transcript_path": path}, "s3")
        self.assertEqual((ev["response"], ev["reasoning"]), ("new answer", "look first"))
        self.assertEqual((ev["metadata"]["output_tokens"], ev["metadata"]["model"]), (12, "gpt-4.1"))

    def test_cursor_gemini_windsurf_carry_the_reply_on_the_hook(self):
        cur = replies.reply_event("cursor", {"hook_event_name": "afterAgentResponse", "text": "hi"}, "c")
        thought = replies.reply_event("cursor", {"hook_event_name": "afterAgentThought", "text": "hmm",
                                                 "duration_ms": 40}, "c")
        gem = replies.reply_event("gemini", {"hook_event_name": "AfterAgent", "prompt": "q",
                                             "prompt_response": "answer"}, "g")
        ws = replies.reply_event("windsurf", {"agent_action_name": "post_cascade_response",
                                              "tool_info": {"response": "## Summary"}}, "w")
        self.assertEqual(cur["response"], "hi")
        self.assertEqual((thought["response"], thought["reasoning"]), ("", "hmm"))
        self.assertEqual(gem["response"], "answer")
        self.assertEqual(ws["response"], "## Summary")
        # The reply text is not kept a second time inside the raw payload.
        self.assertNotIn("prompt_response", gem["metadata"]["raw"])

    def test_only_reply_events_are_claimed(self):
        self.assertTrue(replies.is_reply("claude", {"hook_event_name": "Stop"}))
        self.assertFalse(replies.is_reply("claude", {"hook_event_name": "PreToolUse"}))
        self.assertFalse(replies.is_reply("gemini", {"hook_event_name": "BeforeAgent"}))
        self.assertTrue(replies.is_reply("windsurf", {"agent_action_name": "post_cascade_response"}))

    def test_long_text_is_capped_and_flagged(self):
        ev = replies.reply_event("gemini", {"hook_event_name": "AfterAgent", "prompt_response": "a" * 9000}, "g")
        self.assertEqual(len(ev["response"]), 8000)
        self.assertEqual(ev["metadata"]["response_chars"], 9000)
        self.assertTrue(ev["metadata"]["truncated"])

    def test_session_view_files_it_under_replies(self):
        ev = replies.reply_event("gemini", {"hook_event_name": "AfterAgent", "prompt_response": "answer"}, "g")
        ev["reasoning"] = "why"
        self.assertEqual(event_lane(ev["type"]), "assistant")
        arts = event_artifacts(ev)
        self.assertEqual((arts.get("reply"), arts.get("reasoning")), ("answer", "why"))
        self.assertNotIn("response", arts)  # "response" is labelled as tool output


class Installers(unittest.TestCase):
    def test_each_agent_registers_its_reply_hook(self):
        cmd = "prismor hook-dispatch"
        self.assertTrue({"Stop", "StopFailure"} <= set(_merge_claude({}, cmd, Path("."))["hooks"]))
        self.assertIn("Stop", _merge_codex({}, cmd)["hooks"])
        self.assertIn("Stop", _merge_copilot({}, cmd)["hooks"])
        self.assertTrue({"afterAgentResponse", "afterAgentThought"} <= set(_merge_cursor({}, cmd)["hooks"]))
        self.assertTrue({"BeforeAgent", "AfterAgent"} <= set(_merge_gemini({}, cmd)["hooks"]))


class DispatchRecordsAndStaysSilent(unittest.TestCase):
    """End to end: the reply is recorded, nothing is printed, exit 0.

    Any output or exit 2 on these events makes the agent keep going
    (Claude Stop, Gemini AfterAgent retry, Cursor follow-ups)."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.ws = self.root / "ws"
        self.ws.mkdir()
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("PRISMOR_")}
        self.env.update(HOME=str(self.root / "home"), PRISMOR_HOME=str(self.root / "home" / ".prismor"),
                        PYTHONPATH=ROOT, PRISMOR_NO_UPDATE_CHECK="1")

    def _dispatch(self, agent, payload):
        return subprocess.run([sys.executable, "-m", "prismor.runtime.cli", "hook-dispatch", "--agent", agent,
                               "--workspace", str(self.ws), "--mode", "enforce"],
                              input=json.dumps(payload), text=True, capture_output=True,
                              env=self.env, timeout=120)

    def test_each_agent(self):
        cases = [
            ("claude", {"session_id": "sc", "hook_event_name": "Stop", "last_assistant_message": "claude says"}),
            ("codex", {"session_id": "sx", "hook_event_name": "Stop", "last_assistant_message": "codex says"}),
            ("cursor", {"conversation_id": "su", "hook_event_name": "afterAgentResponse", "text": "cursor says"}),
            ("gemini", {"session_id": "sg", "hook_event_name": "AfterAgent", "prompt_response": "gemini says"}),
            ("windsurf", {"trajectory_id": "sw", "agent_action_name": "post_cascade_response",
                          "tool_info": {"response": "windsurf says"}}),
        ]
        for agent, payload in cases:
            with self.subTest(agent=agent):
                r = self._dispatch(agent, {"cwd": str(self.ws), **payload})
                self.assertEqual((r.returncode, r.stdout.strip()), (0, ""), r.stderr)
                sid = next(v for k, v in payload.items() if k in ("session_id", "conversation_id", "trajectory_id"))
                log = self.root / "home" / ".prismor" / "sessions" / f"{sid}.jsonl"
                rows = [json.loads(l) for l in log.read_text().splitlines()]
                self.assertEqual([(e["type"], e["response"]) for e in rows],
                                 [("assistant_response", f"{agent} says")])


if __name__ == "__main__":
    unittest.main()
