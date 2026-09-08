"""The session view's payload: artefacts, lanes, and one row per tool call.

The event log has always held far more than the session view showed -- the
prompt text, what a tool returned, the instruction files already in context --
so a session rendered as a column of type names and the question "what did this
agent actually do" could only be answered by reading JSONL by hand.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prismor.runtime.store import (  # noqa: E402
    _ARTIFACT_CHARS,
    _merge_tool_phases,
    event_artifacts,
    event_lane,
)


class TestEventArtifacts(unittest.TestCase):
    def test_prompt_text_is_carried(self):
        art = event_artifacts({
            "type": "prompt",
            "prompt": "You are an HR assistant. What is the leave policy?",
            "metadata": {"model": "gpt-4o-mini", "provider": "openai", "surface": "llm-proxy"},
        })
        self.assertIn("HR assistant", art["prompt"])
        self.assertEqual(art["model"], "gpt-4o-mini")
        self.assertEqual(art["surface"], "llm-proxy")

    def test_instruction_files_in_context_are_carried(self):
        """The 'what was here already' half: SessionStart's memory scan."""
        art = event_artifacts({
            "type": "memory",
            "content": "# CLAUDE.md",
            "integrity_findings": [{"title": "Instruction file changed", "severity": "HIGH"}],
            "metadata": {"memory_files": ["/repo/CLAUDE.md", "/repo/AGENTS.md"],
                         "has_invisible_controls": True},
        })
        self.assertEqual(art["memory_files"], ["/repo/CLAUDE.md", "/repo/AGENTS.md"])
        self.assertEqual(art["integrity_findings"][0]["severity"], "HIGH")
        self.assertTrue(art["has_invisible_controls"])

    def test_long_capture_is_bounded_and_says_so(self):
        art = event_artifacts({"type": "shell", "command": "x", "stdout": "y" * (_ARTIFACT_CHARS + 500)})
        self.assertLess(len(art["stdout"]), _ARTIFACT_CHARS + 200)
        self.assertIn("more characters", art["stdout"])

    def test_empty_values_are_omitted_not_shown_blank(self):
        art = event_artifacts({"type": "shell", "command": "ls", "stdout": "", "stderr": None})
        self.assertEqual(art["command"], "ls")
        self.assertNotIn("stdout", art)
        self.assertNotIn("stderr", art)

    def test_unknown_event_type_gets_a_lane_rather_than_vanishing(self):
        self.assertEqual(event_lane("shell"), "shell")
        self.assertEqual(event_lane("file_write"), "files")
        self.assertEqual(event_lane("something_new_next_release"), "other")


class TestMergeToolPhases(unittest.TestCase):
    """One tool call is one row, whichever phases the agent logged."""

    def _ev(self, phase, action, ts, **art):
        return {"agentEvent": phase, "type": "shell", "toolTag": "Bash",
                "action": action, "tsAbs": ts, "artifacts": dict(art)}

    def test_pre_and_post_of_one_call_become_one_row(self):
        # Newest first, the order the query returns.
        events = [
            self._ev("PostToolUse", "shell: ls", "2026-01-01T00:00:02", response="a.txt"),
            self._ev("PreToolUse", "shell: ls", "2026-01-01T00:00:01"),
        ]
        merged = _merge_tool_phases(events)
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["phases"], ["PreToolUse", "PostToolUse"])
        # The verdict comes from the pre-call check; the output from the post.
        self.assertEqual(merged[0]["artifacts"]["response"], "a.txt")

    def test_distinct_calls_are_not_folded_together(self):
        events = [
            self._ev("PostToolUse", "shell: b", "2026-01-01T00:00:04"),
            self._ev("PreToolUse", "shell: b", "2026-01-01T00:00:03"),
            self._ev("PostToolUse", "shell: a", "2026-01-01T00:00:02"),
            self._ev("PreToolUse", "shell: a", "2026-01-01T00:00:01"),
        ]
        self.assertEqual(len(_merge_tool_phases(events)), 2)

    def test_a_post_with_no_pre_in_the_window_still_appears(self):
        """The window can cut a pair in half; the call still happened."""
        events = [self._ev("PostToolUse", "shell: ls", "2026-01-01T00:00:02", response="a.txt")]
        merged = _merge_tool_phases(events)
        self.assertEqual(len(merged), 1)
        self.assertNotIn("phases", merged[0])


if __name__ == "__main__":
    unittest.main()
