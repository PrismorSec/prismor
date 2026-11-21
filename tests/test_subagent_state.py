"""Subagent attribution and hook-matcher migration.

Concurrent ledger writes from parallel subagents are covered by
test_ledger_concurrency.py.

This file pins down subagent_id/subagent_type attribution: Claude tags
tool calls made inside a spawned subagent with agent_id/agent_type, and the
normalizer/telemetry layer must promote those into metadata.subagent_id /
subagent_type (and the Task/Agent tool itself into a subagent_spawn event) so
the control plane can attribute an action to the subagent that took it.
"""
from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from prismor.runtime.enterprise.telemetry import build_record  # noqa: E402
from prismor.runtime.hooks import _merge_claude_entries, _normalize_claude  # noqa: E402

SESSION = "sess"


class HookMatcherMigration(unittest.TestCase):
    """Re-running install-hooks must widen an existing entry's matcher rather
    than appending a second one."""

    COMMAND = 'PYTHONPATH="/x" "/py" -m prismor.runtime.immunity_cli hook-dispatch --agent claude'
    NEW_MATCHER = "Task|Agent|Bash|Read|Edit|MultiEdit|Write|WebFetch|WebSearch|mcp__.*"

    def _new_entry(self):
        return {
            "matcher": self.NEW_MATCHER,
            "hooks": [{"type": "command", "command": self.COMMAND}],
        }

    def _stale(self):
        return [
            {
                "matcher": "Bash|Write|Edit|MultiEdit|mcp__.*",
                "hooks": [{"type": "command", "command": "some-other-tool"}],
            },
            {
                "matcher": "Bash|Read|Edit|MultiEdit|Write|WebFetch|WebSearch|mcp__.*",
                "hooks": [{"type": "command", "command": self.COMMAND}],
            },
        ]

    def test_stale_matcher_is_widened_in_place(self):
        merged = _merge_claude_entries(self._stale(), self._new_entry())
        ours = [e for e in merged if any(h.get("command") == self.COMMAND for h in e["hooks"])]
        self.assertEqual(len(ours), 1, "dispatcher would fire twice per tool call")
        self.assertEqual(ours[0]["matcher"], self.NEW_MATCHER)

    def test_subagent_spawn_tools_are_matched_after_migration(self):
        merged = _merge_claude_entries(self._stale(), self._new_entry())
        ours = [e for e in merged if any(h.get("command") == self.COMMAND for h in e["hooks"])]
        for tool in ("Task", "Agent"):
            self.assertTrue(
                any(re.fullmatch(e["matcher"], tool) for e in ours),
                f"{tool} spawn would not be screened",
            )

    def test_migration_is_idempotent(self):
        once = _merge_claude_entries(self._stale(), self._new_entry())
        twice = _merge_claude_entries(once, self._new_entry())
        self.assertEqual(once, twice)

    def test_another_tools_entry_is_never_hijacked(self):
        merged = _merge_claude_entries(self._stale(), self._new_entry())
        foreign = [e for e in merged if e["matcher"] == "Bash|Write|Edit|MultiEdit|mcp__.*"]
        self.assertEqual(len(foreign), 1)
        self.assertEqual(foreign[0]["hooks"][0]["command"], "some-other-tool")

    def test_fresh_install_still_appends_new_entry(self):
        """No prior install at all: nothing to migrate, so a plain append."""
        merged = _merge_claude_entries([], self._new_entry())
        self.assertEqual(merged, [self._new_entry()])


class SubagentAttribution(unittest.TestCase):
    """Task/Agent tool calls are classified as subagent_spawn, and inner tool
    calls made inside a spawned subagent carry subagent_id/subagent_type
    through the normalizer into the telemetry record."""

    WORKSPACE = Path("/tmp/workspace")

    def test_task_tool_call_is_classified_as_subagent_spawn(self):
        payload = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Task",
            "tool_input": {
                "subagent_type": "general-purpose",
                "description": "research something",
                "prompt": "go find X",
            },
        }
        event = _normalize_claude(payload, SESSION, self.WORKSPACE)
        self.assertEqual(event["type"], "subagent_spawn")
        self.assertEqual(event["subagent_type"], "general-purpose")
        self.assertEqual(event["description"], "research something")

    def test_inner_tool_call_promotes_agent_id_to_subagent_id(self):
        payload = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "ls"},
            "agent_id": "sub-42",
            "agent_type": "general-purpose",
        }
        event = _normalize_claude(payload, SESSION, self.WORKSPACE)
        self.assertEqual(event["metadata"]["subagent_id"], "sub-42")
        self.assertEqual(event["metadata"]["subagent_type"], "general-purpose")

    def test_main_agent_tool_call_has_no_subagent_id(self):
        payload = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "ls"},
        }
        event = _normalize_claude(payload, SESSION, self.WORKSPACE)
        self.assertIsNone(event["metadata"]["subagent_id"])
        self.assertIsNone(event["metadata"]["subagent_type"])

    def test_telemetry_record_carries_subagent_id_for_inner_call(self):
        event = {
            "type": "shell",
            "metadata": {"tool_name": "Bash", "subagent_id": "sub-42", "subagent_type": "general-purpose"},
        }
        record = build_record(finding={}, event=event, extra={}, full_capture=False)
        self.assertEqual(record["subagent_id"], "sub-42")
        self.assertEqual(record["subagent_type"], "general-purpose")

    def test_telemetry_record_carries_subagent_type_for_spawn_event(self):
        event = {"type": "subagent_spawn", "subagent_type": "general-purpose", "metadata": {}}
        record = build_record(finding={}, event=event, extra={}, full_capture=False)
        self.assertIsNone(record["subagent_id"])
        self.assertEqual(record["subagent_type"], "general-purpose")

    def test_telemetry_record_subagent_id_null_on_main_agent_call(self):
        event = {"type": "shell", "metadata": {"tool_name": "Bash"}}
        record = build_record(finding={}, event=event, extra={}, full_capture=False)
        self.assertIsNone(record["subagent_id"])
        self.assertIsNone(record["subagent_type"])


if __name__ == "__main__":
    unittest.main()
