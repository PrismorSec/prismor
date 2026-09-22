"""Tests for the Gemini CLI hooks adapter (strip, _merge_gemini, _normalize_gemini).

Gemini CLI uses the same Claude-style nested hook config shape and exit-2
blocking convention.  These tests verify:
  - stripping    removes Prismor entries and leaves others intact.
  - _merge_gemini  writes all expected events (BeforeTool, AfterTool,
                   SessionStart) with the correct matcher.
  - _normalize_gemini converts every built-in tool name to the right
                   Prismor event type with the right fields.
  - install/uninstall roundtrip writes and then cleanly removes the config.
  - "gemini" appears in _SUPPORTED_AGENTS.
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prismor.runtime.hooks import (
    _SUPPORTED_AGENTS,
    _strip_for_agent,
    _merge_gemini,
    _normalize_gemini,
    install_hooks,
    normalize_payload,
    uninstall_hooks,
)

_MARKER = "hook-dispatch"
_COMMAND = (
    'PYTHONPATH="/repo" python3 -m prismor.runtime.immunity_cli '
    f'{_MARKER} --agent gemini --workspace "/proj" --mode observe'
)


class TestSupportedAgents(unittest.TestCase):
    """Gemini CLI must appear in the _SUPPORTED_AGENTS registry."""

    def test_gemini_in_supported_agents(self):
        self.assertIn("gemini", _SUPPORTED_AGENTS)


# --- stripping -----------------------------------------------------------

class TestStripGemini(unittest.TestCase):
    """Stripping removes Prismor hook entries while preserving others."""

    def _config(self, command):
        return {
            "hooks": {
                "BeforeTool": [
                    {
                        "matcher": "run_shell_command",
                        "hooks": [
                            {"type": "command", "name": "prismor", "command": command},
                            {"type": "command", "name": "other", "command": "other-linter --check"},
                        ],
                    }
                ]
            }
        }

    def test_removes_prismor_entry(self):
        config = self._config(_COMMAND)
        result, removed = _strip_for_agent("gemini", config, _MARKER)
        self.assertTrue(removed)
        before_tool = result["hooks"]["BeforeTool"]
        self.assertEqual(len(before_tool), 1)
        inner = before_tool[0]["hooks"]
        self.assertEqual(len(inner), 1)
        self.assertEqual(inner[0]["name"], "other")

    def test_removes_entire_entry_when_only_prismor(self):
        config = {
            "hooks": {
                "BeforeTool": [
                    {
                        "matcher": "*",
                        "hooks": [{"type": "command", "name": "prismor", "command": _COMMAND}],
                    }
                ]
            }
        }
        result, removed = _strip_for_agent("gemini", config, _MARKER)
        self.assertTrue(removed)
        self.assertEqual(result["hooks"]["BeforeTool"], [])

    def test_no_change_when_marker_absent(self):
        config = {
            "hooks": {
                "BeforeTool": [
                    {"matcher": "*", "hooks": [{"type": "command", "name": "other", "command": "unrelated"}]}
                ]
            }
        }
        result, removed = _strip_for_agent("gemini", config, _MARKER)
        self.assertFalse(removed)

    def test_empty_config(self):
        result, removed = _strip_for_agent("gemini", {}, _MARKER)
        self.assertFalse(removed)
        self.assertEqual(result.get("hooks", {}), {})

    def test_strips_all_event_types(self):
        config = {
            "hooks": {
                event: [
                    {"matcher": "*", "hooks": [{"type": "command", "name": "prismor", "command": _COMMAND}]}
                ]
                for event in ["BeforeTool", "AfterTool", "SessionStart"]
            }
        }
        result, removed = _strip_for_agent("gemini", config, _MARKER)
        self.assertTrue(removed)
        for event in ["BeforeTool", "AfterTool", "SessionStart"]:
            self.assertEqual(result["hooks"][event], [])


# --- _merge_gemini -----------------------------------------------------------

class TestMergeGemini(unittest.TestCase):
    """_merge_gemini inserts the correct hook structure into settings.json."""

    def setUp(self):
        self.result = _merge_gemini({}, _COMMAND)

    def test_before_tool_present(self):
        self.assertIn("BeforeTool", self.result["hooks"])
        self.assertGreater(len(self.result["hooks"]["BeforeTool"]), 0)

    def test_after_tool_present(self):
        self.assertIn("AfterTool", self.result["hooks"])
        self.assertGreater(len(self.result["hooks"]["AfterTool"]), 0)

    def test_session_start_present(self):
        self.assertIn("SessionStart", self.result["hooks"])
        self.assertGreater(len(self.result["hooks"]["SessionStart"]), 0)

    def test_command_contains_marker(self):
        for event_name, entries in self.result["hooks"].items():
            for entry in entries:
                for h in entry.get("hooks", []):
                    self.assertIn(_MARKER, h["command"],
                                  f"hook-dispatch marker missing in {event_name}")

    def test_matcher_covers_shell_tool(self):
        for entry in self.result["hooks"]["BeforeTool"]:
            self.assertIn("run_shell_command", entry.get("matcher", ""))

    def test_matcher_covers_mcp_tools(self):
        for entry in self.result["hooks"]["BeforeTool"]:
            self.assertIn("mcp__", entry.get("matcher", ""))

    def test_hook_type_is_command(self):
        for event_name, entries in self.result["hooks"].items():
            for entry in entries:
                for h in entry.get("hooks", []):
                    self.assertEqual(h.get("type"), "command")

    def test_name_field_is_prismor(self):
        for event_name, entries in self.result["hooks"].items():
            for entry in entries:
                for h in entry.get("hooks", []):
                    self.assertEqual(h.get("name"), "prismor")

    def test_preserves_existing_hooks(self):
        existing = {
            "hooks": {
                "BeforeTool": [
                    {"matcher": "my_tool", "hooks": [{"type": "command", "name": "other", "command": "other-script"}]}
                ]
            }
        }
        result = _merge_gemini(existing, _COMMAND)
        commands = [
            h["command"]
            for e in result["hooks"]["BeforeTool"]
            for h in e.get("hooks", [])
        ]
        self.assertTrue(any("other-script" in c for c in commands))
        self.assertTrue(any(_MARKER in c for c in commands))

    def test_idempotent(self):
        first = _merge_gemini({}, _COMMAND)
        stripped, _ = _strip_for_agent("gemini", first, _MARKER)
        second = _merge_gemini(stripped, _COMMAND)
        prismor_commands = [
            h["command"]
            for entry in second["hooks"].get("BeforeTool", [])
            for h in entry.get("hooks", [])
            if _MARKER in h["command"]
        ]
        self.assertEqual(len(prismor_commands), 1,
                         "hook-dispatch must appear exactly once after strip+re-merge")


# --- _normalize_gemini -------------------------------------------------------

class TestNormalizeGemini(unittest.TestCase):
    """_normalize_gemini maps each Gemini CLI payload to a Prismor event."""

    _WS = Path("/fake/workspace")
    _SID = "gemini-testsession123"

    def _n(self, payload):
        return _normalize_gemini(payload, self._SID, self._WS)

    def test_run_shell_command_before_tool(self):
        event = self._n({
            "hook_event_name": "BeforeTool",
            "tool_name": "run_shell_command",
            "tool_input": {"command": "rm -rf /tmp/test"},
            "cwd": "/fake/workspace",
            "session_id": self._SID,
        })
        self.assertEqual(event["type"], "shell")
        self.assertEqual(event["command"], "rm -rf /tmp/test")
        self.assertEqual(event["agent"], "gemini")
        self.assertEqual(event["agent_event"], "BeforeTool")
        self.assertEqual(event["session_id"], self._SID)

    def test_run_shell_command_carries_stdout(self):
        event = self._n({
            "hook_event_name": "AfterTool",
            "tool_name": "run_shell_command",
            "tool_input": {"command": "ls"},
            "stdout": "file.txt\n",
            "stderr": "",
        })
        self.assertEqual(event["type"], "shell")
        self.assertEqual(event["stdout"], "file.txt\n")

    def test_read_file_absolute_path(self):
        event = self._n({
            "hook_event_name": "BeforeTool",
            "tool_name": "read_file",
            "tool_input": {"absolute_path": "/home/user/.env"},
        })
        self.assertEqual(event["type"], "file_read")
        self.assertEqual(event["path"], "/home/user/.env")

    def test_read_file_fallback_to_file_path(self):
        event = self._n({
            "hook_event_name": "BeforeTool",
            "tool_name": "read_file",
            "tool_input": {"file_path": "src/main.py"},
        })
        self.assertEqual(event["type"], "file_read")
        self.assertEqual(event["path"], "src/main.py")

    def test_write_file(self):
        event = self._n({
            "hook_event_name": "BeforeTool",
            "tool_name": "write_file",
            "tool_input": {"file_path": "output.txt", "content": "hello world"},
        })
        self.assertEqual(event["type"], "file_write")
        self.assertEqual(event["path"], "output.txt")
        self.assertEqual(event["content"], "hello world")

    def test_replace_in_file_uses_diff_field(self):
        event = self._n({
            "hook_event_name": "BeforeTool",
            "tool_name": "replace_in_file",
            "tool_input": {"file_path": "app.py", "diff": "--- a/app.py\n+++ b/app.py"},
        })
        self.assertEqual(event["type"], "file_write")
        self.assertEqual(event["path"], "app.py")
        self.assertEqual(event["content"], "--- a/app.py\n+++ b/app.py")

    def test_web_fetch(self):
        event = self._n({
            "hook_event_name": "BeforeTool",
            "tool_name": "web_fetch",
            "tool_input": {"url": "https://example.com/api"},
        })
        self.assertEqual(event["type"], "network")
        self.assertEqual(event["url"], "https://example.com/api")

    def test_web_search_uses_query_as_url(self):
        event = self._n({
            "hook_event_name": "BeforeTool",
            "tool_name": "web_search",
            "tool_input": {"query": "how to exfiltrate data"},
        })
        self.assertEqual(event["type"], "network")
        self.assertEqual(event["url"], "how to exfiltrate data")

    def test_session_start_returns_memory_type(self):
        event = self._n({
            "hook_event_name": "SessionStart",
            "cwd": str(self._WS),
        })
        self.assertEqual(event["type"], "memory")
        self.assertEqual(event["agent_event"], "SessionStart")

    def test_before_agent_returns_prompt_type(self):
        event = self._n({
            "hook_event_name": "BeforeAgent",
            "prompt": "Refactor this entire codebase",
        })
        self.assertEqual(event["type"], "prompt")
        self.assertEqual(event["prompt"], "Refactor this entire codebase")

    def test_unknown_tool_returns_tool_result(self):
        event = self._n({
            "hook_event_name": "BeforeTool",
            "tool_name": "some_future_tool",
            "tool_input": {},
        })
        self.assertEqual(event["type"], "tool_result")

    def test_metadata_carries_transcript_path(self):
        event = self._n({
            "hook_event_name": "BeforeTool",
            "tool_name": "run_shell_command",
            "tool_input": {"command": "ls"},
            "transcript_path": "/tmp/gemini/session123/transcript.jsonl",
        })
        self.assertEqual(event["metadata"]["transcript_path"],
                         "/tmp/gemini/session123/transcript.jsonl")

    def test_normalize_payload_routes_to_gemini(self):
        result = normalize_payload(
            agent="gemini",
            payload={
                "hook_event_name": "BeforeTool",
                "tool_name": "run_shell_command",
                "tool_input": {"command": "echo hi"},
                "session_id": "gemini-abc",
            },
            workspace=self._WS,
        )
        self.assertEqual(result["event"]["agent"], "gemini")
        self.assertEqual(result["event"]["type"], "shell")


# --- install / uninstall roundtrip -------------------------------------------

class TestGeminiInstallUninstallRoundtrip(unittest.TestCase):
    """install_hooks + uninstall_hooks write and cleanly remove Gemini config."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.workspace = Path(self.tmpdir) / "project"
        self.workspace.mkdir()
        self.repo_root = Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_install_creates_settings_json(self):
        install_hooks(
            repo_root=self.repo_root,
            workspace=self.workspace,
            agent="gemini",
            scope="project",
            mode="observe",
        )
        config_path = self.workspace / ".gemini" / "settings.json"
        self.assertTrue(config_path.exists())
        config = json.loads(config_path.read_text())
        hooks = config.get("hooks", {})
        self.assertIn("BeforeTool", hooks)
        self.assertIn("AfterTool", hooks)
        self.assertIn("SessionStart", hooks)
        self.assertGreater(len(hooks["BeforeTool"]), 0)

    def test_install_contains_marker(self):
        install_hooks(
            repo_root=self.repo_root,
            workspace=self.workspace,
            agent="gemini",
            scope="project",
            mode="observe",
        )
        config_path = self.workspace / ".gemini" / "settings.json"
        self.assertIn(_MARKER, config_path.read_text())

    def test_install_is_idempotent(self):
        for _ in range(2):
            install_hooks(
                repo_root=self.repo_root,
                workspace=self.workspace,
                agent="gemini",
                scope="project",
                mode="observe",
            )
        config_path = self.workspace / ".gemini" / "settings.json"
        config = json.loads(config_path.read_text())
        for event_name, entries in config["hooks"].items():
            prismor_cmds = [
                h["command"]
                for entry in entries
                for h in entry.get("hooks", [])
                if _MARKER in h.get("command", "")
            ]
            self.assertLessEqual(len(prismor_cmds), 1,
                                 f"hook-dispatch duplicated in {event_name}")

    def test_uninstall_clears_hooks(self):
        install_hooks(
            repo_root=self.repo_root,
            workspace=self.workspace,
            agent="gemini",
            scope="project",
            mode="observe",
        )
        results = uninstall_hooks(
            repo_root=self.repo_root,
            workspace=self.workspace,
            agent="gemini",
            scope="project",
        )
        self.assertTrue(results[0]["removed"])
        config_path = self.workspace / ".gemini" / "settings.json"
        config = json.loads(config_path.read_text())
        for entries in config.get("hooks", {}).values():
            if isinstance(entries, list):
                for entry in entries:
                    for h in entry.get("hooks", []):
                        self.assertNotIn(_MARKER, h.get("command", ""))

    def test_install_preserves_existing_settings(self):
        config_path = self.workspace / ".gemini" / "settings.json"
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(json.dumps({
            "theme": "dark",
            "model": "gemini-2.0-flash",
        }))
        install_hooks(
            repo_root=self.repo_root,
            workspace=self.workspace,
            agent="gemini",
            scope="project",
            mode="observe",
        )
        config = json.loads(config_path.read_text())
        self.assertEqual(config.get("theme"), "dark")
        self.assertEqual(config.get("model"), "gemini-2.0-flash")
        self.assertIn("BeforeTool", config.get("hooks", {}))


if __name__ == "__main__":
    unittest.main()
