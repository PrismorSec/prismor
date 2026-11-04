"""Normalizers read the payload keys each agent actually sends (verified against
upstream docs/source 2026-11-03), so the command, path, URL or MCP name that
policy screens is never empty."""

import tempfile
import unittest
from pathlib import Path

from prismor.runtime.hooks import (
    _CLAUDE_TOOL_MATCHER,
    _normalize_claude,
    _normalize_crush,
    _normalize_gemini,
    _normalize_grok,
    _normalize_openhands,
    _normalize_windsurf,
)
from prismor.runtime.policy_engine import PolicyEngine

WS = Path(".")


def _ids(event):
    with tempfile.TemporaryDirectory() as tmp:
        eng = PolicyEngine(workspace=Path(tmp))
        return {f["ruleId"] for f in eng.evaluate(event, index=0)}


class TestWindsurf(unittest.TestCase):
    def test_documented_keys(self):
        shell = _normalize_windsurf({"agent_action_name": "pre_run_command",
                                     "tool_info": {"command_line": "cat ~/.aws/credentials"}}, "s", WS)
        self.assertEqual(shell["command"], "cat ~/.aws/credentials")
        prompt = _normalize_windsurf({"agent_action_name": "pre_user_prompt",
                                      "tool_info": {"user_prompt": "hello"}}, "s", WS)
        self.assertEqual(prompt["prompt"], "hello")
        mcp = _normalize_windsurf({"agent_action_name": "pre_mcp_tool_use", "tool_info": {
            "mcp_server_name": "github", "mcp_tool_name": "create_issue",
            "mcp_tool_arguments": {"title": "x"}}}, "s", WS)
        self.assertEqual((mcp["mcp_server"], mcp["mcp_tool"]), ("github", "create_issue"))
        self.assertIn('"title"', mcp["response"])

    def test_legacy_keys_still_work(self):
        shell = _normalize_windsurf({"agent_action_name": "pre_run_command",
                                     "tool_info": {"command": "ls"}}, "s", WS)
        self.assertEqual(shell["command"], "ls")


class TestClaude(unittest.TestCase):
    def test_powershell_is_shell(self):
        ev = _normalize_claude({"hook_event_name": "PreToolUse", "tool_name": "PowerShell",
                                "tool_input": {"command": "Remove-Item -Recurse C:\\"}}, "s", WS)
        self.assertEqual(ev["type"], "shell")
        self.assertIn("Remove-Item", ev["command"])

    def test_notebook_edit_is_write(self):
        ev = _normalize_claude({"hook_event_name": "PreToolUse", "tool_name": "NotebookEdit",
                                "tool_input": {"notebook_path": "/w/a.ipynb", "new_source": "print(1)"}}, "s", WS)
        self.assertEqual((ev["type"], ev["path"], ev["content"]), ("file_write", "/w/a.ipynb", "print(1)"))

    def test_matcher_covers_new_tools(self):
        names = _CLAUDE_TOOL_MATCHER.split("|")
        self.assertIn("PowerShell", names)
        self.assertIn("NotebookEdit", names)


class TestGemini(unittest.TestCase):
    def test_web_fetch_urls_from_prompt(self):
        ev = _normalize_gemini({"hook_event_name": "BeforeTool", "tool_name": "web_fetch", "tool_input": {
            "prompt": "Summarize https://a.example/x and https://b.example/y"}}, "s", WS)
        self.assertEqual(ev["type"], "network")
        self.assertEqual(ev["url"].split("\n"), ["https://a.example/x", "https://b.example/y"])

    def test_mcp_from_context(self):
        ev = _normalize_gemini({"hook_event_name": "BeforeTool", "tool_name": "mcp_my_srv_do_thing",
                                "tool_input": {"q": 1},
                                "mcp_context": {"server_name": "my_srv", "tool_name": "do_thing"}}, "s", WS)
        self.assertEqual((ev["mcp_server"], ev["mcp_tool"]), ("my_srv", "do_thing"))

    def test_remote_mcp_from_context_url_is_network(self):
        ev = _normalize_gemini({"hook_event_name": "BeforeTool", "tool_name": "mcp_r_t", "tool_input": {},
                                "mcp_context": {"server_name": "r", "tool_name": "t",
                                                "url": "https://mcp.example/sse"}}, "s", WS)
        self.assertEqual((ev["type"], ev["url"]), ("network", "https://mcp.example/sse"))


class TestGrok(unittest.TestCase):
    def test_qualified_mcp_name(self):
        ev = _normalize_grok({"hook_event_name": "PreToolUse", "toolName": "linear__save_issue",
                              "toolInput": {"title": "x"}}, "s", WS)
        self.assertEqual((ev["mcp_server"], ev["mcp_tool"]), ("linear", "save_issue"))

    def test_post_tool_result_key(self):
        ev = _normalize_grok({"hook_event_name": "PostToolUse", "toolName": "linear__save_issue",
                              "toolInput": {}, "toolResult": "created ISSUE-1"}, "s", WS)
        self.assertEqual(ev["type"], "tool_result")
        self.assertIn("ISSUE-1", ev["response"])


class TestCrushOpenHands(unittest.TestCase):
    def test_crush_view_file_path(self):
        ev = _normalize_crush({"event": "PreToolUse", "tool_name": "view",
                               "tool_input": {"file_path": "/home/u/.aws/credentials"}}, "s")
        self.assertEqual(ev["path"], "/home/u/.aws/credentials")
        self.assertIn("secret-access", _ids(ev))

    def test_openhands_view_is_read(self):
        ev = _normalize_openhands({"event_type": "PreToolUse", "tool_name": "file_editor",
                                   "tool_input": {"command": "view", "path": "/w/a.py"}}, "s")
        self.assertEqual((ev["type"], ev["path"]), ("file_read", "/w/a.py"))

    def test_openhands_create_content(self):
        ev = _normalize_openhands({"event_type": "PreToolUse", "tool_name": "file_editor", "tool_input": {
            "command": "create", "path": "/w/b.py", "file_text": "x = 1"}}, "s")
        self.assertEqual((ev["type"], ev["content"]), ("file_write", "x = 1"))


class TestSubagentsAndMisc(unittest.TestCase):
    def test_codex_spawn_agent(self):
        from prismor.runtime.hooks import _normalize_codex
        ev = _normalize_codex({"hook_event_name": "PreToolUse", "tool_name": "spawn_agent", "tool_input": {
            "message": "audit the repo", "task_name": "audit", "agent_type": "explorer"}}, "s", WS)
        self.assertEqual((ev["type"], ev["prompt"], ev["subagent_type"], ev["description"]),
                         ("subagent_spawn", "audit the repo", "explorer", "audit"))

    def test_codex_spawn_agent_items(self):
        from prismor.runtime.hooks import _normalize_codex
        ev = _normalize_codex({"hook_event_name": "PreToolUse", "tool_name": "spawn_agent",
                               "tool_input": {"items": [{"type": "text", "text": "do x"}]}}, "s", WS)
        self.assertEqual(ev["prompt"], "do x")

    def test_codex_matcher_fires_for_spawn_agent(self):
        import re
        from prismor.runtime.hooks import _merge_codex
        m = _merge_codex({}, "x")["hooks"]["PreToolUse"][0]["matcher"]
        self.assertTrue(re.fullmatch(m, "spawn_agent"))

    def test_qwen_agent_and_subagent_id(self):
        from prismor.runtime.hooks import _normalize_qwen
        ev = _normalize_qwen({"hook_event_name": "PreToolUse", "tool_name": "agent", "tool_input": {
            "description": "d", "prompt": "p", "subagent_type": "fork"}}, "s", WS)
        self.assertEqual((ev["type"], ev["prompt"], ev["subagent_type"]), ("subagent_spawn", "p", "fork"))
        inner = _normalize_qwen({"hook_event_name": "PreToolUse", "tool_name": "read_file", "agent_id": "sub-1",
                                 "agent_type": "fork", "tool_input": {"file_path": "/a"}}, "s", WS)
        self.assertEqual(inner["metadata"]["subagent_id"], "sub-1")

    def test_copilot_camel_post_is_post(self):
        from prismor.runtime.hooks import _normalize_copilot
        ev = _normalize_copilot({"toolName": "mcp__srv__t", "toolArgs": {"a": 1},
                                 "toolResult": "RESULT"}, "s", WS)
        self.assertEqual(ev["type"], "tool_result")
        self.assertIn("RESULT", ev["response"])

    def test_kiro_v3_prompt(self):
        from prismor.runtime.hooks import _normalize_kiro
        ev = _normalize_kiro({"hook_event_name": "UserPromptSubmit", "prompt": "hi"}, "s", WS)
        self.assertEqual((ev["type"], ev["prompt"]), ("prompt", "hi"))

    def test_continue_search_is_local(self):
        from prismor.runtime.hooks import _normalize_continue
        ev = _normalize_continue({"hook_event_name": "PreToolUse", "tool_name": "Search",
                                  "tool_input": {"query": "TODO"}}, "s", WS)
        self.assertEqual(ev["type"], "file_read")

    def test_antigravity_search_web_not_a_url(self):
        from prismor.runtime.hooks import _normalize_antigravity
        ev = _normalize_antigravity({"toolCall": {"name": "search_web", "args": {"query": "rust async"}}}, "s", WS)
        self.assertEqual((ev["type"], ev["url"], ev["query"]), ("network", "", "rust async"))

    def test_mcp_server_name_with_double_underscore(self):
        from prismor.runtime import hooks
        with tempfile.TemporaryDirectory() as tmp:
            hooks._mcp_index_cache[str(Path(tmp))] = {"my__srv": {}}
            try:
                ev = _normalize_claude({"hook_event_name": "PreToolUse", "tool_name": "mcp__my__srv__do_thing",
                                        "tool_input": {}}, "s", Path(tmp))
            finally:
                hooks._mcp_index_cache.pop(str(Path(tmp)), None)
        self.assertEqual((ev["mcp_server"], ev["mcp_tool"]), ("my__srv", "do_thing"))


if __name__ == "__main__":
    unittest.main()
