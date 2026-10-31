"""#259: the event types each hook adapter actually produces.

``event_types`` in registry.yaml is what AGENT_INTEGRATIONS.md shows per agent,
so a rule keyed on a type an agent never emits (``file_read`` on Codex, which
does every read and write through Bash) is visibly inactive there instead of
being advertised as covered.

SAMPLES stands in for what each host sends to the hooks Prismor installs. The
test fails if an adapter produces a type the registry does not declare, or if a
declared type is never produced.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from prismor.runtime.hooks import _SUPPORTED_AGENTS, normalize_payload
from prismor.runtime.integrations.registry import get, load_registry
from prismor.runtime.policy_engine import _DEFAULT_FIELDS

REPO_ROOT = Path(__file__).resolve().parent.parent

MCP = "mcp__github__create_issue"


def _claude_shape(event, tool="", **tool_input):
    return {"hook_event_name": event, "tool_name": tool, "tool_input": tool_input}


def _plugin(tool, event="PreToolUse", **tool_input):
    return {"hookEvent": event, "toolName": tool, "toolInput": tool_input}


SAMPLES = {
    "claude": [
        {"hook_event_name": "SessionStart"},
        {"hook_event_name": "UserPromptSubmit", "prompt": "hi"},
        _claude_shape("PreToolUse", "Task", prompt="review", subagent_type="reviewer"),
        _claude_shape("PreToolUse", "Bash", command="ls"),
        _claude_shape("PostToolUse", "Bash", command="ls"),
        _claude_shape("PreToolUse", "Read", file_path="a.py"),
        _claude_shape("PreToolUse", "Grep", pattern="x", path="."),
        _claude_shape("PreToolUse", "Write", file_path="a.py", content="x"),
        _claude_shape("PreToolUse", "Edit", file_path="a.py", old_string="x", new_string="y"),
        _claude_shape("PreToolUse", "WebFetch", url="https://example.com"),
        _claude_shape("PreToolUse", "Skill", skill="pdf"),
        _claude_shape("PreToolUse", MCP, title="x"),
    ],
    # Captured Codex payloads carry only UserPromptSubmit and Bash: file reads
    # and edits run as shell commands (#259), so file_read/file_write never occur.
    "codex": [
        {"hook_event_name": "UserPromptSubmit", "prompt": "hi"},
        _claude_shape("PreToolUse", "Bash", command="cat notes.txt"),
        _claude_shape("PermissionRequest", "Bash", command="rm -rf build"),
        _claude_shape("PostToolUse", "Bash", command="cat notes.txt"),
    ],
    "cursor": [
        {"hook_event_name": "sessionStart"},
        {"hook_event_name": "beforeSubmitPrompt", "prompt": "hi"},
        {"hook_event_name": "beforeShellExecution", "command": "ls"},
        {"hook_event_name": "afterShellExecution", "command": "ls", "output": "a.py"},
        {"hook_event_name": "beforeReadFile", "file_path": "a.py"},
        {"hook_event_name": "afterFileEdit", "file_path": "a.py",
         "edits": [{"old_string": "x", "new_string": "y"}]},
        {"hook_event_name": "beforeMCPExecution", "tool_name": "create_issue",
         "mcp_server_name": "github", "tool_input": "{}"},
        {"hook_event_name": "beforeMCPExecution", "tool_name": "create_issue",
         "mcp_server_name": "github", "tool_input": "{}", "url": "https://mcp.example.com/mcp"},
        {"hook_event_name": "afterMCPExecution", "tool_name": "create_issue",
         "mcp_server_name": "github", "tool_input": "{}", "result_json": "{}"},
    ],
    "windsurf": [
        {"agent_action_name": "pre_user_prompt", "tool_info": {"prompt": "hi"}},
        {"agent_action_name": "pre_run_command", "tool_info": {"command": "ls"}},
        {"agent_action_name": "post_run_command", "tool_info": {"command": "ls"}},
        {"agent_action_name": "pre_read_code", "tool_info": {"file_path": "a.py"}},
        {"agent_action_name": "pre_write_code",
         "tool_info": {"file_path": "a.py", "edits": [{"new_string": "y"}]}},
        {"agent_action_name": "pre_mcp_tool_use",
         "tool_info": {"server_name": "github", "tool_name": "create_issue", "arguments": {}}},
        {"agent_action_name": "post_cascade_response", "tool_info": {"response": "done"}},
    ],
    "openclaw": [
        _plugin("__message__", "UserPromptSubmit", content="hi"),
        _plugin("exec", command="ls"),
        _plugin("exec", "PostToolUse", command="ls"),
        _plugin("read", path="a.py"),
        _plugin("write", path="a.py", content="x"),
        _plugin("edit", path="a.py", newText="y"),
        _plugin("web_fetch", url="https://example.com"),
        _plugin("process", action="list"),
    ],
    "hermes": [
        _plugin("__message__", "UserPromptSubmit", content="hi"),
        _plugin("terminal", command="ls"),
        _plugin("execute_code", code="print(1)"),
        _plugin("read_file", path="a.py"),
        _plugin("patch", path="a.py", new_string="y"),
        _plugin("web_extract", urls=["https://example.com"]),
        _plugin("todo", todos=[]),
    ],
    "opencode": [
        _plugin("bash", command="ls"),
        _plugin("bash", "PostToolUse", command="ls"),
        _plugin("read", filePath="a.py"),
        _plugin("edit", filePath="a.py", newString="y"),
        _plugin("webfetch", url="https://example.com"),
        _plugin("grep", pattern="x"),
    ],
    "copilot": [
        {"hook_event_name": "UserPromptSubmit", "prompt": "hi"},
        _claude_shape("PreToolUse", "Bash", command="ls"),
        _claude_shape("PreToolUse", "Read", path="a.py"),
        _claude_shape("PreToolUse", "Write", path="a.py", file_text="x"),
        {"toolName": "view", "toolArgs": {"path": "a.py"}},
        {"toolName": "web_fetch", "toolArgs": {"url": "https://example.com"}},
        _claude_shape("PreToolUse", MCP, title="x"),
    ],
    "grok": [
        {"hook_event_name": "UserPromptSubmit", "prompt": "hi"},
        {"hookEventName": "pre_tool_use", "toolName": "run_terminal_command",
         "toolInput": {"command": "ls"}},
        {"hookEventName": "pre_tool_use", "toolName": "read_file",
         "toolInput": {"target_file": "a.py"}},
        {"hookEventName": "pre_tool_use", "toolName": "search_replace",
         "toolInput": {"file_path": "a.py", "replace": "y"}},
        {"hookEventName": "pre_tool_use", "toolName": "web_fetch",
         "toolInput": {"url": "https://example.com"}},
        {"hookEventName": "pre_tool_use", "toolName": MCP, "toolInput": {}},
    ],
    "kiro": [
        {"hook_event_name": "userPromptSubmit", "prompt": "hi"},
        _claude_shape("preToolUse", "execute_bash", command="ls"),
        _claude_shape("preToolUse", "fs_read", operations=[{"mode": "Line", "path": "a.py"}]),
        _claude_shape("preToolUse", "fs_write", command="create", path="a.py", file_text="x"),
        _claude_shape("preToolUse", "web_fetch", url="https://example.com"),
        _claude_shape("preToolUse", "use_aws", service_name="s3"),
    ],
    # Crush dispatches PreToolUse only; there is no prompt hook.
    "crush": [
        {"event": "PreToolUse", "tool_name": "bash", "tool_input": {"command": "ls"}},
        {"event": "PreToolUse", "tool_name": "view", "tool_input": {"path": "a.py"}},
        {"event": "PreToolUse", "tool_name": "edit",
         "tool_input": {"file_path": "a.py", "new_string": "y"}},
        {"event": "PreToolUse", "tool_name": "fetch", "tool_input": {"url": "https://example.com"}},
        {"event": "PreToolUse", "tool_name": "grep", "tool_input": {"pattern": "x"}},
    ],
    # OpenHands' file_editor covers both view and edit, so reads arrive as file_write.
    "openhands": [
        {"event_type": "UserPromptSubmit", "message": "hi"},
        {"event_type": "PreToolUse", "tool_name": "terminal", "tool_input": {"command": "ls"}},
        {"event_type": "PreToolUse", "tool_name": "file_editor",
         "tool_input": {"command": "view", "path": "a.py"}},
        {"event_type": "PreToolUse", "tool_name": "task_tracker", "tool_input": {"command": "view"}},
    ],
    "qwen": [
        {"hook_event_name": "UserPromptSubmit", "prompt": "hi"},
        _claude_shape("PreToolUse", "run_shell_command", command="ls"),
        _claude_shape("PreToolUse", "read_file", file_path="a.py"),
        _claude_shape("PreToolUse", "write_file", file_path="a.py", content="x"),
        _claude_shape("PreToolUse", "web_fetch", url="https://example.com"),
        _claude_shape("PreToolUse", MCP, title="x"),
    ],
    # Only the tools in Continue's install matcher reach the hook.
    "continue": [
        {"hook_event_name": "UserPromptSubmit", "prompt": "hi"},
        _claude_shape("PreToolUse", "Bash", command="ls"),
        _claude_shape("PreToolUse", "Read", file_path="a.py"),
        _claude_shape("PreToolUse", "Edit", file_path="a.py", new_string="y"),
        _claude_shape("PreToolUse", "Fetch", url="https://example.com"),
    ],
    "goose": [
        {"event": "UserPromptSubmit", "message": "hi"},
        {"event": "PreToolUse", "tool_name": "shell", "tool_input": {"command": "ls"}},
        {"event": "PreToolUse", "tool_name": "write", "tool_input": {"path": "a.py", "content": "x"}},
        {"event": "PreToolUse", "tool_name": "edit", "tool_input": {"path": "a.py", "after": "y"}},
        {"event": "PreToolUse", "tool_name": "tree", "tool_input": {"path": "."}},
    ],
    # Gemini's BeforeAgent (prompt) hook is not installed.
    "gemini": [
        {"hook_event_name": "SessionStart"},
        _claude_shape("BeforeTool", "run_shell_command", command="ls"),
        _claude_shape("AfterTool", "run_shell_command", command="ls"),
        _claude_shape("BeforeTool", "read_file", absolute_path="/w/a.py"),
        _claude_shape("BeforeTool", "replace", file_path="a.py", new_string="y"),
        _claude_shape("BeforeTool", "google_web_search", query="x"),
        _claude_shape("BeforeTool", MCP, title="x"),
    ],
    # Antigravity dispatches PreToolUse only; there is no prompt hook.
    "antigravity": [
        {"toolCall": {"name": "run_command", "args": {"CommandLine": "ls"}}},
        {"toolCall": {"name": "view_file", "args": {"AbsolutePath": "/w/a.py"}}},
        {"toolCall": {"name": "write_to_file", "args": {"TargetFile": "/w/a.py", "CodeContent": "x"}}},
        {"toolCall": {"name": "read_url_content", "args": {"Url": "https://example.com"}}},
        {"toolCall": {"name": "call_mcp_tool",
                      "args": {"ServerName": "github", "ToolName": "create_issue", "Arguments": "{}"}}},
    ],
}


@pytest.mark.parametrize("agent", _SUPPORTED_AGENTS)
def test_adapter_produces_exactly_the_declared_event_types(agent, tmp_path):
    declared = set(get(agent).event_types)
    assert declared, f"{agent}: add event_types to registry.yaml"
    produced = {
        normalize_payload(agent=agent, payload=payload, workspace=tmp_path)["event"]["type"]
        for payload in SAMPLES[agent]
    }
    assert not produced - declared, f"{agent}: produces undeclared {sorted(produced - declared)}"
    assert not declared - produced, f"{agent}: declares {sorted(declared - produced)} but never produces it"


def test_declared_event_types_are_ones_the_policy_engine_knows():
    schema = json.loads(
        (REPO_ROOT / "prismor/runtime/integrations/registry.schema.json").read_text()
    )
    allowed = set(schema["definitions"]["integration"]["properties"]["event_types"]["items"]["enum"])
    assert allowed <= set(_DEFAULT_FIELDS)
    for entry in load_registry():
        assert set(entry.event_types) <= allowed, entry.id
