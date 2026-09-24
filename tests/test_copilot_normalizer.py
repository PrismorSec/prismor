"""#481: Copilot CLI payloads as captured live from Copilot CLI 1.0.88 (BYOK,
gpt-4.1 + gpt-5.4-mini) with a recorder hook. The old normalizer read only
``toolArgs`` as a JSON string, so every one of these lost its arguments."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from prismor.runtime.hooks import _config_path, _merge_copilot, _normalize_copilot

PATCH_ADD = "*** Begin Patch\n*** Add File: /ws/out.txt\n+created\n*** End Patch\n"

CASES = [
    # PascalCase events (what we register): Claude-shaped tool_input.
    ({"hook_event_name": "PreToolUse", "tool_name": "Bash",
      "tool_input": {"command": "echo probe-shell", "description": "x", "mode": "sync"}},
     {"type": "shell", "command": "echo probe-shell"}),
    ({"hook_event_name": "PreToolUse", "tool_name": "Read", "tool_input": {"path": ".env"}},
     {"type": "file_read", "path": ".env"}),
    ({"hook_event_name": "PreToolUse", "tool_name": "Write",
      "tool_input": {"path": "out2.txt", "file_text": "created"}},
     {"type": "file_write", "path": "out2.txt", "content": "created"}),
    ({"hook_event_name": "PreToolUse", "tool_name": "Edit",
      "tool_input": {"path": "notes.txt", "old_str": "hello", "new_str": "goodbye"}},
     {"type": "file_write", "path": "notes.txt", "content": "goodbye"}),
    ({"hook_event_name": "PreToolUse", "tool_name": "Edit", "tool_input": PATCH_ADD},
     {"type": "file_write", "path": "/ws/out.txt", "content": PATCH_ADD}),
    ({"hook_event_name": "UserPromptSubmit", "prompt": "do the thing"},
     {"type": "prompt", "prompt": "do the thing"}),
    # camelCase events: native tool names, toolArgs as an object or patch text.
    ({"toolName": "bash", "toolArgs": {"command": "echo probe-shell"}},
     {"type": "shell", "command": "echo probe-shell"}),
    ({"toolName": "view", "toolArgs": {"path": "notes.txt"}},
     {"type": "file_read", "path": "notes.txt"}),
    ({"toolName": "create", "toolArgs": {"path": "out2.txt", "file_text": "created"}},
     {"type": "file_write", "path": "out2.txt", "content": "created"}),
    ({"toolName": "apply_patch", "toolArgs": PATCH_ADD},
     {"type": "file_write", "path": "/ws/out.txt"}),
    ({"prompt": "do the thing", "sessionId": "s"},
     {"type": "prompt", "prompt": "do the thing"}),
    # Legacy shape: toolArgs as a JSON string still parses.
    ({"hookEventName": "PreToolUse", "toolName": "bash", "toolArgs": json.dumps({"command": "ls"})},
     {"type": "shell", "command": "ls"}),
]


@pytest.mark.parametrize("payload,expected", CASES)
def test_live_payloads_normalize(payload, expected):
    event = _normalize_copilot(payload, "s1", Path("/ws"))
    assert {k: event.get(k) for k in expected} == expected


def test_install_targets_paths_copilot_loads(tmp_path):
    # Copilot loads only these; the old hooks.json locations were never read.
    assert _config_path("copilot", "project", tmp_path) == tmp_path / ".github" / "hooks" / "prismor.json"
    assert _config_path("copilot", "global", tmp_path).parts[-3:] == (".copilot", "hooks", "prismor.json")


def test_merge_registers_firing_events_and_drops_dead_one():
    cmd = "prismor hook-dispatch --agent copilot"
    merged = _merge_copilot({"hooks": {"UserPromptSubmitted": [{"command": cmd}]}}, cmd)
    assert set(merged["hooks"]) == {"PreToolUse", "PostToolUse", "UserPromptSubmit"}
