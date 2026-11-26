"""Crush and OpenHands register PostToolUse and their tool output reaches the event.

Payload shapes are trimmed from live captures (crush v0.102.0, OpenHands CLI
1.16.0). Goose is the negative case: its PostToolUse carries no output.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from prismor.runtime.hooks import (hook_health, install_hooks, normalize_payload,
                                   should_block, uninstall_hooks, _config_path, _read_json)

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("USERPROFILE", str(tmp_path / "home"))
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / "prismor"))


@pytest.mark.parametrize("agent", ["crush", "openhands"])
def test_post_tool_hook_installs_is_healthy_and_uninstalls(agent, tmp_path):
    kw = dict(repo_root=REPO_ROOT, workspace=tmp_path, agent=agent, scope="project")
    install_hooks(mode="enforce", **kw)
    install_hooks(mode="enforce", **kw)  # idempotent
    path = _config_path(agent, "project", tmp_path)
    assert len(_read_json(path)["hooks"]["PostToolUse"]) == 1
    rows = [r for r in hook_health(tmp_path) if r["agent"] == agent and r["scope"] == "project"]
    assert rows and rows[0]["state"] != "fail", rows
    uninstall_hooks(**kw)
    assert "hook-dispatch" not in path.read_text(encoding="utf-8")


def test_goose_registers_no_post_tool_hook(tmp_path):
    install_hooks(repo_root=REPO_ROOT, workspace=tmp_path, agent="goose", scope="project", mode="enforce")
    assert "PostToolUse" not in _read_json(_config_path("goose", "project", tmp_path))["hooks"]


@pytest.mark.parametrize("agent,payload,expected", [
    ("crush", {"event": "PostToolUse", "session_id": "s", "tool_name": "bash",
               "tool_input": {"command": "echo hi"}, "tool_use_id": "c1",
               "tool_response": "hi\n\n<cwd>/p</cwd>"}, "hi\n\n<cwd>/p</cwd>"),
    ("openhands", {"event_type": "PostToolUse", "session_id": "s", "tool_name": "terminal",
                   "tool_input": {"command": "echo hi"},
                   "tool_response": {"content": [{"type": "text", "text": "hi"}], "is_error": False,
                                     "exit_code": 0, "metadata": {"username": "u"}}}, "hi"),
])
def test_output_reaches_event_and_never_blocks(agent, payload, expected, tmp_path):
    event = normalize_payload(agent=agent, payload=payload, workspace=tmp_path)["event"]
    assert (event["type"], event["agent_event"], event["response"]) == ("shell", "PostToolUse", expected)
    # The call already ran; a post-tool finding must not turn into a deny.
    assert should_block([{"mode": "enforce", "action": "block", "severity": "critical"}], event) is None
