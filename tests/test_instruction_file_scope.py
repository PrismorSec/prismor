"""Agents that never load CLAUDE.md/AGENTS.md must not be judged by them.

The MCP gateway and the SDK adapters ran the project-memory scan on their first
event, so the operator's ~/.claude/CLAUDE.md blocked benign calls and its text
came back in the deny reason the agent reads.
"""
import pytest

from prismor.runtime import hooks
from prismor.runtime.runtime import _block_reason, evaluate_tool_call


@pytest.mark.parametrize("agent,meta", [
    ("mcp-gateway", {}),
    ("openai-agents", {"framework": "openai-agents"}),
])
def test_gateway_and_sdk_agents_skip_the_instruction_file_scan(monkeypatch, tmp_path, agent, meta):
    scanned = []
    monkeypatch.setattr(hooks, "_read_project_memory",
                        lambda ws: scanned.append(ws) or {"content": "", "files": [], "digests": {}})
    event = {"type": "shell", "command": "ls",
             "metadata": {"tool_name": "run_shell", "cwd": str(tmp_path), **meta}}
    evaluate_tool_call(event=event, workspace=tmp_path, agent=agent, mode="enforce",
                       session_id=f"scope-{agent}", persist=False)
    assert scanned == []


def test_hooked_agents_still_scan(monkeypatch, tmp_path):
    scanned = []
    monkeypatch.setattr(hooks, "_read_project_memory",
                        lambda ws: scanned.append(ws) or {"content": "", "files": [], "digests": {}})
    event = {"type": "shell", "command": "ls", "metadata": {"tool_name": "Bash", "cwd": str(tmp_path)}}
    evaluate_tool_call(event=event, workspace=tmp_path, agent="codex", mode="enforce",
                       session_id="scope-codex", persist=False)
    assert scanned


def test_block_reason_never_quotes_instruction_file_text():
    reason = _block_reason({"severity": "high", "title": "Embedded directive",
                            "source": "project_memory", "evidence": "private operator note"})
    assert "private operator note" not in reason
    assert "instruction file" in reason
