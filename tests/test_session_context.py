"""session_context: what fills a session's context window, from its transcript."""
from __future__ import annotations

import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

from prismor.runtime.token_usage import session_context  # noqa: E402


def _turn(mid, inp, read, write, sidechain=False):
    return {"type": "assistant", "isSidechain": sidechain, "message": {"id": mid, "model": "claude-x", "usage": {
        "input_tokens": inp, "output_tokens": 5, "cache_read_input_tokens": read, "cache_creation_input_tokens": write}}}


def _write(path, lines):
    path.write_text("".join(json.dumps(x) + "\n" for x in lines))
    return str(path)


def test_claude_parts_add_up_to_measured_size(tmp_path, monkeypatch):
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path))
    (tmp_path / "settings.json").write_text(json.dumps({"modelSettings": {"claude-x": {"autoCompactWindow": 400000}}}))
    snap = {"type": "prompt_snapshot", "systemPrompt": ["x" * 4000],
            "tools": [{"name": "Bash", "description": "d" * 3990}, {"name": "mcp__s__t", "server": "s", "description": "m" * 1990}]}
    path = _write(tmp_path / "t.jsonl", [
        {"type": "attachment", "attachment": snap},
        {"type": "attachment", "attachment": {"type": "instructions", "files": [{"path": "/a/CLAUDE.md", "content": "c" * 800}]}},
        _turn("m1", 3, 0, 5000),
        _turn("m1", 3, 0, 5000),               # same message, second content block
        _turn("sub", 1, 0, 90000, sidechain=True),  # subagent window, not ours
        {"type": "assistant", "message": {"content": [{"type": "tool_use", "id": "u1", "name": "Bash", "input": {"command": "ls"}}]}},
        {"type": "user", "message": {"content": [{"type": "tool_result", "tool_use_id": "u1", "content": [{"type": "image", "source": {"data": "A" * 99999}}]}]}},
        _turn("m2", 2, 5000, 3000),
    ])
    ctx = session_context("ignored", path)
    assert ctx["used"] == 8002 and ctx["first"] == 5003 and ctx["turns"] == 2
    assert ctx["limit"] == ctx["compact_at"] == 400000
    parts = {p["key"]: p["tokens"] for p in ctx["parts"]}
    assert parts["system_prompt"] == 1000 and parts["memory"] == 200
    assert parts["mcp_tools"] < parts["system_tools"]
    assert sum(parts.values()) == ctx["used"]          # rows always add up to the measured size
    msgs = {p["key"]: p for p in ctx["parts"]}["messages"]["items"]
    assert msgs[0]["name"] == "Bash result" and msgs[0]["detail"] == "ls" and msgs[0]["tokens"] == 1600  # image, not base64 length
    by_key = {p["key"]: p for p in ctx["parts"]}
    assert by_key["mcp_tools"]["items"][0] == {"name": "mcp__s__t", "detail": "s", "tokens": by_key["mcp_tools"]["items"][0]["tokens"]}
    assert by_key["memory"]["items"][0]["name"] == "/a/CLAUDE.md"


def test_overhead_estimate_is_capped_at_first_turn(tmp_path, monkeypatch):
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path))
    snap = {"type": "prompt_snapshot", "systemPrompt": ["x" * 400000], "tools": []}
    path = _write(tmp_path / "t.jsonl", [{"type": "attachment", "attachment": snap}, _turn("m1", 0, 0, 1000)])
    ctx = session_context("ignored", path)
    assert ctx["limit"] == 200000 and ctx["compact_at"] is None
    assert sum(p["tokens"] for p in ctx["parts"]) == 1000


def test_codex_reads_window_from_rollout(tmp_path):
    def tc(total, window):
        return {"type": "event_msg", "payload": {"type": "token_count", "info": {
            "model_context_window": window, "last_token_usage": {"total_tokens": total}}}}
    path = _write(tmp_path / "rollout-x.jsonl", [
        {"type": "turn_context", "payload": {"model": "gpt-x"}}, tc(1000, 272000), tc(1000, 272000), tc(4000, 272000)])
    ctx = session_context("ignored", path)
    assert (ctx["used"], ctx["limit"], ctx["turns"], ctx["model"]) == (4000, 272000, 2, "gpt-x")
    assert [p["tokens"] for p in ctx["parts"]] == [1000, 3000]


def test_unknown_without_transcript(tmp_path):
    assert session_context("nope", str(tmp_path / "missing.jsonl")) == {"known": False}
