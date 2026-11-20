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


def test_wire_context_names_only_and_throttled(tmp_path, monkeypatch):
    from prismor.runtime import token_usage as tu
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path))
    monkeypatch.setattr(tu.store, "prismor_home", lambda: tmp_path)
    path = _write(tmp_path / "t.jsonl", [
        {"type": "user", "message": {"content": "my secret plan"}}, _turn("m1", 0, 0, 1000)])
    monkeypatch.setattr(tu, "find_transcript", lambda sid: Path(path))
    wire = tu._wire_context("s1")
    assert wire["used"] == 1000 and "my secret plan" not in json.dumps(wire)
    assert {p["key"]: p for p in wire["parts"]}["messages"]["items"] == [{"name": "Prompt", "tokens": 3}]
    assert tu._wire_context("s1") is None   # within the minute


def test_new_usage_ticks_the_heartbeat(monkeypatch, tmp_path):
    """Usage only lands in the spool; without a tick an unmanaged workspace
    never uploaded it (the heartbeat runs per call for managed repos only)."""
    from prismor.runtime import token_usage as tu
    from prismor.runtime.enterprise import heartbeat
    ticks = []
    monkeypatch.setattr(heartbeat, "maybe_flush", lambda *a, **k: ticks.append(1))
    monkeypatch.setattr(tu, "_spool_usage", lambda *a, **k: None)
    monkeypatch.setattr(tu.store, "record_token_usages", lambda ws, sid, rows: [True] * len(rows))
    row = {"message_id": "m", "model": "x", "input_tokens": 1, "output_tokens": 1, "cache_read_tokens": 0,
           "cache_creation_tokens": 0, "cache_1h_tokens": 0}
    tu._record_many(tmp_path, "s", "claude", [row])
    assert ticks == [1]
    monkeypatch.setattr(tu.store, "record_token_usages", lambda ws, sid, rows: [False] * len(rows))
    tu._record_many(tmp_path, "s", "claude", [row])
    assert ticks == [1]   # nothing new, no tick


def _turn_m(mid, model, size):
    return {"type": "assistant", "message": {"id": mid, "model": model, "usage": {
        "input_tokens": 0, "output_tokens": 1, "cache_read_input_tokens": size, "cache_creation_input_tokens": 0}}}


def test_window_sources_in_order(monkeypatch):
    from prismor.runtime import token_usage as tu
    monkeypatch.setattr(tu, "price_for", lambda m, fetch=True: {"max_input_tokens": 272000} if m == "gpt-x" else None)
    assert tu._context_window("gpt-x", 10, compact_at=150000) == (150000, "agent setting")
    assert tu._context_window("gpt-x", 10) == (272000, "model card")
    assert tu._context_window("claude-y[1m]", 10) == (1_000_000, "model id")
    assert tu._context_window("unknown", 10) == (200_000, "default")
    assert tu._context_window("gpt-x", 300_000) == (400_000, "observed")   # a turn held more: next tier


def test_model_switch_uses_new_models_window_and_peak(tmp_path, monkeypatch):
    from prismor.runtime import token_usage as tu
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path))
    monkeypatch.setattr(tu, "price_for", lambda m, fetch=True: {"max_input_tokens": {"big": 1_000_000, "small": 200_000}[m]})
    path = _write(tmp_path / "t.jsonl", [_turn_m("a", "big", 500_000), _turn_m("b", "big", 600_000), _turn_m("c", "small", 90_000)])
    ctx = session_context("ignored", path)
    assert (ctx["model"], ctx["limit"], ctx["limit_source"]) == ("small", 200_000, "model card")  # not bumped by big's 600K peak
    assert ctx["models"] == [{"model": "big", "from_turn": 1, "turns": 2, "peak": 600_000},
                             {"model": "small", "from_turn": 3, "turns": 1, "peak": 90_000}]


def test_overhead_recalibrates_when_tools_change(tmp_path, monkeypatch):
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path))
    small = {"type": "prompt_snapshot", "systemPrompt": ["x" * 400], "tools": []}
    big = {"type": "prompt_snapshot", "systemPrompt": ["x" * 400], "tools": [{"name": "mcp__s__t", "server": "s", "description": "m" * 40000}]}
    path = _write(tmp_path / "t.jsonl", [
        {"type": "attachment", "attachment": small}, _turn("m1", 0, 0, 200),
        {"type": "attachment", "attachment": big}, _turn("m2", 0, 0, 12000)])
    parts = {p["key"]: p["tokens"] for p in session_context("ignored", path)["parts"]}
    assert parts["mcp_tools"] > 9000   # sized against the turn after the new tools, not the 200-token first turn


def test_subagents_listed_in_own_windows(tmp_path, monkeypatch):
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path))
    main = tmp_path / "s1.jsonl"
    _write(main, [
        {"type": "assistant", "message": {"content": [{"type": "tool_use", "id": "u1", "name": "Agent",
                                                         "input": {"description": "Find the bug", "subagent_type": "Explore", "prompt": "p"}}]}},
        {"type": "user", "toolUseResult": {"agentId": "abc", "description": "Find the bug"},
         "message": {"content": [{"type": "tool_result", "tool_use_id": "u1", "content": "done"}]}},
        _turn("m1", 0, 0, 5000)])
    (tmp_path / "s1" / "subagents").mkdir(parents=True)
    _write(tmp_path / "s1" / "subagents" / "agent-abc.jsonl", [
        {**_turn_m("x1", "claude-x", 40_000), "isSidechain": True}, {**_turn_m("x2", "claude-x", 70_000), "isSidechain": True}])
    ctx = session_context("ignored", str(main))
    assert ctx["used"] == 5000                     # the subagent's 70K is not in the main window
    assert ctx["subagents"] == [{"id": "abc", "type": "Explore", "description": "Find the bug", "model": "claude-x",
                                 "used": 70_000, "peak": 70_000, "limit": 200_000, "limit_source": "default", "turns": 2}]
    names = [i["name"] for p in ctx["parts"] if p["key"] == "messages" for i in p["items"]]
    assert "Subagent result" in names              # what it handed back is counted in the main window


def test_mcp_and_agent_deltas_keep_current_set(tmp_path, monkeypatch):
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path))
    add = {"type": "mcp_instructions_delta", "addedNames": ["a", "b"], "addedBlocks": ["## a\n" + "x" * 400, "## b\n" + "y" * 400]}
    again = {"type": "mcp_instructions_delta", "addedNames": ["a"], "addedBlocks": ["## a\n" + "x" * 400], "removedNames": ["b"]}
    agents = {"type": "agent_listing_delta", "addedTypes": ["Explore"], "addedLines": ["- Explore: " + "z" * 200]}
    path = _write(tmp_path / "t.jsonl", [
        {"type": "attachment", "attachment": add}, {"type": "attachment", "attachment": agents},
        {"type": "attachment", "attachment": again}, {"type": "attachment", "attachment": agents},  # re-announced after a compaction
        _turn("m1", 0, 0, 100_000)])
    parts = {p["key"]: p for p in session_context("ignored", path)["parts"]}
    assert [i["name"] for i in parts["mcp_instructions"]["items"]] == ["a"]   # b removed, a not doubled
    assert [i["name"] for i in parts["agents"]["items"]] == ["Explore"]
