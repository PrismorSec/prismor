"""Subagent attribution in the Claude Agent SDK, Agent Framework and Semantic
Kernel adapters. Shapes are the ones live runs produced (claude-agent-sdk
0.2.174 hook input; agent-framework 1.22 / semantic-kernel 1.45 agent-as-tool).
The main agent must never read as a subagent."""
import asyncio
import pathlib
import sys
from types import SimpleNamespace

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
for sub in ("claude-agent-sdk", "agent-framework", "semantic-kernel"):
    sys.path.insert(0, str(ROOT / "adapters" / sub))


def _spy(monkeypatch, module):
    captured = []
    real = module.evaluate_tool_call

    def spy(*, event, **kw):
        captured.append(event["metadata"])
        return real(event=event, **kw)

    monkeypatch.setattr(module, "evaluate_tool_call", spy)
    return captured


def test_claude_agent_sdk_reads_agent_id(tmp_path, monkeypatch):
    import prismor_claude_agent_sdk as m
    seen = _spy(monkeypatch, m)
    hook = m.prismor_pre_tool_use_hook(mode="observe", workspace=tmp_path)
    base = {"tool_name": "mcp__tools__fetch_url", "tool_input": {"url": "https://example.com"}}
    asyncio.run(hook(base, "t1", {}))
    # A session started with --agent: agent_type without agent_id is the main thread.
    asyncio.run(hook({**base, "agent_type": "reviewer"}, "t2", {}))
    asyncio.run(hook({**base, "agent_id": "a5266a9321ef5fb33", "agent_type": "researcher"}, "t3", {}))
    assert [(s["subagent_id"], s["subagent_type"]) for s in seen] == [
        (None, None), (None, None), ("a5266a9321ef5fb33", "researcher")]


def test_agent_framework_agent_as_tool_is_a_subagent(tmp_path, monkeypatch):
    import prismor_agent_framework as m
    seen = _spy(monkeypatch, m)
    main = m.PrismorMiddleware(name="support-bot", mode="observe", workspace=tmp_path)
    sub = m.PrismorMiddleware(name="researcher", mode="observe", workspace=tmp_path)
    ctx = lambda: SimpleNamespace(function=SimpleNamespace(name="fetch_url"), arguments={"url": "x"}, result=None)

    async def run():
        async def nothing():
            return None
        await main.process(ctx(), nothing)          # main agent's own tool

        async def ask_researcher():                  # agent.as_tool(): the sub-agent runs inside
            await sub.process(ctx(), nothing)
        await main.process(ctx(), ask_researcher)

    asyncio.run(run())
    assert seen[0]["subagent_type"] is None
    assert seen[1]["subagent_type"] is None          # ask_researcher, called by the main agent
    assert seen[2]["subagent_type"] == "researcher"
    assert seen[2]["subagent_id"].startswith("support-bot:")


def test_semantic_kernel_agent_as_plugin_is_a_subagent(tmp_path, monkeypatch):
    pytest.importorskip("semantic_kernel")
    import prismor_semantic_kernel as m
    seen = _spy(monkeypatch, m)
    main = m.make_filter(name="support-bot", mode="observe", workspace=tmp_path)
    sub = m.make_filter(name="researcher", mode="observe", workspace=tmp_path)
    ctx = lambda n: SimpleNamespace(function=SimpleNamespace(plugin_name="Fetch", name=n, metadata=None),
                                    arguments={"url": "x"}, function_result=None)

    async def run():
        async def nothing(c):
            return None
        await main(ctx("fetch_url"), nothing)

        async def researcher_plugin(c):
            await sub(ctx("fetch_url"), nothing)
        await main(ctx("researcher"), researcher_plugin)

    asyncio.run(run())
    assert [s["subagent_type"] for s in seen] == [None, None, "researcher"]
