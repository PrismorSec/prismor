"""Subagent attribution in the Google ADK adapter. Shapes from a live ADK 2.13
run: a transfer to a sub_agent keeps the invocation (active agent is not its
root_agent); an AgentTool runs its agent as a new invocation where it is its
own root, recognised by running inside the parent's AgentTool.run_async."""
import asyncio
from types import SimpleNamespace
from unittest.mock import patch

import prismor_google_adk as adk
from prismor.runtime.runtime import Decision
from prismor.runtime.subagent_context import nested_subagent


def _agent(name, root=None):
    a = SimpleNamespace(name=name)
    a.root_agent = root or a
    return a


def _ctx(agent, inv, call):
    return SimpleNamespace(agent_name=agent.name, invocation_id=inv, function_call_id=call,
                           _invocation_context=SimpleNamespace(agent=agent))


class AgentTool:
    """Stand-in: run_async runs the wrapped agent, whose tools hit the callback."""
    name = "Summarizer"

    def __init__(self, inner):
        self.inner = inner

    async def run_async(self, *, args, tool_context):
        return self.inner()


def _spy(seen):
    return patch("prismor_google_adk.evaluate_tool_call",
                 lambda *, event, **kw: seen.append(event["metadata"]) or Decision(allow=True))


def test_root_transfer_and_agent_tool(tmp_path):
    seen = []
    with _spy(seen):
        before = adk.make_before_tool_callback(workspace=tmp_path, mode="enforce")
        coordinator = _agent("Coordinator")
        fetch = SimpleNamespace(name="fetch_url")

        before(fetch, {"url": "a"}, _ctx(coordinator, "e-1", "c1"))            # root agent
        researcher = _agent("Researcher", root=coordinator)
        before(fetch, {"url": "b"}, _ctx(researcher, "e-1", "c2"))             # transferred to
        tool = AgentTool(lambda: before(fetch, {"url": "c"}, _ctx(_agent("Summarizer"), "e-2", "c4")))
        outer = _ctx(coordinator, "e-1", "c3")
        before(tool, {"request": "x"}, outer)                                  # launches the AgentTool
        asyncio.run(tool.run_async(args={}, tool_context=outer))               # ADK runs it
        before(fetch, {"url": "d"}, _ctx(coordinator, "e-1", "c5"))            # root again

    types = [m["subagent_type"] for m in seen]
    assert types == [None, "Researcher", None, "Summarizer", None]
    assert seen[3]["subagent_id"] == "Coordinator:e-1#c3"
    assert seen[1]["subagent_id"] == "Researcher:e-1"


def test_agent_tool_leaves_no_context_behind(tmp_path):
    """Only a before-callback installed (the documented setup) and the agent
    run failing: later calls, in any invocation, are still the root agent's."""
    seen = []

    def boom():
        raise RuntimeError("sub-agent failed")

    with _spy(seen):
        before = adk.make_before_tool_callback(workspace=tmp_path, mode="enforce")
        coordinator = _agent("Coordinator")
        tool, outer = AgentTool(boom), _ctx(coordinator, "e-9", "c1")
        before(tool, {}, outer)
        try:
            asyncio.run(tool.run_async(args={}, tool_context=outer))
        except RuntimeError:
            pass
        before(SimpleNamespace(name="fetch_url"), {}, _ctx(coordinator, "e-10", "c2"))
    assert seen[1]["subagent_type"] is None
    assert nested_subagent("x") == (None, None)


def test_plugin_guards_agent_tool_without_plugins(tmp_path):
    """AgentTool(include_plugins=False) runs its agent on a Runner without the
    plugin; the plugin puts its callbacks on that agent tree instead."""
    seen = []
    with _spy(seen):
        plugin = adk.PrismorPlugin(workspace=tmp_path, mode="enforce")
        mine = lambda *a: None
        leaf = SimpleNamespace(name="Leaf", before_tool_callback=None, after_tool_callback=None, sub_agents=[])
        inner = SimpleNamespace(name="Summarizer", before_tool_callback=mine, after_tool_callback=None,
                                sub_agents=[leaf])
        tool = AgentTool(lambda: None)
        tool.agent, tool.include_plugins = inner, False
        ctx = _ctx(_agent("Coordinator"), "e-1", "c1")
        asyncio.run(plugin.before_tool_callback(tool=tool, tool_args={}, tool_context=ctx))
        asyncio.run(plugin.before_tool_callback(tool=tool, tool_args={}, tool_context=ctx))  # idempotent

    assert inner.before_tool_callback == [plugin._before, mine]
    assert leaf.before_tool_callback == [plugin._before] and leaf.after_tool_callback == [plugin._after]

    tool2 = AgentTool(lambda: None)
    tool2.agent = SimpleNamespace(name="X", before_tool_callback=None, after_tool_callback=None, sub_agents=[])
    tool2.include_plugins = True
    with _spy([]):
        asyncio.run(plugin.before_tool_callback(tool=tool2, tool_args={}, tool_context=ctx))
    assert tool2.agent.before_tool_callback is None  # the plugin reaches it; no double screening
