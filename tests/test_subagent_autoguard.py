"""Guarding the main agent covers the agents it runs: an unguarded subagent
would run its tools with no policy at all (Agno teams, LlamaIndex
AgentWorkflow, BeeAI handoff targets)."""
import pytest


def test_agno_guard_team_hooks_every_member():
    pytest.importorskip("agno")
    from agno.agent import Agent
    from agno.team import Team
    from prismor_agno import guard_team

    a, b, c = Agent(name="a"), Agent(name="b"), Agent(name="c")
    inner = Team(name="inner", members=[c])
    team = Team(name="lead", members=[a, b, inner])
    guard_team(team, mode="enforce")
    hooks = [n.tool_hooks for n in (team, a, b, inner, c)]
    assert all(h and len(h) == 1 for h in hooks)
    assert len({id(h[0]) for h in hooks}) == 1   # one hook: one set of controls
    guard_team(team, mode="enforce")              # idempotent per hook instance
    assert len(team.tool_hooks) == 2              # a second guard call adds its own hook


def test_llamaindex_guard_workflow_guards_every_agent(tmp_path):
    pytest.importorskip("llama_index.core")
    from llama_index.core.agent.workflow import AgentWorkflow, FunctionAgent
    from llama_index.core.llms.mock import MockLLM
    from prismor_llamaindex import guard_workflow

    def fetch_url(url: str) -> str:
        """Fetch a URL."""
        return "ok"

    def lookup(q: str) -> str:
        """Look something up."""
        return "ok"

    llm = MockLLM()
    root = FunctionAgent(name="root", description="r", tools=[fetch_url], llm=llm, can_handoff_to=["researcher"])
    researcher = FunctionAgent(name="researcher", description="s", tools=[lookup], llm=llm)
    wf = AgentWorkflow(agents=[root, researcher], root_agent="root")
    guard_workflow(wf, workspace=tmp_path)
    for agent in wf.agents.values():
        assert agent.tools and all(getattr(t, "__prismor_guarded__", False) for t in agent.tools)


def test_beeai_guarded_handoff_guards_its_target(tmp_path):
    pytest.importorskip("beeai_framework")
    from types import SimpleNamespace
    from beeai_framework.tools import tool
    import prismor_beeai as pb

    @tool
    def fetch_url(url: str) -> str:
        """Fetch a URL."""
        return "ok"

    class Handoff:
        name = "researcher"
        _target = SimpleNamespace(meta=SimpleNamespace(name="Researcher"), _tools=[fetch_url])

        async def _run(self, input, options, context):
            return "ok"

        async def clone(self):
            return self

    pb.guard_tool(Handoff(), workspace=tmp_path)
    assert getattr(fetch_url, "__prismor_guarded__", False)
