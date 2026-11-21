"""Tests for the OpenAI Agents SDK adapter (adapters/openai-agents).

Exercises the adapter end to end against the real Prismor policy pipeline with no
live LLM: allow / observe / enforce, and per-user IAM scoping. The adapter wraps
a plain callable, so we drive it by calling the wrapped function directly.
"""
import sys
from pathlib import Path

import pytest

# The adapter ships as a separate distribution under adapters/; make it
# importable for the in-repo test without an editable install.
_ADAPTER_SRC = Path(__file__).resolve().parent.parent / "adapters" / "openai-agents"
if str(_ADAPTER_SRC) not in sys.path:
    sys.path.insert(0, str(_ADAPTER_SRC))

from prismor.openai import PrismorBlocked, prismor_guard  # noqa: E402

# The legacy flat module must stay importable and share the same objects, so
# isinstance checks work across old- and new-style imports.
import prismor_openai as _legacy  # noqa: E402
assert _legacy.PrismorBlocked is PrismorBlocked


def _make_tool():
    """A tool that records whether it actually ran."""
    calls = {"ran": 0, "last": None}

    def run_shell(command: str) -> str:
        calls["ran"] += 1
        calls["last"] = command
        return f"ran: {command}"

    return run_shell, calls


def test_safe_call_runs(tmp_path):
    tool, calls = _make_tool()
    guarded = prismor_guard(tool, workspace=tmp_path, mode="enforce")
    assert guarded(command="echo hello") == "ran: echo hello"
    assert calls["ran"] == 1


def test_enforce_blocks_destructive(tmp_path):
    tool, calls = _make_tool()
    guarded = prismor_guard(tool, workspace=tmp_path, mode="enforce")
    with pytest.raises(PrismorBlocked) as exc:
        guarded(command="rm -rf /")
    # Tool must NOT have executed.
    assert calls["ran"] == 0
    assert exc.value.decision is not None
    assert exc.value.decision.blocking is not None


def test_observe_never_blocks_but_records(tmp_path):
    tool, calls = _make_tool()
    guarded = prismor_guard(tool, workspace=tmp_path, mode="observe")
    # Same dangerous input, but observe mode is log-only: the call proceeds.
    assert guarded(command="rm -rf /") == "ran: rm -rf /"
    assert calls["ran"] == 1


def test_no_raise_returns_decision(tmp_path):
    tool, calls = _make_tool()
    guarded = prismor_guard(tool, workspace=tmp_path, mode="enforce", raise_on_block=False)
    decision = guarded(command="rm -rf /")
    assert decision.allow is False
    assert decision.blocking is not None
    assert calls["ran"] == 0


def test_subject_tagged_on_findings(tmp_path):
    tool, _ = _make_tool()
    guarded = prismor_guard(
        tool, workspace=tmp_path, mode="enforce", subject="user:alice", raise_on_block=False
    )
    decision = guarded(command="rm -rf /")
    assert decision.subject is not None
    assert decision.subject.user_id == "alice"
    assert decision.blocking.get("subject", {}).get("user_id") == "alice"


def test_per_request_subject_context(tmp_path):
    # Guard with NO bound subject (the multi-tenant pattern): the per-request
    # context decides who the call is attributed to.
    from prismor.runtime.principal import use_subject

    tool, _ = _make_tool()
    guarded = prismor_guard(tool, workspace=tmp_path, mode="enforce", raise_on_block=False)

    with use_subject("user:dave"):
        decision = guarded(command="rm -rf /")
    assert decision.subject.user_id == "dave"
    assert decision.blocking.get("subject", {}).get("user_id") == "dave"

    with use_subject("user=erin;team=sre"):
        decision2 = guarded(command="rm -rf /")
    assert decision2.subject.user_id == "erin"
    assert decision2.subject.team_id == "sre"


def _write_iam(workspace: Path) -> None:
    iam_dir = workspace / ".prismor"
    iam_dir.mkdir(parents=True, exist_ok=True)
    # bob is denied shell tools (Bash); other users have no profile → unrestricted.
    (iam_dir / "iam.yaml").write_text(
        "agents:\n"
        "  user:bob:\n"
        "    allowed_tools: [Read]\n"
        "    deny_tools: [Bash]\n"
        "    deny_network: true\n"
        "    allowed_paths: ['**']\n",
        encoding="utf-8",
    )


def test_per_user_iam_scoping(tmp_path, monkeypatch):
    # Ensure no ambient named-agent identity overrides subject-based selection.
    monkeypatch.delenv("PRISMOR_AGENT_ID", raising=False)
    _write_iam(tmp_path)

    tool, calls = _make_tool()

    # bob: has a deny-Bash IAM profile → a safe shell call is still blocked.
    bob = prismor_guard(tool, workspace=tmp_path, mode="enforce", subject="user:bob")
    with pytest.raises(PrismorBlocked):
        bob(command="echo hi")
    assert calls["ran"] == 0

    # alice: no IAM profile → same safe call is allowed.
    alice = prismor_guard(tool, workspace=tmp_path, mode="enforce", subject="user:alice")
    assert alice(command="echo hi") == "ran: echo hi"
    assert calls["ran"] == 1


try:
    import agents as _agents_sdk  # noqa: F401
    _HAS_AGENTS_SDK = True
except ImportError:
    _HAS_AGENTS_SDK = False


@pytest.mark.skipif(not _HAS_AGENTS_SDK, reason="openai-agents not installed")
class TestRealAgentSDK:
    """guard_agent's actual job is wrapping a real Agent's FunctionTool
    (on_invoke_tool) — the tests above only exercise prismor_guard's plain-
    callable fallback path, which is a different code path entirely. See
    PrismorSec/prismor#138."""

    def _make_ctx(self, tool_name="run_shell", agent=None):
        from agents.tool_context import ToolContext
        return ToolContext(context=None, tool_name=tool_name, tool_call_id="call_1", tool_arguments="{}", agent=agent)

    def test_guard_agent_wraps_real_function_tool(self, tmp_path):
        import asyncio
        import json
        from agents import Agent, function_tool
        from prismor.openai import guard_agent

        @function_tool
        def run_shell(command: str) -> str:
            return f"ran: {command}"

        agent = Agent(name="ops", tools=[run_shell])
        guard_agent(agent, workspace=tmp_path, mode="enforce", raise_on_block=True)
        tool = agent.tools[0]
        assert getattr(tool, "__prismor_guarded__", False)

        result = asyncio.run(tool.on_invoke_tool(self._make_ctx(), json.dumps({"command": "echo hi"})))
        assert result == "ran: echo hi"

        with pytest.raises(PrismorBlocked):
            asyncio.run(tool.on_invoke_tool(self._make_ctx(), json.dumps({"command": "rm -rf /"})))

    def test_guard_agent_per_user_iam(self, tmp_path, monkeypatch):
        import asyncio
        import json
        from agents import Agent, function_tool
        from prismor.openai import guard_agent, use_subject

        monkeypatch.delenv("PRISMOR_AGENT_ID", raising=False)
        _write_iam(tmp_path)

        @function_tool
        def run_shell(command: str) -> str:
            return f"ran: {command}"

        agent = Agent(name="ops", tools=[run_shell])
        guard_agent(agent, workspace=tmp_path, mode="enforce", raise_on_block=True)
        tool = agent.tools[0]

        with use_subject("user:alice"):
            result = asyncio.run(tool.on_invoke_tool(self._make_ctx(), json.dumps({"command": "echo hi"})))
        assert result == "ran: echo hi"

        with use_subject("user:bob"), pytest.raises(PrismorBlocked):
            asyncio.run(tool.on_invoke_tool(self._make_ctx(), json.dumps({"command": "echo hi"})))

    def test_handoff_call_carries_subagent_attribution(self, tmp_path, monkeypatch):
        """The first agent whose tool runs in a run is the main agent; an agent
        reached by a handoff later in the same run is a subagent, and so is
        every agent of a nested run (an agent used as a tool). Decided from
        the run, not the `name=` label: an app-level label (or none) used to
        make the main agent itself read as a subagent."""
        import asyncio
        import json
        from agents import Agent, function_tool
        from agents.usage import Usage
        import prismor_openai as po

        captured = []
        real_evaluate = po.evaluate_tool_call

        def spy(*, event, **kwargs):
            captured.append(event)
            return real_evaluate(event=event, **kwargs)

        monkeypatch.setattr(po, "evaluate_tool_call", spy)

        @function_tool
        def run_shell(command: str) -> str:
            return f"ran: {command}"

        primary = Agent(name="primary", tools=[run_shell])
        po.guard_agent(primary, workspace=tmp_path, name="support-bot", mode="observe", raise_on_block=True)
        tool = primary.tools[0]
        researcher = Agent(name="researcher")
        run = Usage()  # one run: every ToolContext of it shares this object

        def call(agent, usage):
            ctx = self._make_ctx(agent=agent)
            ctx.usage = usage
            asyncio.run(tool.on_invoke_tool(ctx, json.dumps({"command": "echo hi"})))

        call(primary, run)       # the main agent
        call(researcher, run)    # handed off to, same run
        call(primary, run)       # main again after control returns

        # A nested run (agent as tool) has its own Usage but runs inside the
        # parent's tool call.
        token = po._RUNNING_AGENT.set((id(primary), "support-bot"))
        try:
            call(researcher, Usage())
        finally:
            po._RUNNING_AGENT.reset(token)

        types = [e["metadata"]["subagent_type"] for e in captured]
        assert types == [None, "researcher", None, "researcher"]
        assert captured[1]["metadata"]["subagent_id"] is not None
        assert captured[0]["metadata"]["subagent_id"] is None
        # A subagent names the guard it runs under: its controls apply on top.
        assert captured[1]["metadata"]["parent_agent_name"] == "support-bot"
        assert captured[3]["metadata"]["parent_agent_name"] == "support-bot"
        assert "parent_agent_name" not in captured[0]["metadata"]


def test_guard_agent_also_guards_handoff_and_as_tool_agents(tmp_path):
    """Guarding the main agent covers every agent it can run: an agent left
    unguarded would run its tools with no policy at all."""
    pytest.importorskip("agents")
    from agents import Agent, function_tool, handoff
    import prismor_openai as po

    def mk():
        @function_tool
        def fetch_url(url: str) -> str:
            return "ok"
        return fetch_url

    deep = Agent(name="deep", tools=[mk()])
    researcher = Agent(name="researcher", tools=[mk()], handoffs=[deep])
    summarizer = Agent(name="summarizer", tools=[mk()])
    main = Agent(name="main", tools=[mk(), summarizer.as_tool(tool_name="ask", tool_description="x")],
                 handoffs=[handoff(researcher)])
    researcher.handoffs.append(main)   # a cycle must not loop
    po.guard_agent(main, workspace=tmp_path)
    for a in (main, researcher, summarizer, deep):
        assert all(getattr(t, "__prismor_guarded__", False) for t in a.tools), a.name


def test_as_tool_call_is_marked_as_a_handoff(tmp_path):
    """An agent-as-tool's input is what its agent is handed: data_boundary.handoffs screens it."""
    pytest.importorskip("agents")
    import asyncio
    from types import SimpleNamespace
    from unittest.mock import patch
    from agents import Agent
    import prismor_openai as po
    from prismor.runtime.runtime import Decision

    tool = Agent(name="summarizer").as_tool(tool_name="ask", tool_description="x")
    po._guard_function_tool(tool, subject=None, workspace=tmp_path, agent="openai-agents", mode="observe",
                            session_id="s", event_type="shell", raise_on_block=False, name="main")
    seen = []
    with patch("prismor_openai.evaluate_tool_call",
               lambda *, event, **kw: seen.append(event["metadata"]) or Decision(allow=False, reason="stop")):
        asyncio.run(tool.on_invoke_tool(SimpleNamespace(context=None, usage=SimpleNamespace()), '{"input": "hi"}'))
    assert seen[0]["handoff_to"] == "summarizer"
