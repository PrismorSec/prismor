"""LlamaIndex, smolagents and AG2 adapters against the real Prismor policy
pipeline (no live LLM). Each framework's tests run against its real tool
objects when it is installed and are skipped otherwise; conftest.py wires the
adapter shims onto prismor.__path__.
"""
import asyncio
from types import SimpleNamespace
from unittest.mock import patch

import pytest

SECRET = "ghp_" + "A" * 36


def _shell(ran):
    def run_shell(command: str) -> str:
        """Run a shell command."""
        ran.append(command)
        return f"ran {command}"
    return run_shell


# ── LlamaIndex ───────────────────────────────────────────────────────────────

def test_llamaindex_guards_function_tool(tmp_path):
    pytest.importorskip("llama_index.core")
    from prismor.llamaindex import guard_tools
    ran = []
    (tool,) = guard_tools([_shell(ran)], workspace=tmp_path, mode="enforce")
    assert "ran echo hi" in tool.call(command="echo hi").content
    out = tool.call(command="rm -rf /").content
    assert "Prismor blocked" in out and ran == ["echo hi"]
    out = asyncio.run(tool.acall(command="rm -rf /")).content  # the agents' path
    assert "Prismor blocked" in out and ran == ["echo hi"]


def test_llamaindex_observe_redact_and_name(tmp_path):
    pytest.importorskip("llama_index.core")
    from prismor.llamaindex import guard_tools
    (obs,) = guard_tools([_shell([])], workspace=tmp_path, mode="observe")
    assert "ran rm -rf /" in obs.call(command="rm -rf /").content

    def cat(path: str) -> str:
        """Read a file."""
        return f"github_token: {SECRET}"
    (tool,) = guard_tools([cat], workspace=tmp_path, mode="enforce")
    assert SECRET not in tool.call(path="config.yaml").content

    with patch("prismor_llamaindex.evaluate_tool_call",
               return_value=SimpleNamespace(allow=True, engine=None, findings=[])) as ev:
        (named,) = guard_tools([_shell([])], workspace=tmp_path, name="support-li")
        named.call(command="echo hi")
    kw = ev.call_args.kwargs
    assert kw["agent_name"] == "support-li" and kw["agent"] == "llamaindex"


# ── smolagents ───────────────────────────────────────────────────────────────

def _smol_tool(ran):
    from smolagents import tool

    @tool
    def run_shell(command: str) -> str:
        """Run a shell command.

        Args:
            command: the command to run
        """
        ran.append(command)
        return f"ran {command}"
    return run_shell


def test_smolagents_guards_tool_calls(tmp_path):
    pytest.importorskip("smolagents")
    from prismor.smolagents import guard_tools
    ran = []
    (t,) = guard_tools([_smol_tool(ran)], workspace=tmp_path, mode="enforce")
    assert t(command="echo hi") == "ran echo hi"
    assert "Prismor blocked" in t(command="rm -rf /") and ran == ["echo hi"]


def test_smolagents_codeagent_executor_goes_through_the_guard(tmp_path):
    """A CodeAgent's generated Python calls tools through the executor's
    static_tools; the guarded forward must still be what runs."""
    pytest.importorskip("smolagents")
    from smolagents.local_python_executor import LocalPythonExecutor
    from prismor.smolagents import guard_tools
    ran = []
    (t,) = guard_tools([_smol_tool(ran)], workspace=tmp_path, mode="enforce")
    ex = LocalPythonExecutor(additional_authorized_imports=[])
    ex.send_tools({"run_shell": t})
    out = ex("result = run_shell(command='rm -rf /')\nresult")
    assert "Prismor blocked" in str(out.output) and ran == []


def test_smolagents_guard_agent_skips_final_answer_and_names(tmp_path):
    pytest.importorskip("smolagents")
    from smolagents.default_tools import FinalAnswerTool
    from prismor.smolagents import guard_agent
    fa = FinalAnswerTool()
    agent = SimpleNamespace(tools={"run_shell": _smol_tool([]), "final_answer": fa})
    with patch("prismor_smolagents.evaluate_tool_call",
               return_value=SimpleNamespace(allow=True, engine=None, findings=[])) as ev:
        guard_agent(agent, workspace=tmp_path, name="support-smol")
        agent.tools["run_shell"](command="echo hi")
    assert not getattr(fa, "__prismor_guarded__", False)
    assert ev.call_args.kwargs["agent_name"] == "support-smol"


# ── AG2 ──────────────────────────────────────────────────────────────────────

def test_ag2_middleware_blocks_without_running_the_tool(tmp_path):
    pytest.importorskip("ag2")
    from ag2.events import ToolCallEvent, ToolResultEvent
    from prismor.ag2 import PrismorMiddleware
    mw = PrismorMiddleware(workspace=tmp_path, name="support-ag2")
    ran = []

    async def call_next(event, context):
        ran.append(event.name)
        return ToolResultEvent.from_call(event, result=f"github_token: {SECRET}")

    blocked = asyncio.run(mw.on_tool_execution(
        call_next, ToolCallEvent("run_shell", arguments='{"command": "rm -rf /"}'), None))
    assert "Prismor blocked" in blocked.result.parts[0].content and ran == []
    ok = asyncio.run(mw.on_tool_execution(
        call_next, ToolCallEvent("run_shell", arguments='{"command": "cat config.yaml"}'), None))
    assert ran == ["run_shell"] and SECRET not in ok.result.parts[0].content


def test_ag2_legacy_function_map(tmp_path):
    from prismor.ag2 import guard_agent
    ran = []
    executor = SimpleNamespace(_function_map={"run_shell": _shell(ran)})
    guard_agent(executor, workspace=tmp_path, name="support-ag2")
    fn = executor._function_map["run_shell"]
    assert fn(command="echo hi") == "ran echo hi"
    assert "Prismor blocked" in fn(command="rm -rf /") and ran == ["echo hi"]
    with pytest.raises(TypeError):
        guard_agent(SimpleNamespace(), workspace=tmp_path)


def test_ag2_guard_agent_adds_middleware_on_1x(tmp_path):
    pytest.importorskip("ag2")
    from ag2 import Agent
    from prismor.ag2 import PrismorMiddleware, guard_agent
    agent = Agent("ops", "test")
    guard_agent(agent, workspace=tmp_path, name="support-ag2")
    assert any(getattr(m.middleware, "cls", None) is PrismorMiddleware for m in agent.middleware)
