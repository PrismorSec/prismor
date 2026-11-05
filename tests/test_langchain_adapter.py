"""Tests for the LangChain adapter (adapters/langchain).

Unlike the openai-agents/browser-use adapters, this one had zero test
coverage at all before PrismorSec/prismor#138. Exercises real
langchain_core.tools.Tool/@tool objects — not bare callables or mocks —
against the real Prismor policy pipeline, no live LLM.
"""
import asyncio
import sys
from pathlib import Path

import pytest

pytest.importorskip("langchain_core")

_ADAPTER_SRC = Path(__file__).resolve().parent.parent / "adapters" / "langchain"
if str(_ADAPTER_SRC) not in sys.path:
    sys.path.insert(0, str(_ADAPTER_SRC))

from langchain_core.tools import tool  # noqa: E402

from prismor.langchain import (  # noqa: E402
    PrismorBlocked,
    PrismorCallbackHandler,
    guard_tools,
    prismor_guard_tool,
)


def _make_tools():
    @tool
    def run_shell(command: str) -> str:
        """Execute a shell command."""
        return f"ran: {command}"

    @tool
    def read_file(path: str) -> str:
        """Read a file."""
        return f"contents of {path}"

    return run_shell, read_file


def test_guard_tools_safe_call_runs(tmp_path):
    run_shell, _ = _make_tools()
    guarded = guard_tools([run_shell], workspace=tmp_path, raise_on_block=True)
    assert guarded[0].run(tool_input={"command": "echo hi"}) == "ran: echo hi"


def test_guard_tools_blocks_destructive(tmp_path):
    run_shell, _ = _make_tools()
    guarded = guard_tools([run_shell], workspace=tmp_path, mode="enforce", raise_on_block=True)
    with pytest.raises(PrismorBlocked):
        guarded[0].run(tool_input={"command": "rm -rf /"})


def test_prismor_guard_tool_single(tmp_path):
    run_shell, _ = _make_tools()
    guarded = prismor_guard_tool(run_shell, workspace=tmp_path, mode="enforce", raise_on_block=True)
    assert guarded.run(tool_input={"command": "echo hi"}) == "ran: echo hi"
    with pytest.raises(PrismorBlocked):
        guarded.run(tool_input={"command": "rm -rf /"})


def test_event_type_override_for_path_based_tools(tmp_path):
    _, read_file = _make_tools()
    guarded = prismor_guard_tool(
        read_file, workspace=tmp_path, event_type="file_read", mode="enforce", raise_on_block=True
    )
    with pytest.raises(PrismorBlocked):
        guarded.run(tool_input={"path": ".env"})


def test_async_coroutine_path_is_guarded(tmp_path):
    @tool
    async def run_shell_async(command: str) -> str:
        """Execute a shell command asynchronously."""
        return f"ran: {command}"

    guarded = guard_tools([run_shell_async], workspace=tmp_path, mode="enforce", raise_on_block=True)
    assert asyncio.run(guarded[0].arun(tool_input={"command": "echo hi"})) == "ran: echo hi"
    with pytest.raises(PrismorBlocked):
        asyncio.run(guarded[0].arun(tool_input={"command": "rm -rf /"}))


def test_callback_handler_blocks_on_tool_start(tmp_path):
    handler = PrismorCallbackHandler(mode="enforce", workspace=tmp_path)
    handler.on_tool_start({"name": "run_shell"}, "echo hi")  # does not raise
    with pytest.raises(PrismorBlocked):
        handler.on_tool_start({"name": "run_shell"}, "rm -rf /")


def test_callback_handler_captures_langgraph_node_as_subagent(tmp_path, monkeypatch):
    """LangGraph stamps the graph path onto callback run metadata. A call
    inside an agent subgraph is a subagent; the top-level graph (including a
    single ReAct agent's "tools" node) is the main agent."""
    import prismor_langchain as pl

    captured = []
    real_evaluate = pl.evaluate_tool_call

    def spy(*, event, **kwargs):
        captured.append(event)
        return real_evaluate(event=event, **kwargs)

    monkeypatch.setattr(pl, "evaluate_tool_call", spy)

    handler = PrismorCallbackHandler(mode="observe", workspace=tmp_path)
    # No LangGraph metadata: a plain single-agent call, no subagent.
    handler.on_tool_start({"name": "run_shell"}, "echo hi")
    # A single ReAct agent: its tool node is "tools", one graph level. Still the
    # main agent (shapes captured from a live LangGraph 1.x run).
    handler.on_tool_start(
        {"name": "run_shell"}, "echo hi", run_id="run-1",
        metadata={"langgraph_node": "tools", "langgraph_checkpoint_ns": "tools:e3e2"},
    )
    # The "researcher" agent subgraph of a multi-agent graph: a subagent.
    handler.on_tool_start(
        {"name": "run_shell"}, "echo hi", run_id="run-2",
        metadata={"langgraph_node": "tools",
                  "langgraph_checkpoint_ns": "researcher:9933|tools:f019"},
    )

    assert len(captured) == 3
    assert captured[0]["metadata"]["subagent_type"] is None
    assert captured[1]["metadata"]["subagent_type"] is None
    assert captured[2]["metadata"]["subagent_type"] == "researcher"
    assert captured[2]["metadata"]["subagent_id"] == "researcher:9933"


def _write_iam(workspace: Path) -> None:
    iam_dir = workspace / ".prismor"
    iam_dir.mkdir(parents=True, exist_ok=True)
    (iam_dir / "iam.yaml").write_text(
        "agents:\n"
        "  user:bob:\n"
        "    allowed_tools: [Read]\n"
        "    deny_tools: [Bash]\n"
        "    deny_network: true\n"
        "    allowed_paths: ['**']\n",
        encoding="utf-8",
    )


def test_use_subject_per_user_iam(tmp_path, monkeypatch):
    from prismor.langchain import use_subject

    monkeypatch.delenv("PRISMOR_AGENT_ID", raising=False)
    _write_iam(tmp_path)
    run_shell, _ = _make_tools()
    guarded = guard_tools([run_shell], workspace=tmp_path, mode="enforce", raise_on_block=True)

    with use_subject("user:alice"):
        assert guarded[0].run(tool_input={"command": "ls -la"}) == "ran: ls -la"

    with use_subject("user:bob"), pytest.raises(PrismorBlocked):
        guarded[0].run(tool_input={"command": "ls -la"})


def test_agent_served_over_mcp_is_a_handoff(tmp_path):
    """langchain-mcp-adapters names a tool by the server's bare tool name; the
    server is only in the call closure. An agent served over MCP is still checked."""
    import yaml
    from langchain_core.tools import StructuredTool

    (tmp_path / ".prismor").mkdir()
    (tmp_path / ".prismor" / "policy.yaml").write_text(yaml.safe_dump({"settings": {"agent_connections": {
        "mode": "enforce",
        "agents": {"agt_claude": {"name": "claude", "aliases": ["mcp:claude"]}},
        "allow": [{"from": "planner", "to": "claude"}],
    }}}))

    def mcp_tool(server_name):
        async def call_tool(**arguments):  # closes over server_name, as langchain-mcp-adapters' does
            return f"{server_name} ran", None
        return StructuredTool(name="Agent", description="Run a subagent.", coroutine=call_tool,
                              response_format="content_and_artifact",
                              args_schema={"type": "object", "properties": {"prompt": {"type": "string"}}})

    def call(name):
        t = prismor_guard_tool(mcp_tool("claude"), workspace=tmp_path, agent="langchain", name=name, mode="enforce")
        return asyncio.run(t.ainvoke({"prompt": "hi"}))

    assert call("planner") == "claude ran"
    blocked = call("researcher")
    assert "Prismor blocked" in blocked and "researcher" in blocked and "claude" in blocked
