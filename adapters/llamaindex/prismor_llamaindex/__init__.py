"""Prismor adapter for LlamaIndex (``pip install llama-index-core``).

Routes every tool call through ``prismor.runtime.runtime.evaluate_tool_call``
before the tool runs — same policy engine, observe/enforce model, and
per-user attribution as the other adapters.

LlamaIndex's choke point is the tool object itself: ``FunctionAgent``,
``ReActAgent`` and ``AgentWorkflow`` all execute a tool through
``tool.acall(**kwargs)`` (sync code through ``tool.call``), and a
``FunctionTool`` funnels both into its ``_fn`` / ``_async_fn``. Guarding those
two callables means a denied call never reaches your function, and the denial
comes back to the model as an ordinary tool output so the run carries on.
Other ``BaseTool`` subclasses (``QueryEngineTool`` and friends) are guarded at
``call`` / ``acall`` instead.

Easy path::

    from llama_index.core.agent.workflow import FunctionAgent
    from prismor.llamaindex import guard_tools

    tools = guard_tools([run_shell, lookup_order], name="support-bot", mode="enforce")
    agent = FunctionAgent(tools=tools, llm=llm)

Plain functions are accepted and wrapped in ``FunctionTool.from_defaults``.
"""
from __future__ import annotations

import asyncio
import os
import weakref
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, List, Optional, Sequence, Union

from prismor.runtime.principal import Subject, resolve_subject, use_subject
from prismor.runtime.redaction import redact_tool_result
from prismor.runtime.runtime import Decision, evaluate_tool_call, log_observe_findings
from prismor.runtime.subagent_context import nested_subagent, running

__all__ = ["guard_tools", "guard_workflow", "prismor_guard_tool", "use_subject", "PrismorBlocked"]

_TYPE_FIELD = {
    "shell": "command",
    "file_read": "path",
    "file_write": "path",
    "network": "url",
    "prompt": "content",
    "tool_result": "content",
}


class PrismorBlocked(Exception):
    """Raised when Prismor denies a tool call (``raise_on_block=True``)."""

    def __init__(self, reason: str, decision: Optional[Decision] = None) -> None:
        super().__init__(reason or "blocked by Prismor policy")
        self.decision = decision


def _payload(args: tuple, kwargs: dict) -> str:
    return " ".join([str(a) for a in args] + [str(v) for v in kwargs.values()]).strip()


# Root agent of each AgentWorkflow run and the guard name its calls are
# evaluated under, keyed by id of the run's state store (a finalizer drops the
# entry with the run).
_ROOT: dict = {}


async def _workflow_subagent(guard_name: str = "") -> tuple:
    """(subagent_id, subagent_type, parent guard name) inside a multi-agent
    AgentWorkflow, else (None, None, None).

    The workflow keeps the active agent in ``current_agent_name``; it starts as
    the root agent and changes on a handoff, which also sets ``next_agent``.
    The root is remembered from the first guarded call made before any handoff,
    with its guard name: a handoff target inherits that agent's controls.
    """
    try:
        from workflows import Context
        store = Context.get_step_context().store
        current = await store.get("current_agent_name", default=None)
        if not current:
            return None, None, None
        key = id(store)
        if key not in _ROOT:
            if await store.get("next_agent", default=None) is not None:
                # ponytail: the root handed off before any guarded call of its
                # own, so it was never seen; the active agent is a handoff target.
                return f"{current}:{key:x}", str(current), None
            _ROOT[key] = (current, guard_name)
            weakref.finalize(store, _ROOT.pop, key, None)
    except Exception:  # not in a workflow step, or not a multi-agent workflow
        return None, None, None
    root, root_guard = _ROOT[key]
    return (None, None, None) if current == root else (f"{current}:{key:x}", str(current), root_guard or None)


def prismor_guard_tool(
    tool: Any,
    *,
    subject: Optional[Union[str, Subject]] = None,
    workspace: Optional[Union[str, Path]] = None,
    agent: str = "llamaindex",
    name: str = "",
    mode: str = "observe",
    session_id: Optional[str] = None,
    event_type: str = "shell",
    raise_on_block: bool = False,
) -> Any:
    """Guard one LlamaIndex tool (or plain function). Returns the tool."""
    if not hasattr(tool, "metadata"):  # a plain function
        from llama_index.core.tools import FunctionTool
        tool = FunctionTool.from_defaults(fn=tool)
    if getattr(tool, "__prismor_guarded__", False):
        return tool
    ws = Path(workspace) if workspace else Path.cwd()
    sid = session_id or f"llamaindex-{os.getpid()}"
    tool_name = tool.metadata.get_name()
    ctx_param = getattr(tool, "ctx_param_name", None)
    engine: List[Any] = [None]

    def _decide(args: tuple, kwargs: dict, sub: tuple = (None, None)) -> Optional[str]:
        # The workflow Context is plumbing, not tool input.
        kwargs = {k: v for k, v in kwargs.items() if k != ctx_param}
        field = _TYPE_FIELD.get(event_type, "command")
        event = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "session_id": sid,
            "agent": agent,
            "agent_event": "PreToolUse",
            "type": event_type,
            field: _payload(args, kwargs),
            "metadata": {"tool_name": tool_name, "framework": "llamaindex",
                         "args": [str(a) for a in args], "kwargs": {k: str(v) for k, v in kwargs.items()},
                         "subagent_id": sub[0], "subagent_type": sub[1],
                         # A handoff target runs on the root agent's authority.
                         "parent_agent_name": sub[2] if len(sub) > 2 else None},
        }
        decision: Decision = evaluate_tool_call(
            event=event, workspace=ws, agent=agent, agent_name=name, mode=mode,
            session_id=sid, subject=resolve_subject(subject),
        )
        log_observe_findings(decision, mode=mode, tool_name=tool_name)
        engine[0] = decision.engine
        if decision.allow:
            return None
        reason = decision.reason or "policy violation"
        if raise_on_block:
            raise PrismorBlocked(reason, decision)
        return f"⛔ Prismor blocked this tool call: {reason}"

    def _redact(out: Any) -> Any:
        return redact_tool_result(out, workspace=ws, engine=engine[0])

    async def _sub() -> tuple:
        # The workflow's own handoff signal first; else an agent run inside
        # another guarded tool (an agent used as a tool) is a subagent.
        found = await _workflow_subagent(name or agent)
        return found if found[0] else nested_subagent(name or agent)

    if hasattr(tool, "_fn") and hasattr(tool, "_async_fn"):  # FunctionTool
        fn, afn = tool._fn, tool._async_fn

        def guarded_fn(*args: Any, **kwargs: Any) -> Any:
            denial = _decide(args, kwargs, nested_subagent(name or agent))
            if denial is not None:
                return denial
            with running(name or agent):
                return _redact(fn(*args, **kwargs))

        async def guarded_afn(*args: Any, **kwargs: Any) -> Any:
            denial = await asyncio.to_thread(_decide, args, kwargs, await _sub())
            if denial is not None:
                return denial
            with running(name or agent):
                return _redact(await afn(*args, **kwargs))

        tool._fn, tool._async_fn = guarded_fn, guarded_afn
    else:  # any other BaseTool: guard the public entry points
        from llama_index.core.tools.types import ToolOutput
        call, acall = tool.call, getattr(tool, "acall", None)

        def _denied(text: str, args: tuple, kwargs: dict) -> Any:
            return ToolOutput(content=text, tool_name=tool_name,
                              raw_input={"args": args, "kwargs": kwargs}, raw_output=text)

        def guarded_call(*args: Any, **kwargs: Any) -> Any:
            denial = _decide(args, kwargs, nested_subagent(name or agent))
            if denial is not None:
                return _denied(denial, args, kwargs)
            with running(name or agent):
                return call(*args, **kwargs)

        tool.call = guarded_call
        if acall is not None:
            async def guarded_acall(*args: Any, **kwargs: Any) -> Any:
                denial = await asyncio.to_thread(_decide, args, kwargs, await _sub())
                if denial is not None:
                    return _denied(denial, args, kwargs)
                with running(name or agent):
                    return await acall(*args, **kwargs)
            tool.acall = guarded_acall

    tool.__prismor_guarded__ = True
    return tool


def guard_tools(tools: Sequence[Any], **kwargs: Any) -> List[Any]:
    """Guard a list of LlamaIndex tools / functions. Returns the guarded tools
    (pass these to the agent — plain functions come back as FunctionTools)."""
    guarded = [prismor_guard_tool(t, **kwargs) for t in tools]
    try:
        from prismor.runtime.agents import record_seen
        framework = kwargs.get("agent", "llamaindex")
        record_seen(
            kwargs.get("name") or framework, framework=framework,
            workspace=Path(kwargs["workspace"]) if kwargs.get("workspace") else Path.cwd(),
            tools=[{"name": t.metadata.get_name(), "source": "declared"} for t in guarded],
            session_id=kwargs.get("session_id") or f"llamaindex-{os.getpid()}",
        )
    except Exception:
        pass
    return guarded


def guard_workflow(workflow: Any, **kwargs: Any) -> Any:
    """Guard the tools of every agent in an ``AgentWorkflow``, with the same
    settings. Agents reached by a handoff run on the root agent's authority, so
    they are held to the same policy (told apart by ``when: subagent.*``); an
    agent left unguarded would run its tools unchecked. Returns the workflow.

    An agent that one of these tools runs inside its body (an agent used as a
    tool) is created by your code: guard its tools too.
    """
    for member in (getattr(workflow, "agents", None) or {}).values():
        tools = getattr(member, "tools", None)
        if tools:
            member.tools = guard_tools(list(tools), **kwargs)
    return workflow
