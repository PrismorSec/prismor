"""Prismor adapter for CrewAI.

Routes every CrewAI tool invocation through ``prismor.runtime.runtime.evaluate_tool_call``
before the tool runs — same policy engine, observe/enforce model, and per-user
attribution as the other adapters.

CrewAI tools come in a few shapes (``@tool``-decorated structured tools, and
``BaseTool`` subclasses with ``_run``). :func:`prismor_guard_tool` wraps whichever
callable the tool exposes (``func`` / ``_run`` / ``run``), so a denied call never
executes. Returns the same tool object. A thin layer over
:class:`prismor.sdk.PrismorClient`.

Easy path::

    from crewai import Agent
    from prismor.crewai import guard_tools

    tools = guard_tools([run_shell], subject="user:alice")
    agent = Agent(role="ops", tools=tools, ...)
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Callable, List, Optional, Sequence, Union

from prismor.runtime.principal import Subject, use_subject
from prismor.runtime.runtime import Decision, evaluate_tool_call
from prismor.sdk import BlockContext, PrismorBlocked, PrismorClient

__all__ = ["guard_tools", "prismor_guard_tool", "use_subject", "PrismorBlocked"]

# Tool attributes that hold the actual implementation, in preference order.
_IMPL_ATTRS = ("func", "_run", "run")


def _evaluate(**kwargs: Any) -> Decision:
    """Resolve ``evaluate_tool_call`` through this module's global at call time.

    A test (or an app) that patches ``prismor.crewai.evaluate_tool_call`` keeps
    seeing every call, whether the patch lands before or after guarding.
    """
    return evaluate_tool_call(**kwargs)


def _client(**kwargs: Any) -> PrismorClient:
    return PrismorClient(framework="crewai", evaluate=_evaluate, **kwargs)


def prismor_guard_tool(
    tool: Any,
    *,
    subject: Optional[Union[str, Subject]] = None,
    workspace: Optional[Union[str, Path]] = None,
    agent: str = "crewai",
    name: str = "",
    mode: str = "observe",
    session_id: Optional[str] = None,
    event_type: str = "shell",
    raise_on_block: bool = False,
    approvals: bool = True,
    on_policy_block: Optional[Callable[[Decision, BlockContext], Any]] = None,
) -> Any:
    """Wrap a CrewAI tool's implementation so calls are policy-checked.

    On a denial the tool body does not run: by default a denial string is
    returned to the agent, ``raise_on_block=True`` raises :class:`PrismorBlocked`,
    and ``on_policy_block(decision, ctx)`` lets the app decide what the model
    sees instead.
    """
    if getattr(tool, "__prismor_guarded__", False):
        return tool
    tool_name = getattr(tool, "name", None) or getattr(tool, "__name__", "tool")
    client = _client(
        workspace=workspace, agent=agent, agent_name=name, mode=mode,
        session_id=session_id or f"crewai-{os.getpid()}", subject=subject,
        approvals=approvals, raise_on_block=raise_on_block, on_policy_block=on_policy_block,
    )

    wrapped_any = False
    for attr in _IMPL_ATTRS:
        impl = getattr(tool, attr, None)
        if not callable(impl):
            continue
        # _run/run are bound methods on a class instance; wrapping the instance
        # attribute shadows the bound method for this tool object only.
        try:
            setattr(tool, attr, client.guard(impl, tool_name=tool_name, event_type=event_type))
            wrapped_any = True
        except Exception:
            continue
        # `func` is the canonical impl for structured tools; once wrapped, stop.
        if attr == "func":
            break

    if wrapped_any:
        tool.__prismor_guarded__ = True
    return tool


def guard_tools(tools: Sequence[Any], **kwargs: Any) -> List[Any]:
    """Guard a list of CrewAI tools in one call. Returns the same list.

    Pass ``goal="..."`` to also capture the agent's intent: the session's
    intent-scoped rules are synthesized from the goal + these tools' names so
    ``evaluate_tool_call`` enforces task-alignment for this headless agent (R2/R3).
    """
    goal = kwargs.pop("goal", None)
    guarded = [prismor_guard_tool(t, **kwargs) for t in tools]
    names = [getattr(t, "name", None) or getattr(t, "__name__", None) for t in tools]
    _client(
        workspace=kwargs.get("workspace"), agent=kwargs.get("agent", "crewai"),
        agent_name=kwargs.get("name", ""),
        session_id=kwargs.get("session_id") or f"crewai-{os.getpid()}",
    ).declare_tools([n for n in names if n], goal=goal)
    return guarded
