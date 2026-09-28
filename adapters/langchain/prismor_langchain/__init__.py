"""Prismor adapter for LangChain / LangGraph.

Same control point as the other framework adapters: every tool invocation is
routed through ``prismor.runtime.runtime.evaluate_tool_call`` before the tool runs, so a
LangChain/LangGraph agent gets the exact policy, observe/enforce model, and
per-user attribution a local coding agent already has.

Two surfaces:

* :func:`guard_tools` / :func:`prismor_guard_tool` — wrap a ``BaseTool``'s
  implementation so a denied call never executes (hard enforcement). This is the
  reliable path and what you normally want.
* :class:`PrismorCallbackHandler` — a ``BaseCallbackHandler`` for observability /
  soft-blocking via ``on_tool_start`` (capture every tool call even for tools you
  didn't wrap).

Both are thin layers over :class:`prismor.sdk.PrismorClient`; anything they do,
a custom integration can do with the same client.

Easy path::

    from langgraph.prebuilt import create_react_agent
    from prismor.langchain import guard_tools

    tools = guard_tools([run_shell, fetch_url], subject="user:alice")
    agent = create_react_agent(model, tools)
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Callable, List, Optional, Sequence, Union

from prismor.runtime.principal import Subject, use_subject
from prismor.runtime.runtime import Decision, evaluate_tool_call
from prismor.sdk import BlockContext, PrismorBlocked, PrismorClient

__all__ = [
    "guard_tools",
    "prismor_guard_tool",
    "PrismorCallbackHandler",
    "use_subject",
    "PrismorBlocked",
]


def _evaluate(**kwargs: Any) -> Decision:
    """Resolve ``evaluate_tool_call`` through this module's global at call time.

    A test (or an app) that patches ``prismor.langchain.evaluate_tool_call``
    keeps seeing every call, whether the patch lands before or after guarding.
    """
    return evaluate_tool_call(**kwargs)


def _client(**kwargs: Any) -> PrismorClient:
    return PrismorClient(framework="langchain", evaluate=_evaluate, **kwargs)


def prismor_guard_tool(
    tool: Any,
    *,
    subject: Optional[Union[str, Subject]] = None,
    workspace: Optional[Union[str, Path]] = None,
    agent: str = "langchain",
    name: str = "",
    mode: str = "observe",
    session_id: Optional[str] = None,
    event_type: str = "shell",
    raise_on_block: bool = False,
    approvals: bool = True,
    on_policy_block: Optional[Callable[[Decision, BlockContext], Any]] = None,
) -> Any:
    """Wrap a LangChain ``BaseTool``'s implementation so calls are policy-checked.

    Wraps both the sync ``func`` and async ``coroutine`` if present. On an
    enforce-mode denial the tool body does not run; by default a denial string is
    returned to the agent (smooth recovery), ``raise_on_block=True`` raises
    :class:`PrismorBlocked`, and ``on_policy_block(decision, ctx)`` lets the app
    decide what the model sees instead. Returns the same tool object.
    """
    if getattr(tool, "__prismor_guarded__", False):
        return tool
    tool_name = getattr(tool, "name", None) or getattr(tool, "__name__", "tool")
    client = _client(
        workspace=workspace, agent=agent, agent_name=name, mode=mode,
        session_id=session_id or f"langchain-{os.getpid()}", subject=subject,
        approvals=approvals, raise_on_block=raise_on_block, on_policy_block=on_policy_block,
    )
    for attr in ("func", "coroutine"):
        impl = getattr(tool, attr, None)
        if callable(impl):
            # The async path runs the whole decision (and any approval wait) in
            # a worker thread so the event loop keeps servicing other tools.
            setattr(tool, attr, client.guard(
                impl, tool_name=tool_name, event_type=event_type,
                is_async=(attr == "coroutine"),
            ))
    tool.__prismor_guarded__ = True
    return tool


def guard_tools(tools: Sequence[Any], **kwargs: Any) -> List[Any]:
    """Guard a list of LangChain tools in one call. Returns the same list.

    Pass ``goal="..."`` to also capture the agent's intent: the session's
    intent-scoped rules are synthesized from the goal + these tools' names so
    ``evaluate_tool_call`` enforces task-alignment for this headless agent (R2/R3).
    """
    goal = kwargs.pop("goal", None)
    guarded = [prismor_guard_tool(t, **kwargs) for t in tools]
    names = [getattr(t, "name", None) or getattr(t, "__name__", None) for t in tools]
    _client(
        workspace=kwargs.get("workspace"), agent=kwargs.get("agent", "langchain"),
        agent_name=kwargs.get("name", ""),
        session_id=kwargs.get("session_id") or f"langchain-{os.getpid()}",
    ).declare_tools([n for n in names if n], goal=goal)
    return guarded


# ── Callback handler (observability / soft block) ───────────────────────────

try:
    from langchain_core.callbacks import BaseCallbackHandler as _BaseCB
except Exception:  # pragma: no cover - langchain not installed
    _BaseCB = object  # type: ignore[assignment,misc]


class PrismorCallbackHandler(_BaseCB):  # type: ignore[misc]
    """Capture every tool call via ``on_tool_start`` and evaluate it.

    Add to any chain/agent run (``config={"callbacks": [PrismorCallbackHandler()]}``)
    to record + evaluate tool calls even for tools you did not wrap. In enforce
    mode it raises :class:`PrismorBlocked` from ``on_tool_start`` (which aborts the
    tool call before the tool runs); in observe mode it only records.
    """

    raise_error = True  # ask LangChain to propagate our exception

    def __init__(
        self,
        *,
        subject: Optional[Union[str, Subject]] = None,
        workspace: Optional[Union[str, Path]] = None,
        agent: str = "langchain",
        mode: str = "observe",
        session_id: Optional[str] = None,
        event_type: str = "shell",
        approvals: bool = True,
    ) -> None:
        self._client = _client(
            workspace=workspace, agent=agent, mode=mode,
            session_id=session_id or f"langchain-cb-{os.getpid()}", subject=subject,
            approvals=approvals,
        )
        self._event_type = event_type

    def on_tool_start(self, serialized: dict, input_str: str, **kwargs: Any) -> None:
        name = (serialized or {}).get("name", "tool")
        # LangGraph stamps the executing graph node onto callback metadata for
        # every run inside a StateGraph; a multi-agent graph names each agent
        # node distinctly, so this is that framework's subagent identity.
        run_metadata = kwargs.get("metadata") or {}
        node = run_metadata.get("langgraph_node") if isinstance(run_metadata, dict) else None
        run_id = kwargs.get("run_id")
        sub_type = str(node) if node else None
        sub_id = f"{node}-{run_id}" if node and run_id else None
        decision = self._client.check(
            name, (input_str,), {}, event_type=self._event_type,
            subagent_id=sub_id, subagent_type=sub_type,
        )
        if decision.allow:  # honor the runtime decision (incl. org kill-switch / forced-enforce), not the app-passed mode
            return
        if self._client.resolve_block(decision, args=(input_str,)).approved:
            return  # approved → allowed
        raise PrismorBlocked(decision.reason or "policy violation", decision)
