"""Prismor adapter for AG2 (``pip install ag2``).

Routes every tool call through ``prismor.runtime.runtime.evaluate_tool_call``
before the tool runs — same policy engine, observe/enforce model, and
per-user attribution as the other adapters. (AG2 is the community fork of
AutoGen; ``autogen-core`` has its own adapter in ``prismor.autogen_core``.)

AG2 1.x (``import ag2``) runs every tool call through its middleware chain:
``BaseMiddleware.on_tool_execution(call_next, event, context)`` wraps the
execution, and not awaiting ``call_next`` means the tool never runs. A denied
call returns ``ToolResultEvent.from_call(event, denial)``, the same shape AG2's
own ``approval_required`` middleware uses, so the model gets the denial as the
tool result and the turn carries on::

    from ag2 import Agent
    from prismor.ag2 import prismor_middleware

    agent = Agent("ops", "You are an ops assistant.", config=config,
                  tools=[run_shell, lookup_order],
                  middleware=[prismor_middleware(name="support-bot", mode="enforce")])

AG2 0.x (``import autogen``) executes tools from the executor agent's
``function_map``; :func:`guard_agent` wraps every function registered there::

    register_function(run_shell, caller=assistant, executor=user_proxy, ...)
    guard_agent(user_proxy, name="support-bot", mode="enforce")

Subagents: an agent (or chat) run from inside a guarded tool is a subagent of
the agent whose tool launched it; its guarded calls carry subagent type = its
own ``name=``, so give each agent its own name. Group-chat peers and nested
chats started from a reply (not a tool) are not subagents here.
"""
from __future__ import annotations

import asyncio
import functools
import inspect
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Union

from prismor.runtime.principal import Subject, resolve_subject, use_subject
from prismor.runtime.redaction import redact_tool_result
from prismor.runtime.runtime import Decision, evaluate_tool_call
from prismor.runtime.subagent_context import nested_subagent, running

try:  # AG2 1.x; the adapter stays importable (and testable) without it
    from ag2.middleware.base import BaseMiddleware as _Base
except ImportError:
    _Base = object

__all__ = ["prismor_middleware", "PrismorMiddleware", "guard_agent", "use_subject", "PrismorBlocked"]

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


def _check(tool_name: str, args: Dict[str, Any], *, subject, workspace: Path, agent: str,
           name: str, mode: str, session_id: str, event_type: str,
           raise_on_block: bool) -> "tuple[Optional[str], Decision]":
    """One policy check. Returns (denial text or None, decision)."""
    field = _TYPE_FIELD.get(event_type, "command")
    # asyncio.to_thread copies the context, so this sees a launching tool too.
    sub_id, sub_type = nested_subagent(name or agent)
    event = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "session_id": session_id,
        "agent": agent,
        "agent_event": "PreToolUse",
        "type": event_type,
        field: " ".join(str(v) for v in args.values()).strip(),
        "metadata": {"tool_name": tool_name, "framework": "ag2",
                     "args": {k: str(v) for k, v in args.items()},
                     "subagent_id": sub_id, "subagent_type": sub_type},
    }
    decision: Decision = evaluate_tool_call(
        event=event, workspace=workspace, agent=agent, agent_name=name, mode=mode,
        session_id=session_id, subject=resolve_subject(subject),
    )
    if decision.allow:
        return None, decision
    reason = decision.reason or "policy violation"
    if raise_on_block:
        raise PrismorBlocked(reason, decision)
    return f"⛔ Prismor blocked this tool call: {reason}", decision


class PrismorMiddleware(_Base):
    """AG2 1.x middleware. Register it through :func:`prismor_middleware`
    (AG2 instantiates middleware per turn from a factory)."""

    def __init__(
        self,
        event: Any = None,
        context: Any = None,
        *,
        name: str = "",
        subject: Optional[Union[str, Subject]] = None,
        workspace: Optional[Union[str, Path]] = None,
        agent: str = "ag2",
        mode: str = "enforce",
        session_id: Optional[str] = None,
        event_type: str = "shell",
        raise_on_block: bool = False,
    ) -> None:
        self.initial_event, self.context = event, context
        self._opts = dict(
            subject=subject, workspace=Path(workspace) if workspace else Path.cwd(),
            agent=agent, name=name, mode=mode,
            session_id=session_id or f"ag2-{os.getpid()}",
            event_type=event_type, raise_on_block=raise_on_block,
        )

    async def on_tool_execution(self, call_next: Callable, event: Any, context: Any) -> Any:
        args = getattr(event, "serialized_arguments", None)
        if not isinstance(args, dict):
            try:
                args = json.loads(getattr(event, "arguments", "") or "{}")
            except ValueError:
                args = {"arguments": str(getattr(event, "arguments", ""))}
        # A step-up approval can wait on a human; keep the event loop free.
        denial, decision = await asyncio.to_thread(_check, event.name, args, **self._opts)
        if denial is not None:
            from ag2.events import ToolResultEvent
            return ToolResultEvent.from_call(event, result=denial)
        with running(self._opts["name"] or self._opts["agent"], getattr(event, "id", None)):
            result = await call_next(event, context)
        # Mask credentials in the tool's output before the model reads it.
        for i, part in enumerate(getattr(getattr(result, "result", None), "parts", None) or []):
            text = getattr(part, "content", None)
            if isinstance(text, str):
                masked = redact_tool_result(text, workspace=self._opts["workspace"],
                                            engine=decision.engine)
                if masked != text:
                    result.result.parts[i] = type(part)(masked)
        return result


def prismor_middleware(**kwargs: Any) -> Any:
    """The middleware factory to pass in ``Agent(middleware=[...])`` (AG2 1.x)."""
    from ag2 import Middleware
    return Middleware(PrismorMiddleware, **kwargs)


def guard_agent(
    agent: Any,
    *,
    name: str = "",
    subject: Optional[Union[str, Subject]] = None,
    workspace: Optional[Union[str, Path]] = None,
    mode: str = "enforce",
    session_id: Optional[str] = None,
    event_type: str = "shell",
    raise_on_block: bool = False,
) -> Any:
    """Guard an existing AG2 agent. Returns the agent.

    AG2 1.x: adds :func:`prismor_middleware` with these options to the agent.
    AG2 0.x: wraps every function in the executor agent's ``function_map`` —
    call it after ``register_function`` / ``register_for_execution``. A denied
    call returns the denial string as the function's result, so the executor
    replies with it and the conversation carries on.
    """
    if hasattr(agent, "add_middleware"):  # AG2 1.x
        agent.add_middleware(prismor_middleware(
            name=name, subject=subject, workspace=workspace, mode=mode,
            session_id=session_id, event_type=event_type, raise_on_block=raise_on_block))
        return agent
    fmap = getattr(agent, "_function_map", None)
    if fmap is None:
        raise TypeError("guard_agent expects an AG2 Agent (1.x) or an executor "
                        "ConversableAgent with registered functions (0.x)")
    opts = dict(subject=subject, workspace=Path(workspace) if workspace else Path.cwd(),
                agent="ag2", name=name, mode=mode,
                session_id=session_id or f"ag2-{os.getpid()}",
                event_type=event_type, raise_on_block=raise_on_block)

    def _wrap(tool_name: str, fn: Callable) -> Callable:
        if getattr(fn, "__prismor_guarded__", False):
            return fn
        if inspect.iscoroutinefunction(fn):
            @functools.wraps(fn)
            async def guarded(**kwargs: Any) -> Any:
                denial, decision = await asyncio.to_thread(_check, tool_name, kwargs, **opts)
                if denial is not None:
                    return denial
                with running(name or "ag2"):
                    result = await fn(**kwargs)
                return redact_tool_result(result, workspace=opts["workspace"],
                                          engine=decision.engine)
        else:
            @functools.wraps(fn)
            def guarded(**kwargs: Any) -> Any:
                denial, decision = _check(tool_name, kwargs, **opts)
                if denial is not None:
                    return denial
                with running(name or "ag2"):
                    result = fn(**kwargs)
                return redact_tool_result(result, workspace=opts["workspace"],
                                          engine=decision.engine)
        guarded.__prismor_guarded__ = True
        return guarded

    for tool_name, fn in list(fmap.items()):
        fmap[tool_name] = _wrap(tool_name, fn)
    return agent
