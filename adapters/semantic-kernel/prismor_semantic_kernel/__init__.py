"""Prismor adapter for Semantic Kernel (Microsoft).

Routes every tool (function) call through
``prismor.runtime.runtime.evaluate_tool_call`` before the call runs — same
policy engine, observe/enforce model, and per-user attribution as the other
adapters.

Semantic Kernel's real hook point for LLM-initiated tool calls is the
``AUTO_FUNCTION_INVOCATION`` filter: ``kernel.add_filter(FilterTypes.AUTO_FUNCTION_INVOCATION,
filter_fn)`` where ``filter_fn(context, next)`` wraps the actual invocation.
Every registered filter is composed into a single middleware stack; the
innermost link calls ``context.function.invoke(...)``. Simply not calling
``await next(context)`` means that inner call — and therefore the real
tool — never runs. This is the cleanest gate-then-continue semantics of
any framework Prismor integrates with.

Easy path::

    from semantic_kernel import Kernel
    from semantic_kernel.filters import FilterTypes
    from prismor.semantic_kernel import make_filter

    kernel = Kernel()
    kernel.add_filter(FilterTypes.AUTO_FUNCTION_INVOCATION, make_filter(subject="user:alice", mode="enforce"))
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, Optional, Union

from semantic_kernel.functions.function_result import FunctionResult

from prismor.runtime.principal import Subject, resolve_subject
from prismor.runtime.redaction import redact_tool_result
from prismor.runtime.runtime import Decision, evaluate_tool_call
from prismor.runtime.subagent_context import nested_subagent, running

__all__ = ["make_filter", "PrismorBlocked"]

_TYPE_FIELD = {
    "shell": "command",
    "file_read": "path",
    "file_write": "path",
    "network": "url",
    "prompt": "content",
    "tool_result": "content",
}


class PrismorBlocked(Exception):
    def __init__(self, reason: str, decision: Optional[Decision] = None) -> None:
        super().__init__(reason or "blocked by Prismor policy")
        self.decision = decision


def _payload(arguments: Any) -> str:
    try:
        items = dict(arguments).values()
    except Exception:
        return str(arguments)
    return " ".join(str(v) for v in items).strip()


def make_filter(
    *,
    subject: Optional[Union[str, Subject]] = None,
    workspace: Optional[Union[str, Path]] = None,
    agent: str = "semantic-kernel",
    mode: str = "enforce",
    session_id: Optional[str] = None,
    event_type: str = "shell",
    raise_on_block: bool = False,
    name: str = "",
) -> Callable[[Any, Callable[[Any], Awaitable[None]]], Awaitable[None]]:
    """Build a Prismor AUTO_FUNCTION_INVOCATION filter bound to the given
    subject/workspace/mode. Pass the returned coroutine to
    ``kernel.add_filter(FilterTypes.AUTO_FUNCTION_INVOCATION, ...)``.

    ``name`` labels this agent. An agent used as another agent's plugin runs
    inside the parent's function call; give its kernel its own filter and
    name, and its calls report as subagent ``name`` for ``when: subagent.*``.
    """
    ws = Path(workspace) if workspace else Path.cwd()
    sid = session_id or f"semantic-kernel-{os.getpid()}"

    async def prismor_filter(context: Any, next: Callable[[Any], Awaitable[None]]) -> None:
        fn = context.function
        tool_name = f"{fn.plugin_name}-{fn.name}" if getattr(fn, "plugin_name", None) else fn.name
        field = _TYPE_FIELD.get(event_type, "command")
        sub_id, sub_type = nested_subagent(name)
        event = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "session_id": sid,
            "agent": agent,
            "agent_event": "PreToolUse",
            "type": event_type,
            field: _payload(context.arguments),
            "metadata": {
                "tool_name": tool_name,
                "framework": "semantic-kernel",
                "args": dict(context.arguments) if context.arguments else {},
                "subagent_id": sub_id,
                "subagent_type": sub_type,
            },
        }
        decision: Decision = evaluate_tool_call(
            event=event, workspace=ws, agent=agent, agent_name=name, mode=mode,
            session_id=sid, subject=resolve_subject(subject),
        )
        if not decision.allow:
            reason = decision.reason or "policy violation"
            if raise_on_block:
                raise PrismorBlocked(reason, decision)
            # Deny by NOT calling next(context) -- the inner handler
            # (context.function.invoke(...)) is only reached via the chain
            # `next` builds; skipping it means the real tool never runs.
            # Set a synthetic function_result so the model still sees a
            # coherent (denied) tool response rather than an empty one.
            context.function_result = FunctionResult(
                function=fn.metadata,
                value=f"⛔ Prismor blocked this tool call: {reason}",
            )
            return
        with running(name):
            await next(context)
        # The chain leaves the function's OUTPUT on context.function_result;
        # redact it before Semantic Kernel folds it into the chat history.
        result = getattr(context, "function_result", None)
        if result is not None:
            redacted = redact_tool_result(result, workspace=ws,
                                          engine=decision.engine)
            if redacted is not result:
                context.function_result = redacted

    return prismor_filter
