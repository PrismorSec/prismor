"""Prismor adapter for Microsoft Agent Framework (``pip install agent-framework``).

Routes every tool (function) call through
``prismor.runtime.runtime.evaluate_tool_call`` before the call runs — same
policy engine, observe/enforce model, and per-user attribution as the other
adapters.

Agent Framework's hook point for tool calls is *function middleware*: a
``FunctionMiddleware`` whose ``process(context, call_next)`` wraps the
invocation. The innermost link of the chain runs the function, so not
awaiting ``call_next()`` means the real tool never runs. A denied call sets
``context.result`` to the denial so the model sees a coherent tool response
and the run carries on (``MiddlewareTermination`` would end the whole loop).

Easy path::

    from agent_framework import Agent
    from agent_framework.openai import OpenAIChatClient
    from prismor.agent_framework import PrismorMiddleware

    agent = Agent(
        client=OpenAIChatClient(model="gpt-4o-mini"), name="ops", tools=[run_shell],
        middleware=[PrismorMiddleware(name="ops-bot", mode="enforce")],
    )

    with use_subject("user:alice"):      # per-request, multi-tenant
        await agent.run(prompt)
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable, Optional, Union

from prismor.runtime.principal import Subject, resolve_subject, use_subject
from prismor.runtime.redaction import redact_tool_result
from prismor.runtime.runtime import Decision, evaluate_tool_call
from prismor.runtime.subagent_context import nested_subagent, running

try:  # the base class only matters to Agent Framework's middleware sorter
    from agent_framework import FunctionMiddleware as _Base
except ImportError:  # importable (and testable) without the framework
    _Base = object

__all__ = ["PrismorMiddleware", "use_subject", "PrismorBlocked"]

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


def _args(arguments: Any) -> dict:
    if arguments is None:
        return {}
    if hasattr(arguments, "model_dump"):  # pydantic args model
        arguments = arguments.model_dump()
    try:
        return dict(arguments)
    except Exception:
        return {"value": str(arguments)}


class PrismorMiddleware(_Base):
    """Function middleware that policy-checks every tool call.

    Pass it in ``Agent(..., middleware=[PrismorMiddleware(...)])`` (or on the
    chat client). ``name`` is the instance label the console shows and
    controls; ``subject`` binds one end user, otherwise ``use_subject`` /
    ``PRISMOR_SUBJECT`` / the device identity apply per call. Give an agent
    used as a tool its own middleware and name: its calls then report as
    subagent ``name`` for ``when: subagent.*`` rules.
    """

    def __init__(
        self,
        *,
        name: Optional[str] = None,
        subject: Optional[Union[str, Subject]] = None,
        workspace: Optional[Union[str, Path]] = None,
        agent: str = "agent-framework",
        mode: str = "enforce",
        session_id: Optional[str] = None,
        event_type: str = "shell",
        raise_on_block: bool = False,
    ) -> None:
        self.name = name or ""
        self.subject = subject
        self.workspace = Path(workspace) if workspace else Path.cwd()
        self.agent = agent
        self.mode = mode
        self.session_id = session_id or f"agent-framework-{os.getpid()}"
        self.event_type = event_type
        self.raise_on_block = raise_on_block

    async def process(self, context: Any, call_next: Callable[[], Awaitable[None]]) -> None:
        args = _args(getattr(context, "arguments", None))
        # An agent used as a tool (agent.as_tool()) runs inside the parent's
        # function call, so its own middleware sees the parent still running:
        # that call is a subagent's, typed by this middleware's name.
        sub_id, sub_type = nested_subagent(self.name)
        field = _TYPE_FIELD.get(self.event_type, "command")
        event = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "session_id": self.session_id,
            "agent": self.agent,
            "agent_event": "PreToolUse",
            "type": self.event_type,
            field: " ".join(str(v) for v in args.values()).strip(),
            "metadata": {
                "tool_name": getattr(context.function, "name", str(context.function)),
                "framework": "agent-framework",
                "args": args,
                "subagent_id": sub_id,
                "subagent_type": sub_type,
            },
        }
        decision: Decision = evaluate_tool_call(
            event=event, workspace=self.workspace, agent=self.agent,
            agent_name=self.name, mode=self.mode, session_id=self.session_id,
            subject=resolve_subject(self.subject),
        )
        if not decision.allow:
            reason = decision.reason or "policy violation"
            if self.raise_on_block:
                raise PrismorBlocked(reason, decision)
            # Short-circuit: without call_next() the function never runs.
            context.result = f"⛔ Prismor blocked this tool call: {reason}"
            return
        with running(self.name):
            await call_next()
        # Redact the tool's OUTPUT before the framework hands it to the model.
        result = getattr(context, "result", None)
        if result is not None:
            redacted = redact_tool_result(result, workspace=self.workspace,
                                          engine=decision.engine)
            if redacted is not result:
                context.result = redacted
