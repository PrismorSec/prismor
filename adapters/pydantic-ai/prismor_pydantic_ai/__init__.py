"""Prismor adapter for Pydantic AI.

Routes every tool call through ``prismor.runtime.runtime.evaluate_tool_call``
before the tool runs — same policy engine, observe/enforce model, and
per-user attribution as the other adapters.

Pydantic AI's real interception point is a ``WrapperToolset`` subclass:
``call_tool(name, tool_args, ctx, tool)`` is the single choke point every
tool call passes through, regardless of whether the tool is a plain
Python function, an MCP-server tool, or a toolset composed from several
of the above. This is a hard pre-execution gate — not calling
``super().call_tool(...)`` means the wrapped tool never runs.

Easy path::

    from pydantic_ai import Agent
    from prismor.pydantic_ai import guard_toolsets

    agent = Agent('openai:gpt-4o-mini', toolsets=guard_toolsets(
        [my_toolset], subject="user:alice", mode="enforce",
    ))

Subagents: Pydantic AI delegates by running another agent inside a tool
(``await researcher.run(..., usage=ctx.usage)``). A guarded call made while a
guarded tool is running is attributed to a subagent whose type is the inner
toolset's ``name=``, so give each agent's toolsets their own name.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Union

from pydantic_ai.exceptions import ToolFailed
from pydantic_ai.toolsets import WrapperToolset

from prismor.runtime.principal import Subject, resolve_subject
from prismor.runtime.redaction import redact_tool_result
from prismor.runtime.runtime import Decision, evaluate_tool_call
from prismor.runtime.subagent_context import nested_subagent, running

__all__ = ["guard_toolsets", "PrismorToolset", "PrismorBlocked"]

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


def _payload(tool_args: Dict[str, Any]) -> str:
    return " ".join(str(v) for v in (tool_args or {}).values()).strip()


class PrismorToolset(WrapperToolset):
    """WrapperToolset that policy-checks every call_tool() before delegating.

    This is the real Pydantic AI hook: call_tool(name, tool_args, ctx, tool)
    is the single choke point every tool call passes through.
    """

    def __init__(
        self,
        wrapped: Any,
        *,
        subject: Optional[Union[str, Subject]] = None,
        workspace: Optional[Union[str, Path]] = None,
        agent: str = "pydantic-ai",
        name: Optional[str] = None,
        mode: str = "enforce",
        session_id: Optional[str] = None,
        event_type: str = "shell",
        raise_on_block: bool = False,
    ) -> None:
        super().__init__(wrapped)  # type: ignore[call-arg]
        object.__setattr__(self, "_prismor_subject", subject)
        object.__setattr__(self, "_prismor_ws", Path(workspace) if workspace else Path.cwd())
        object.__setattr__(self, "_prismor_agent", agent)
        object.__setattr__(self, "_prismor_name", name or "")
        object.__setattr__(self, "_prismor_mode", mode)
        object.__setattr__(self, "_prismor_sid", session_id or f"pydantic-ai-{os.getpid()}")
        object.__setattr__(self, "_prismor_event_type", event_type)
        object.__setattr__(self, "_prismor_raise", raise_on_block)

    async def call_tool(self, name: str, tool_args: Dict[str, Any], ctx: Any, tool: Any) -> Any:
        field = _TYPE_FIELD.get(self._prismor_event_type, "command")  # type: ignore[attr-defined]
        label = self._prismor_name or self._prismor_agent  # type: ignore[attr-defined]
        sub_id, sub_type = nested_subagent(label)
        event = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "session_id": getattr(ctx, "run_id", None) or self._prismor_sid,  # type: ignore[attr-defined]
            "agent": self._prismor_agent,  # type: ignore[attr-defined]
            "agent_event": "PreToolUse",
            "type": self._prismor_event_type,  # type: ignore[attr-defined]
            field: _payload(tool_args),
            "metadata": {
                "tool_name": name,
                "framework": "pydantic-ai",
                "tool_call_id": getattr(ctx, "tool_call_id", None),
                "args": dict(tool_args or {}),
                "subagent_id": sub_id,
                "subagent_type": sub_type,
            },
        }
        decision: Decision = evaluate_tool_call(
            event=event,
            workspace=self._prismor_ws,  # type: ignore[attr-defined]
            agent=self._prismor_agent,  # type: ignore[attr-defined]
            agent_name=self._prismor_name,  # type: ignore[attr-defined]
            mode=self._prismor_mode,  # type: ignore[attr-defined]
            session_id=event["session_id"],
            subject=resolve_subject(self._prismor_subject),  # type: ignore[attr-defined]
        )
        if not decision.allow:
            reason = decision.reason or "policy violation"
            if self._prismor_raise:  # type: ignore[attr-defined]
                raise PrismorBlocked(reason, decision)
            # ToolFailed -> the model sees a definitive failure and adapts,
            # without the retry-budget consumption ModelRetry implies (this
            # is a policy denial, not a transient/correctable error).
            raise ToolFailed(f"⛔ Prismor blocked this tool call: {reason}")
        # call_tool is also the single choke point the RESULT comes back
        # through, so the same wrapper that refuses a call can repair one.
        # An agent run inside this tool is a subagent of this one.
        with running(label, getattr(ctx, "tool_call_id", None)):
            result = await super().call_tool(name, tool_args, ctx, tool)
        return redact_tool_result(
            result,
            workspace=self._prismor_ws,  # type: ignore[attr-defined]
            engine=decision.engine,
        )


def guard_toolsets(toolsets: Sequence[Any], **kwargs: Any) -> List[PrismorToolset]:
    """Wrap a list of toolsets (or bare tool functions via FunctionToolset) so
    every call is policy-checked. Returns new PrismorToolset instances."""
    return [PrismorToolset(t, **kwargs) for t in toolsets]
