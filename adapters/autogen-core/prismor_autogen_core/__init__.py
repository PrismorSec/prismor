"""Prismor adapter for AutoGen (Microsoft) — Core runtime.

Routes every tool call through ``prismor.runtime.runtime.evaluate_tool_call``
before the tool runs — same policy engine, observe/enforce model, and
per-user attribution as the other adapters.

CAVEAT (kept from the roadmap entry): this hooks the low-level
``autogen-core`` runtime, specifically the path used by
``autogen_core.tool_agent.tool_agent_caller_loop`` /
``autogen_core.tool_agent.ToolAgent``. Tool calls reach the ``ToolAgent``
as individual ``runtime.send_message(FunctionCall, recipient=tool_agent_id)``
calls, which is exactly the point an ``InterventionHandler.on_send`` sees.
The high-level ``AgentChat`` ``AssistantAgent`` (what most AutoGen users
actually build with) does not route tool execution through this same path,
so this adapter does not cover ``AssistantAgent`` usage.

Easy path::

    from autogen_core import SingleThreadedAgentRuntime
    from prismor.autogen_core import PrismorInterventionHandler

    runtime = SingleThreadedAgentRuntime(
        intervention_handlers=[PrismorInterventionHandler(subject="user:alice", mode="enforce")],
    )

Subagents: the runtime says which agent sent each FunctionCall
(``message_context.sender``). Calls from the main agent carry no subagent;
calls from any other agent are attributed to it (type = its AgentId type) for
``when: subagent.*`` rules. Name the main agent's type with ``main_agent=``;
otherwise the first agent seen sending a tool call is taken as the main one.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Union

from autogen_core import DefaultInterventionHandler, DropMessage, FunctionCall
from autogen_core.models import FunctionExecutionResult
from autogen_core.tool_agent import ToolException

from prismor.runtime.principal import Subject, resolve_subject
from prismor.runtime.redaction import redact_tool_result
from prismor.runtime.runtime import Decision, evaluate_tool_call

__all__ = ["PrismorInterventionHandler", "PrismorBlocked"]

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


def _payload(arguments: str) -> str:
    try:
        parsed = json.loads(arguments)
        if isinstance(parsed, dict):
            return " ".join(str(v) for v in parsed.values()).strip()
    except (json.JSONDecodeError, TypeError):
        pass
    return str(arguments)


class PrismorInterventionHandler(DefaultInterventionHandler):
    """InterventionHandler that policy-checks every FunctionCall on_send()
    before it reaches the ToolAgent. This is autogen-core's real hook: any
    message sent through the runtime passes through on_send() first, and
    returning DropMessage or raising cancels delivery."""

    def __init__(
        self,
        *,
        subject: Optional[Union[str, Subject]] = None,
        workspace: Optional[Union[str, Path]] = None,
        agent: str = "autogen-core",
        mode: str = "enforce",
        session_id: Optional[str] = None,
        event_type: str = "shell",
        drop_instead_of_raise: bool = False,
        main_agent: Optional[str] = None,
    ) -> None:
        self._subject = subject
        self._ws = Path(workspace) if workspace else Path.cwd()
        self._agent = agent
        self._mode = mode
        self._sid = session_id or f"autogen-core-{os.getpid()}"
        self._event_type = event_type
        self._drop = drop_instead_of_raise
        self._main = main_agent

    def _subagent(self, sender: Any) -> tuple:
        """(subagent_id, subagent_type) for the sending agent, or (None, None) for the main one."""
        sender_type = getattr(sender, "type", None)
        if not sender_type:
            return None, None
        if self._main is None:
            # ponytail: first sender is the main agent; pass main_agent= when
            # several agents can start at once.
            self._main = sender_type
        if sender_type == self._main:
            return None, None
        return str(sender), sender_type

    async def on_send(self, message: Any, *, message_context: Any, recipient: Any) -> Any:
        if not isinstance(message, FunctionCall):
            return message  # not a tool call -- pass through untouched

        field = _TYPE_FIELD.get(self._event_type, "command")
        sub_id, sub_type = self._subagent(getattr(message_context, "sender", None))
        event = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "session_id": self._sid,
            "agent": self._agent,
            "agent_event": "PreToolUse",
            "type": self._event_type,
            field: _payload(message.arguments),
            "metadata": {
                "tool_name": message.name,
                "framework": "autogen-core",
                "call_id": message.id,
                "recipient": str(recipient),
                "subagent_id": sub_id,
                "subagent_type": sub_type,
            },
        }
        decision: Decision = evaluate_tool_call(
            event=event,
            workspace=self._ws,
            agent=self._agent,
            mode=self._mode,
            session_id=self._sid,
            subject=resolve_subject(self._subject),
        )
        if not decision.allow:
            reason = decision.reason or "policy violation"
            if self._drop:
                return DropMessage
            # ToolException is caught specifically by tool_agent_caller_loop
            # and converted into a failed FunctionExecutionResult fed back to
            # the model -- the conversation continues with the denial visible
            # to the model, same UX as the other adapters' default behavior.
            exc = ToolException(
                call_id=message.id,
                content=f"⛔ Prismor blocked this tool call: {reason}",
                name=message.name,
            )
            # ToolException is a dataclass over BaseException, so str(exc) is
            # empty and the caller loop's f"Error: {result}" handed the model a
            # bare "Error: ". args is what str() renders.
            exc.args = (exc.content,)
            raise exc
        return message

    async def on_response(self, message: Any, *, sender: Any, recipient: Any) -> Any:
        """Redact a tool's OUTPUT on the return leg.

        ``on_send`` sees the request and can refuse it; the ToolAgent's reply
        comes back through here as a ``FunctionExecutionResult`` whose
        ``content`` is the raw tool output, on its way into the caller loop's
        message list. That is where a credential in an allowed tool's result
        would otherwise reach the model.
        """
        if isinstance(message, FunctionExecutionResult):
            redact_tool_result(message, workspace=self._ws)
        return message
