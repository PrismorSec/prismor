"""Prismor adapter for Agno.

Routes every tool call through ``prismor.runtime.runtime.evaluate_tool_call``
before the tool runs — same policy engine, observe/enforce model, and
per-user attribution as the other adapters.

Agno's real hook point is the ``tool_hooks`` list on ``Agent``/``Team``
(distinct from the singular ``pre_hook``/``post_hook``, whose exceptions are
not guaranteed to be surfaced the same way). Each hook is threaded into a
nested execution chain around the tool's entrypoint — Agno introspects the
hook's own signature and injects whichever of ``function_name`` /
``function_call`` / ``args`` (or ``arguments``) it declares.
``function_call`` here is *not* a data object — it's the callable that
continues the chain; not calling it means the real tool never runs, and any
exception raised propagates normally (verified against source: the
try/finally wrapper around hook calls only isolates message-list state,
it does not swallow exceptions).

Easy path::

    from agno.agent import Agent
    from prismor.agno import prismor_tool_hook

    agent = Agent(model=..., tools=[run_shell], tool_hooks=[prismor_tool_hook])
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Union

from prismor.runtime.principal import Subject, resolve_subject
from prismor.runtime.redaction import redact_tool_result
from prismor.runtime.runtime import Decision, evaluate_tool_call

__all__ = ["make_tool_hook", "prismor_tool_hook", "PrismorBlocked"]

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


def _payload(arguments: Dict[str, Any]) -> str:
    return " ".join(str(v) for v in (arguments or {}).values()).strip()


def make_tool_hook(
    *,
    subject: Optional[Union[str, Subject]] = None,
    workspace: Optional[Union[str, Path]] = None,
    agent: str = "agno",
    name: Optional[str] = None,
    mode: str = "enforce",
    session_id: Optional[str] = None,
    event_type: str = "shell",
    raise_on_block: bool = False,
) -> Callable[..., Any]:
    """Build a Prismor tool_hook bound to the given subject/workspace/mode.

    Pass the returned callable in ``Agent(tool_hooks=[...])``. Use this
    (rather than the bare ``prismor_tool_hook``) whenever you need a
    non-default subject, workspace, or mode.
    """
    ws = Path(workspace) if workspace else Path.cwd()
    sid = session_id or f"agno-{os.getpid()}"

    def hook(function_name: str, function_call: Callable[..., Any], arguments: Dict[str, Any]) -> Any:
        field = _TYPE_FIELD.get(event_type, "command")
        event = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "session_id": sid,
            "agent": agent,
            "agent_event": "PreToolUse",
            "type": event_type,
            field: _payload(arguments),
            "metadata": {
                "tool_name": function_name,
                "framework": "agno",
                "args": dict(arguments or {}),
            },
        }
        decision: Decision = evaluate_tool_call(
            event=event, workspace=ws, agent=agent, agent_name=name or "", mode=mode,
            session_id=sid, subject=resolve_subject(subject),
        )
        if not decision.allow:
            reason = decision.reason or "policy violation"
            if raise_on_block:
                raise PrismorBlocked(reason, decision)
            # The hook's return value IS the tool result, so the model reads
            # the denial. Raising made Agno log an ERROR with a traceback for
            # an ordinary, expected block.
            return f"⛔ Prismor blocked this tool call: {reason}"
        # The hook chain hands back the tool's own return value: redact it
        # here, the last point before Agno folds it into the model's context.
        return redact_tool_result(function_call(**arguments), workspace=ws,
                                  engine=decision.engine)

    return hook


# Default hook using module-level defaults (mode="enforce", cwd workspace, no
# subject) -- pass directly to Agent(tool_hooks=[prismor_tool_hook]) for the
# common case; use make_tool_hook(...) to customize.
prismor_tool_hook = make_tool_hook()
