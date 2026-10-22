"""Prismor adapter for Google Agent Development Kit (ADK).

Routes every tool call through ``prismor.runtime.runtime.evaluate_tool_call``
before the tool runs — same policy engine, observe/enforce model, and
per-user attribution as the other adapters.

ADK's real hook point is ``before_tool_callback(tool, args, tool_context)``,
set on ``LlmAgent(before_tool_callback=fn)``. Deny is by *substitution*,
not exception: returning ``None`` lets the real tool run; returning a
``dict`` skips the real tool call entirely and that dict becomes the tool's
result instead — the model never sees the tool actually execute.

Easy path::

    from google.adk.agents import LlmAgent
    from prismor.google_adk import make_before_tool_callback

    agent = LlmAgent(
        model="gemini-flash-latest", name="ops", tools=[run_shell],
        before_tool_callback=make_before_tool_callback(subject="user:alice", mode="enforce"),
        after_tool_callback=make_after_tool_callback(),
    )

The after-callback is the result side of the same gate: ADK hands it
``tool_response`` and a dict return REPLACES it, so a credential sitting in
an otherwise-allowed tool's output is masked before the model reads it.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Union

from prismor.runtime.principal import Subject, resolve_subject
from prismor.runtime.redaction import redact_tool_result
from prismor.runtime.runtime import Decision, evaluate_tool_call

__all__ = ["make_before_tool_callback", "make_after_tool_callback", "PrismorPlugin", "PrismorBlocked"]

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


def _payload(args: Dict[str, Any]) -> str:
    return " ".join(str(v) for v in (args or {}).values()).strip()


def make_before_tool_callback(
    *,
    subject: Optional[Union[str, Subject]] = None,
    workspace: Optional[Union[str, Path]] = None,
    agent: str = "google-adk",
    mode: str = "enforce",
    session_id: Optional[str] = None,
    event_type: str = "shell",
    raise_on_block: bool = False,
    name: Optional[str] = None,
) -> Callable[[Any, Dict[str, Any], Any], Optional[Dict[str, Any]]]:
    """Build a Prismor before_tool_callback bound to the given
    subject/workspace/mode. Pass the returned callable as
    ``LlmAgent(before_tool_callback=...)``. ``name`` is the instance label
    the console shows and controls on its own (e.g. ``"support-bot"``).
    """
    ws = Path(workspace) if workspace else Path.cwd()
    sid = session_id or f"google-adk-{os.getpid()}"

    def callback(tool: Any, args: Dict[str, Any], tool_context: Any) -> Optional[Dict[str, Any]]:
        field = _TYPE_FIELD.get(event_type, "command")
        run_id = getattr(tool_context, "invocation_id", None) or sid
        event = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "session_id": run_id,
            "agent": agent,
            "agent_event": "PreToolUse",
            "type": event_type,
            field: _payload(args),
            "metadata": {
                "tool_name": getattr(tool, "name", str(tool)),
                "framework": "google-adk",
                "args": dict(args or {}),
            },
        }
        decision: Decision = evaluate_tool_call(
            event=event, workspace=ws, agent=agent, agent_name=name or "",
            mode=mode, session_id=run_id, subject=resolve_subject(subject),
        )
        if not decision.allow:
            reason = decision.reason or "policy violation"
            if raise_on_block:
                raise PrismorBlocked(reason, decision)
            # Deny-by-substitution: a dict return SKIPS the real tool call
            # entirely and becomes the tool's result -- ADK's own mechanism,
            # not an exception.
            return {"error": f"⛔ Prismor blocked this tool call: {reason}"}
        return None  # None -> proceed with the real tool call

    return callback


def make_after_tool_callback(
    *,
    workspace: Optional[Union[str, Path]] = None,
) -> Callable[[Any, Dict[str, Any], Any, Any], Optional[Any]]:
    """Build a Prismor after_tool_callback that redacts the tool's OUTPUT.

    ``before_tool_callback`` sees only the request. This one is handed the
    tool's response, and a non-``None`` return REPLACES it — ADK's own
    substitution mechanism, the same one the before-callback denies through.
    Best-effort by contract: it never raises, so a masking failure can never
    turn into a failed tool call.
    """
    ws = Path(workspace) if workspace else Path.cwd()

    def callback(tool: Any, args: Dict[str, Any], tool_context: Any,
                 tool_response: Any) -> Optional[Any]:
        redacted = redact_tool_result(tool_response, workspace=ws)
        # None -> ADK keeps the original response (which, for a result object
        # redacted in place, is already the masked one).
        return redacted if redacted != tool_response else None

    return callback


try:  # ADK's plugin system; optional so this module imports without google-adk
    from google.adk.plugins.base_plugin import BasePlugin as _BasePlugin
except ImportError:
    _BasePlugin = object


class PrismorPlugin(_BasePlugin):
    """One plugin that guards every agent a ``Runner`` hosts.

    ``Runner(..., plugins=[PrismorPlugin(name="support-bot", mode="enforce")])``
    -- plugin callbacks run before agent-level ones, so sub-agents and agents
    added later are covered without touching each ``LlmAgent``. Takes the same
    keyword arguments as :func:`make_before_tool_callback`.
    """

    def __init__(self, **kwargs: Any) -> None:
        if _BasePlugin is not object:
            super().__init__(name="prismor")
        self._before = make_before_tool_callback(**kwargs)
        self._after = make_after_tool_callback(workspace=kwargs.get("workspace"))

    async def before_tool_callback(self, *, tool: Any, tool_args: Dict[str, Any],
                                   tool_context: Any) -> Optional[Dict[str, Any]]:
        return self._before(tool, tool_args, tool_context)

    async def after_tool_callback(self, *, tool: Any, tool_args: Dict[str, Any],
                                  tool_context: Any, result: Any) -> Optional[Any]:
        return self._after(tool, tool_args, tool_context, result)
