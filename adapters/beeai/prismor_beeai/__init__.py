"""Prismor adapter for BeeAI Framework (IBM Research / Linux Foundation).

Routes every tool call through ``prismor.runtime.runtime.evaluate_tool_call``
before the tool runs — same policy engine, observe/enforce model, and
per-user attribution as the other adapters.

The check wraps the tool's own ``_run``: ``Tool.run()`` validates the input
and then awaits ``self._run(...)``, so a denial raised there means the body
never runs, and it is raised as a ``ToolError`` -- the error BeeAI agents
catch and show the model. (An earlier version hooked the tool's "start"
event; the emitter re-wraps a listener's exception as a generic
``EmitterError``, so the model never saw why and the agent run crashed.)

RESULT REDACTION: not available here. The other adapters wrap the tool's
entrypoint and so hold its return value; this one attaches a listener to a
"start" event and never sees the output, so a credential in an allowed tool's
result is out of reach on this surface (see contract.SURFACES["sdk-adapter"]).

Easy path::

    from prismor.beeai import guard_tool

    tool = guard_tool(RunShellTool(), subject="user:alice", mode="enforce")
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Union

from beeai_framework.tools import ToolError

from prismor.runtime.principal import Subject, resolve_subject
from prismor.runtime.runtime import Decision, evaluate_tool_call
from prismor.runtime.subagent_context import nested_subagent, running

__all__ = ["guard_tool", "guard_tools", "PrismorBlocked"]

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


def _payload(tool_input: Any) -> str:
    try:
        data = tool_input.model_dump() if hasattr(tool_input, "model_dump") else dict(tool_input)
    except Exception:
        return str(tool_input)
    return " ".join(str(v) for v in data.values()).strip()


def guard_tool(
    tool: Any,
    *,
    subject: Optional[Union[str, Subject]] = None,
    workspace: Optional[Union[str, Path]] = None,
    agent: str = "beeai",
    mode: str = "enforce",
    session_id: Optional[str] = None,
    event_type: str = "shell",
    raise_on_block: bool = False,
    name: str = "",
) -> Any:
    """Policy-check every call of a BeeAI tool before its body runs.

    A denied call raises ``ToolError`` with the reason, which the agent hands
    back to the model; ``self._run()``'s original body is never reached.
    Returns the same tool object. ``name`` labels the agent these tools belong
    to (the console's per-agent row, and its type when it runs as a subagent).

    BeeAI runs a subagent from a tool -- a ``HandoffTool`` runs its target
    agent inside its own call. Guard the HandoffTool too: the agent it runs is
    then reported as subagent ``<target name>`` (or this ``name`` when set).
    """
    if getattr(tool, "__prismor_guarded__", False):
        return tool
    ws = Path(workspace) if workspace else Path.cwd()
    sid = session_id or f"beeai-{os.getpid()}"
    tool_name = getattr(tool, "name", tool.__class__.__name__)

    original_run = tool._run

    target = getattr(tool, "_target", None)  # HandoffTool: the agent it runs
    target_meta = getattr(target, "meta", None)
    target_name = getattr(target_meta, "name", None)

    async def guarded_run(input: Any, options: Any, context: Any) -> Any:
        field = _TYPE_FIELD.get(event_type, "command")
        sub_id, sub_type = nested_subagent(name)
        payload_event = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "session_id": sid,
            "agent": agent,
            "agent_event": "PreToolUse",
            "type": event_type,
            field: _payload(input),
            "metadata": {
                "tool_name": tool_name,
                "framework": "beeai",
                "raw_input": str(input),
                "subagent_id": sub_id,
                "subagent_type": sub_type,
                # A HandoffTool's input is what its target agent is handed.
                **({"handoff_to": target_name or tool_name} if target is not None else {}),
            },
        }
        decision: Decision = evaluate_tool_call(
            event=payload_event, workspace=ws, agent=agent, agent_name=name, mode=mode,
            session_id=sid, subject=resolve_subject(subject),
        )
        if not decision.allow:
            reason = decision.reason or "policy violation"
            if raise_on_block:
                raise PrismorBlocked(reason, decision)
            # A ToolError is what BeeAI agents catch and hand to the model. The
            # "start"-event listener this replaced raised inside the emitter,
            # which re-wraps it as a generic EmitterError ("Error during event
            # emission"): the reason was lost and the agent run crashed.
            raise ToolError(f"⛔ Prismor blocked this tool call: {reason}")
        # The agent a handoff runs reports as <target name> when its own
        # tools carry no name=; this guard's agent is its parent.
        with running(name or agent, getattr(context, "run_id", None),
                     agent_name=name or agent, child_type=target_name):
            return await original_run(input, options, context)

    # ponytail: wraps the body, so a hit in the tool's (opt-in) result cache is
    # served without a policy check. Move the check ahead of the cache if a
    # guarded tool ever enables one.
    tool._run = guarded_run

    # The agent a HandoffTool runs is a subagent on this agent's authority:
    # guard its tools with the same settings, so guarding the main agent's
    # tools covers what it hands off to (recursively, via its own handoffs).
    # They report under the target's name; this agent's controls still apply
    # to them as their parent (the running() context below names it).
    for sub_tool in list(getattr(target, "_tools", None) or []):
        guard_tool(sub_tool, subject=subject, workspace=workspace, agent=agent,
                   mode=mode, session_id=session_id, event_type=event_type,
                   raise_on_block=raise_on_block, name=target_name or "")

    # A HandoffTool clones its target agent, and RequirementAgent.clone clones
    # every tool; FunctionTool.clone builds a fresh tool, which dropped this
    # guard: a handed-off agent's tools ran unchecked. Guard the clone too.
    original_clone = tool.clone

    async def guarded_clone() -> Any:
        return guard_tool(
            await original_clone(), subject=subject, workspace=workspace, agent=agent,
            mode=mode, session_id=session_id, event_type=event_type,
            raise_on_block=raise_on_block, name=name)

    tool.clone = guarded_clone
    tool.__prismor_guarded__ = True
    return tool


def guard_tools(tools: Any, **kwargs: Any) -> Any:
    """Guard a list of BeeAI tools in one call. Returns the same list."""
    return [guard_tool(t, **kwargs) for t in tools]
