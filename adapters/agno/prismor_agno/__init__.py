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
import weakref
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Union

from prismor.runtime.principal import Subject, resolve_subject
from prismor.runtime.redaction import redact_tool_result
from prismor.runtime.runtime import Decision, evaluate_tool_call
from prismor.runtime.subagent_context import nested_subagent, running

__all__ = ["make_tool_hook", "prismor_tool_hook", "guard_team", "PrismorBlocked"]

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


# The guard name each team leader's own calls are evaluated under, so a
# member's call (which may carry a hook of its own) inherits the leader's
# per-agent controls. Keyed by id(team); a finalizer drops it with the team.
_TEAM_GUARD: Dict[int, str] = {}


def _team_guard(team: Any, agent_obj: Any, guard_name: str) -> Optional[str]:
    """Record the leader's guard name; for a member call, return it as the parent."""
    if team is None:
        return None
    key = id(team)
    if agent_obj is None:  # the leader's own call
        if key not in _TEAM_GUARD:
            _TEAM_GUARD[key] = guard_name
            try:
                weakref.finalize(team, _TEAM_GUARD.pop, key, None)
            except TypeError:
                pass
        return None
    return _TEAM_GUARD.get(key)


def _subagent_of(agent_obj: Any, team: Any, label: str) -> tuple:
    """(subagent_id, subagent_type), or (None, None) for the main agent.

    Agno injects ``agent`` and ``team`` into a hook that declares them. A
    team leader's own call has a team and no agent; a standalone Agent has an
    agent and no team; a member running a delegated task has both: that member
    is the subagent. Anything run inside another guarded tool (a nested team,
    an agent used as a tool) is a subagent too.
    """
    if agent_obj is not None and team is not None:
        member = getattr(agent_obj, "name", None) or "member"
        return f"{member}:{id(agent_obj):x}", member
    return nested_subagent(getattr(team, "name", None) or getattr(agent_obj, "name", None) or label)


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
    agent_label = agent  # the framework id; `agent` in the hook is Agno's injected Agent

    def hook(function_name: str, function_call: Callable[..., Any], arguments: Dict[str, Any],
             agent: Any = None, team: Any = None) -> Any:
        field = _TYPE_FIELD.get(event_type, "command")
        label = getattr(team, "name", None) or getattr(agent, "name", None) or name or agent_label
        sub_id, sub_type = _subagent_of(agent, team, label)
        guard_name = name or agent_label
        parent = _team_guard(team, agent, guard_name)
        event = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "session_id": sid,
            "agent": agent_label,
            "agent_event": "PreToolUse",
            "type": event_type,
            field: _payload(arguments),
            "metadata": {
                "tool_name": function_name,
                "framework": "agno",
                "args": dict(arguments or {}),
                "subagent_id": sub_id,
                "subagent_type": sub_type,
                "parent_agent_name": parent if sub_id else None,
            },
        }
        decision: Decision = evaluate_tool_call(
            event=event, workspace=ws, agent=agent_label, agent_name=name or "", mode=mode,
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
        with running(label, agent_name=guard_name):
            result = function_call(**arguments)
        return redact_tool_result(result, workspace=ws, engine=decision.engine)

    return hook


# Default hook using module-level defaults (mode="enforce", cwd workspace, no
# subject) -- pass directly to Agent(tool_hooks=[prismor_tool_hook]) for the
# common case; use make_tool_hook(...) to customize.
prismor_tool_hook = make_tool_hook()


def guard_team(team: Any, **kwargs: Any) -> Any:
    """Add one Prismor tool hook to a ``Team`` and every member, recursively
    (nested teams included). Members run delegated work on the leader's
    authority, so they share its hook and per-agent controls; their calls are
    told apart by ``when: subagent.*``. A member left without a hook would run
    its tools unchecked. Takes make_tool_hook's arguments; returns the team.
    """
    hook = make_tool_hook(**kwargs)
    pending, seen = [team], set()
    while pending:
        node = pending.pop()
        if id(node) in seen:
            continue
        seen.add(id(node))
        hooks = list(getattr(node, "tool_hooks", None) or [])
        if hook not in hooks:
            node.tool_hooks = hooks + [hook]
        pending.extend(getattr(node, "members", None) or [])
    return team
