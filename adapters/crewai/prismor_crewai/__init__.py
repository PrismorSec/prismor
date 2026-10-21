"""Prismor adapter for CrewAI.

Routes every CrewAI tool invocation through ``prismor.runtime.runtime.evaluate_tool_call``
before the tool runs — same policy engine, observe/enforce model, and per-user
attribution as the other adapters.

CrewAI tools come in a few shapes (``@tool``-decorated structured tools, and
``BaseTool`` subclasses with ``_run``). :func:`prismor_guard_tool` wraps whichever
callable the tool exposes (``func`` / ``_run`` / ``run``), so a denied call never
executes. Returns the same tool object.

Easy path::

    from crewai import Agent
    from prismor.crewai import guard_tools

    tools = guard_tools([run_shell], subject="user:alice")
    agent = Agent(role="ops", tools=tools, ...)
"""
from __future__ import annotations

import functools
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, List, Optional, Sequence, Union

from prismor.runtime.redaction import redact_tool_result
from prismor.runtime.principal import Subject, resolve_subject, use_subject
from prismor.runtime.runtime import Decision, evaluate_tool_call, log_observe_findings

__all__ = ["guard_tools", "prismor_guard_tool", "use_subject", "PrismorBlocked"]

_TYPE_FIELD = {
    "shell": "command",
    "file_read": "path",
    "file_write": "path",
    "network": "url",
    "prompt": "content",
    "tool_result": "content",
}

# Tool attributes that hold the actual implementation, in preference order.
_IMPL_ATTRS = ("func", "_run", "run")


class PrismorBlocked(Exception):
    def __init__(self, reason: str, decision: Optional[Decision] = None) -> None:
        super().__init__(reason or "blocked by Prismor policy")
        self.decision = decision


def _payload(args: tuple, kwargs: dict) -> str:
    parts = [str(a) for a in args]
    parts += [str(v) for v in kwargs.values()]
    return " ".join(parts).strip()


def _evaluate(*, tool_name, args, kwargs, subject, ws, agent, mode, sid, event_type, agent_name="") -> Decision:
    field = _TYPE_FIELD.get(event_type, "command")
    event = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "session_id": sid,
        "agent": agent,
        "agent_event": "PreToolUse",
        "type": event_type,
        field: _payload(args, kwargs),
        "metadata": {
            "tool_name": tool_name,
            "framework": "crewai",
            "args": list(args),
            "kwargs": dict(kwargs or {}),
        },
    }
    return evaluate_tool_call(
        event=event, workspace=ws, agent=agent, agent_name=agent_name,
        mode=mode, session_id=sid, subject=resolve_subject(subject),
    )


class _RunWith:
    """Sentinel from ``_decide``: run the tool, but with these (redacted) args."""

    __slots__ = ("args", "kwargs")

    def __init__(self, args: tuple, kwargs: dict) -> None:
        self.args = tuple(args)
        self.kwargs = dict(kwargs)


def prismor_guard_tool(
    tool: Any,
    *,
    subject: Optional[Union[str, Subject]] = None,
    workspace: Optional[Union[str, Path]] = None,
    agent: str = "crewai",
    name: str = "",
    mode: str = "observe",
    session_id: Optional[str] = None,
    event_type: str = "shell",
    raise_on_block: bool = False,
    approvals: bool = True,
) -> Any:
    """Wrap a CrewAI tool's implementation so calls are policy-checked."""
    if getattr(tool, "__prismor_guarded__", False):
        return tool
    ws = Path(workspace) if workspace else Path.cwd()
    sid = session_id or f"crewai-{os.getpid()}"
    _agent_name = name  # per-instance label
    tool_name = getattr(tool, "name", None) or getattr(tool, "__name__", "tool")

    def _decide(args: tuple, kwargs: dict):
        decision = _evaluate(
            tool_name=tool_name, args=args, kwargs=kwargs, subject=subject, ws=ws,
            agent=agent, agent_name=_agent_name, mode=mode, sid=sid, event_type=event_type,
        )
        log_observe_findings(decision, mode=mode, tool_name=tool_name)
        _engine[0] = decision.engine
        if not decision.allow:  # honor the runtime decision (incl. org kill-switch / forced-enforce), not the app-passed mode
            # Headless STEP_UP → post an approval request and block until an admin
            # decides. Approve → proceed; deny/timeout/not-enrolled → fail closed.
            if approvals:
                try:
                    from prismor.runtime.enterprise import approvals as _approvals
                    outcome = _approvals.await_step_up(
                        decision, agent=agent, session_id=sid, tool=tool_name, agent_name=_agent_name
                    )
                    if outcome:
                        # "Approve redacted": strip the flagged values on-device
                        # before running (the console only saw masked values).
                        if getattr(outcome, "redacted", False):
                            return _RunWith(
                                _approvals.redact_approved_payload(args, workspace=ws),
                                _approvals.redact_approved_payload(kwargs, workspace=ws),
                            )
                        return None  # approved → allowed
                except Exception:
                    pass
            reason = decision.reason or "policy violation"
            if raise_on_block:
                raise PrismorBlocked(reason, decision)
            return f"⛔ Prismor blocked this tool call: {reason}"
        return None

    # The Decision's own PolicyEngine, parked by _decide for _redact to reuse
    # rather than rebuild. A list because the guarded callables are re-entrant
    # (and async, in LangChain's case): index 0 is only ever a fresher engine
    # for the same workspace, so a racing overwrite costs nothing.
    _engine: List[Any] = [None]

    def _redact(result: Any) -> Any:
        """Mask the tool's OUTPUT before CrewAI feeds it back to the model.

        The pre-call check can only refuse; a tool that reads a file with a
        hardcoded credential in it is allowed, and the credential is in the
        return value. This wrapper holds that value, so it is the one place
        that leak can still be repaired.
        """
        return redact_tool_result(result, workspace=ws, engine=_engine[0])

    wrapped_any = False
    for attr in _IMPL_ATTRS:
        impl = getattr(tool, attr, None)
        if not callable(impl):
            continue
        # _run/run are bound methods on a class instance; wrapping the instance
        # attribute shadows the bound method for this tool object only.
        @functools.wraps(impl)
        def guarded(*args: Any, __impl=impl, **kwargs: Any) -> Any:
            denial = _decide(args, kwargs)
            if isinstance(denial, _RunWith):
                return _redact(__impl(*denial.args, **denial.kwargs))
            if denial is not None:
                return denial
            return _redact(__impl(*args, **kwargs))

        try:
            setattr(tool, attr, guarded)
            wrapped_any = True
        except Exception:
            # shortcut: a slots tool cannot take the wrapper. Leave it unmarked
            # so a caller does not treat the original method as guarded.
            continue

    if wrapped_any:
        tool.__prismor_guarded__ = True
    return tool


def guard_tools(tools: Sequence[Any], **kwargs: Any) -> List[Any]:
    """Guard a list of CrewAI tools in one call. Returns the same list.

    Pass ``goal="..."`` to also capture the agent's intent: the session's
    intent-scoped rules are synthesized from the goal + these tools' names so
    ``evaluate_tool_call`` enforces task-alignment for this headless agent (R2/R3).
    """
    goal = kwargs.pop("goal", None)
    guarded = [prismor_guard_tool(t, **kwargs) for t in tools]
    _names = [getattr(t, "name", None) or getattr(t, "__name__", None) for t in tools]
    try:
        from prismor.runtime.agents import record_seen
        _framework = kwargs.get("agent", "crewai")
        record_seen(
            kwargs.get("name") or _framework, framework=_framework,
            workspace=Path(kwargs["workspace"]) if kwargs.get("workspace") else Path.cwd(),
            tools=[{"name": n, "source": "declared"} for n in _names if n],
            session_id=kwargs.get("session_id") or f"crewai-{os.getpid()}",
        )
    except Exception:
        pass
    if goal:
        try:
            from prismor.runtime.intent import capture_intent
            capture_intent(
                goal,
                workspace=Path(kwargs["workspace"]) if kwargs.get("workspace") else Path.cwd(),
                session_id=kwargs.get("session_id") or f"crewai-{os.getpid()}",
                available_tools=[n for n in _names if n] or None,
                agent=kwargs.get("agent", "crewai"),
            )
        except Exception:
            pass
    return guarded
