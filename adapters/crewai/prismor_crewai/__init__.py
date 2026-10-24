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

For a crew, :func:`guard_crew` guards every agent's tools and also tracks
which agent is working: an agent doing a task another agent delegated to it
(``allow_delegation``, or every worker of a hierarchical crew under its
manager) is a subagent, typed by its role, for ``when: subagent.*`` rules.
"""
from __future__ import annotations

import contextvars
import functools
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, List, Optional, Sequence, Union

from prismor.runtime.redaction import redact_tool_result
from prismor.runtime.principal import Subject, resolve_subject, use_subject
from prismor.runtime.runtime import Decision, evaluate_tool_call, log_observe_findings

__all__ = ["guard_crew", "guard_tools", "prismor_guard_tool", "use_subject", "PrismorBlocked"]

# Agents currently executing a task, outermost first: (role, subagent id or
# None for an agent doing its own task). Set by guard_crew's execute_task
# wrapper; CrewAI runs a delegated task synchronously inside the delegating
# agent's tool call, so the nesting is visible here.
# ponytail: contextvars do not cross threads; a task CrewAI runs on a worker
# thread (async_execution, max_execution_time) starts a fresh stack there.
_WORKING: contextvars.ContextVar[tuple] = contextvars.ContextVar("prismor_crewai_working", default=())


def _current_subagent() -> tuple:
    """(subagent_id, subagent_type) of the agent making this call, or (None, None)."""
    stack = _WORKING.get()
    if not stack or stack[-1][1] is None:
        return None, None
    role, sub_id = stack[-1]
    return sub_id, role

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
    sub_id, sub_type = _current_subagent()
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
            "subagent_id": sub_id,
            "subagent_type": sub_type,
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


def _track_working(crew_agent: Any, *, delegated: bool) -> None:
    """Wrap one agent's execute_task so its tool calls know who is working.

    ``delegated``: every task this agent runs was handed to it by a manager
    (a hierarchical crew's worker), even when the manager is CrewAI's own.
    """
    if getattr(crew_agent, "__prismor_tracked__", False):
        return
    original = crew_agent.execute_task
    role = str(getattr(crew_agent, "role", None) or "agent")

    @functools.wraps(original)
    def execute_task(*args: Any, **kwargs: Any) -> Any:
        stack = _WORKING.get()
        sub_id = f"{role}:{uuid.uuid4().hex[:8]}" if (stack or delegated) else None
        token = _WORKING.set(stack + ((role, sub_id),))
        try:
            return original(*args, **kwargs)
        finally:
            _WORKING.reset(token)

    # CrewAI agents are pydantic models; bypass their __setattr__ validation.
    object.__setattr__(crew_agent, "execute_task", execute_task)
    object.__setattr__(crew_agent, "__prismor_tracked__", True)


def guard_crew(crew: Any, **kwargs: Any) -> Any:
    """Guard every agent of a Crew and attribute delegated work to subagents.

    In a sequential crew each agent doing its own task is the main agent; one
    working on a task delegated by a coworker is a subagent. In a hierarchical
    crew the manager is the main agent and every worker is a subagent. Takes
    the same options as :func:`guard_tools`; returns the crew.
    """
    hierarchical = str(getattr(getattr(crew, "process", None), "value", getattr(crew, "process", ""))) == "hierarchical"
    manager = getattr(crew, "manager_agent", None)
    for crew_agent in getattr(crew, "agents", None) or []:
        if crew_agent is manager:
            continue
        if getattr(crew_agent, "tools", None):
            guard_tools(crew_agent.tools, **kwargs)
        _track_working(crew_agent, delegated=hierarchical)
    if manager is not None:
        if getattr(manager, "tools", None):
            guard_tools(manager.tools, **kwargs)
        _track_working(manager, delegated=False)
    return crew
