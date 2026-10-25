"""Prismor adapter for the OpenAI Agents SDK.

Wrap any agent tool with :func:`prismor_guard` so every invocation is routed
through Prismor's shared policy pipeline *before* the tool runs — the same
``prismor.runtime.runtime.evaluate_tool_call`` that backs local coding-agent hooks. A
call that violates an enforce-mode policy (or the calling user's IAM profile)
raises :class:`PrismorBlocked` and the underlying tool never executes.

Easy path — guard a whole agent in one call::

    from agents import Agent, function_tool
    from prismor.openai import guard_agent

    @function_tool
    def run_shell(command: str) -> str:
        ...

    agent = Agent(name="ops", tools=[run_shell])
    guard_agent(agent, subject="user:alice")   # every tool now policy-checked

Or guard a single tool / callable with :func:`prismor_guard`. The wrapper is
framework-light: it works on any plain callable (so it is unit-testable without a
live model) and on OpenAI Agents SDK ``FunctionTool`` objects.
"""
from __future__ import annotations

import contextvars
import functools
import json
import os
import weakref
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, List, Optional, Union

from prismor.runtime.redaction import redact_tool_result
from prismor.runtime.principal import Subject, resolve_subject, use_subject
from prismor.runtime.runtime import Decision, evaluate_tool_call, log_observe_findings

__all__ = ["prismor_guard", "guard_agent", "use_subject", "PrismorBlocked", "build_event"]

# event_type → the event field a string payload is matched against (mirrors
# prismor.runtime.policy_engine._DEFAULT_FIELDS).
_TYPE_FIELD = {
    "shell": "command",
    "file_read": "path",
    "file_write": "path",
    "network": "url",
    "prompt": "content",
    "tool_result": "content",
}


class PrismorBlocked(Exception):
    """Raised when Prismor denies a tool call. Carries the :class:`Decision`."""

    def __init__(self, reason: str, decision: Optional[Decision] = None) -> None:
        super().__init__(reason or "blocked by Prismor policy")
        self.decision = decision


def _tool_name(tool: Any) -> str:
    return (
        getattr(tool, "name", None)
        or getattr(tool, "__name__", None)
        or tool.__class__.__name__
    )


def _default_command(args: tuple, kwargs: dict) -> str:
    """Flatten a call's argument *values* into one matchable string.

    Values only (not ``key=value``) so the payload reads like the underlying
    command/URL/path the rules expect — e.g. ``run_shell(command="rm -rf /")``
    yields ``"rm -rf /"``, which the ``destructive-command`` rule matches (it
    anchors on a word boundary that ``command=rm`` would defeat).
    """
    parts = [str(a) for a in args]
    parts += [str(v) for v in kwargs.values()]
    return " ".join(parts).strip()


def build_event(
    *,
    tool_name: str,
    payload: str,
    event_type: str,
    session_id: str,
    agent: str,
    args: tuple = (),
    kwargs: Optional[dict] = None,
    subagent_id: Optional[str] = None,
    subagent_type: Optional[str] = None,
) -> dict:
    """Construct a canonical Prismor event for a tool call (see prismor/runtime/hooks.py)."""
    field = _TYPE_FIELD.get(event_type, "command")
    event = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "session_id": session_id,
        "agent": agent,
        "agent_event": "PreToolUse",
        "type": event_type,
        field: payload,
        "metadata": {
            "tool_name": tool_name,
            "framework": "openai-agents",
            "args": list(args),
            "kwargs": dict(kwargs or {}),
            # The SDK's active agent for this specific call, when it differs
            # from the top-level agent the tool was guarded under — a handoff
            # or an agent-as-tool nested run. Absent on calls made by the
            # primary agent, mirroring hooks.py's Claude Code subagent fields.
            "subagent_id": subagent_id,
            "subagent_type": subagent_type,
        },
    }
    return event


def prismor_guard(
    tool: Callable[..., Any],
    *,
    subject: Optional[Union[str, Subject]] = None,
    workspace: Optional[Union[str, Path]] = None,
    agent: str = "openai-agents",
    name: str = "",
    mode: str = "observe",
    session_id: Optional[str] = None,
    event_type: str = "shell",
    command_builder: Optional[Callable[[tuple, dict], str]] = None,
    raise_on_block: bool = True,
    approvals: bool = True,
) -> Callable[..., Any]:
    """Wrap ``tool`` so each call is evaluated by Prismor before it runs.

    Args:
        tool: the callable (or OpenAI Agents SDK tool) to guard.
        subject: end-user the calls are attributed to — a ``Subject``, a
            ``PRISMOR_SUBJECT``-style string (``"user:alice"``), or ``None`` to
            resolve from environment / device identity at call time.
        workspace: policy + session-store workspace (default: ``$PWD``).
        agent: agent id for telemetry/heartbeat tagging.
        mode: ``enforce`` (block on enforce findings) or ``observe`` (never block).
        session_id: session to record under (default: per-process id).
        event_type: canonical event type to emit (``shell`` by default so
            destructive-command / secret-exfiltration rules apply to tool args).
        command_builder: maps ``(args, kwargs)`` → the matchable payload string.
        raise_on_block: raise :class:`PrismorBlocked` on deny (default). If
            ``False``, denied calls return the ``Decision`` instead of running.

    Returns:
        A wrapped callable with the same signature as ``tool``.
    """
    # OpenAI Agents SDK FunctionTool objects aren't plain callables — guard their
    # invocation in place and hand the same tool back so Agent(tools=[...]) and
    # the tool's JSON schema are untouched.
    if _is_function_tool(tool):
        return _guard_function_tool(
            tool,
            subject=subject,
            workspace=workspace,
            agent=agent,
            mode=mode,
            session_id=session_id,
            event_type=event_type,
            raise_on_block=raise_on_block,
            approvals=approvals,
        )

    ws = Path(workspace) if workspace else Path.cwd()
    sid = session_id or f"openai-agents-{os.getpid()}"
    builder = command_builder or _default_command
    _agent_name = name  # per-instance label

    def _evaluate(args: tuple, kwargs: dict) -> Decision:
        payload = builder(args, kwargs)
        event = build_event(
            tool_name=_tool_name(tool),
            payload=payload,
            event_type=event_type,
            session_id=sid,
            agent=agent,
            args=args,
            kwargs=kwargs,
        )
        return evaluate_tool_call(
            event=event,
            workspace=ws,
            agent=agent,
            agent_name=_agent_name,
            mode=mode,
            session_id=sid,
            subject=resolve_subject(subject),
        )

    @functools.wraps(tool)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        decision = _evaluate(args, kwargs)
        log_observe_findings(decision, mode=mode, tool_name=_tool_name(tool))
        # In observe mode the call is always allowed to proceed — the finding is
        # still recorded and shipped to telemetry, so it is log-only monitoring.
        # Only enforce mode turns a denial into a hard block.
        if not decision.allow:  # honor the runtime decision (incl. org kill-switch / forced-enforce), not the app-passed mode
            if raise_on_block:
                raise PrismorBlocked(decision.reason or "blocked", decision)
            return decision
        # Allowed: the tool ran, and its OUTPUT is the half a pre-call check
        # never sees. Redact before the SDK folds it into the model's context.
        return redact_tool_result(tool(*args, **kwargs), workspace=ws,
                                  engine=decision.engine)

    wrapper.__prismor_guarded__ = True  # type: ignore[attr-defined]
    return wrapper


# ── OpenAI Agents SDK FunctionTool support ──────────────────────────────────

# Which agent is the main one is a property of the run, not of the `name=`
# label: the first agent whose tool runs is the main agent, and an agent
# reached by a handoff is a subagent. Every ToolContext of one run shares the
# run's Usage object, so it keys the run (by id: Usage is an unhashable
# dataclass; a finalizer drops the entry when the run is gone). An agent used as a tool runs a nested
# Runner inside the parent's tool call, so that whole nested run is a subagent;
# _RUNNING_AGENT carries the parent across that boundary.
_RUN_ROOT: dict = {}
# Both hold (agent id, the guard's agent name): the name is the parent whose
# per-agent controls a subagent's calls inherit.
_RUNNING_AGENT: contextvars.ContextVar[Optional[tuple]] = contextvars.ContextVar(
    "prismor_openai_running_agent", default=None)


def _subagent_of(ctx: Any, guard_name: str = "") -> tuple:
    """(subagent_id, subagent_type, parent guard name) for this call, or
    (None, None, None) on the main agent."""
    active = getattr(ctx, "agent", None)
    if active is None:
        return None, None, None
    outer = _RUNNING_AGENT.get()
    nested = outer is not None and outer[0] != id(active)
    usage = getattr(ctx, "usage", None)
    if usage is None:  # no run to key on: treat the agent as the main one
        root = (id(active), guard_name)
    else:
        key = id(usage)
        if key not in _RUN_ROOT:
            _RUN_ROOT[key] = (id(active), guard_name)
            try:
                weakref.finalize(usage, _RUN_ROOT.pop, key, None)
            except TypeError:
                pass
        root = _RUN_ROOT[key]
    if not nested and root[0] == id(active):
        return None, None, None
    name = getattr(active, "name", None) or "agent"
    parent = outer[1] if nested else root[1]
    return f"{name}-{id(active)}", name, parent or None


def _subagents_of(agent_obj: Any) -> List[Any]:
    """Agents ``agent_obj`` can run: its handoff targets and its agents-as-tools."""
    found = []
    for h in getattr(agent_obj, "handoffs", None) or []:
        ref = getattr(h, "_agent_ref", None)  # a Handoff keeps a weakref to its agent
        target = ref() if callable(ref) else (h if hasattr(h, "tools") else None)
        if target is not None:
            found.append(target)
    for tool in getattr(agent_obj, "tools", None) or []:
        inner = getattr(tool, "_agent_instance", None)  # Agent.as_tool()
        if inner is not None:
            found.append(inner)
    return found


def _is_function_tool(obj: Any) -> bool:
    """Duck-type an OpenAI Agents SDK FunctionTool (has an async on_invoke_tool)."""
    return hasattr(obj, "on_invoke_tool") and hasattr(obj, "name")


def _payload_from_tool_input(raw: Any) -> str:
    """Flatten a tool's JSON-string arguments into a matchable payload string."""
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except (ValueError, TypeError):
            return raw
    else:
        parsed = raw
    if isinstance(parsed, dict):
        return " ".join(f"{k} {v}" for k, v in parsed.items()).strip()
    if isinstance(parsed, (list, tuple)):
        return " ".join(str(v) for v in parsed).strip()
    return str(parsed)


def _guard_function_tool(
    tool: Any,
    *,
    subject: Optional[Union[str, Subject]],
    workspace: Optional[Union[str, Path]],
    agent: str,
    name: str = "",
    mode: str,
    session_id: Optional[str],
    event_type: str,
    raise_on_block: bool,
    approvals: bool = True,
) -> Any:
    """Wrap a FunctionTool's ``on_invoke_tool`` so the call is evaluated first.

    On an enforce-mode denial the tool body never runs; the model receives a
    clear denial string (the natural way to feed a tool result back to an agent)
    so it can adjust instead of crashing the run. Returns the same tool object.
    """
    if getattr(tool, "__prismor_guarded__", False):
        return tool

    original = tool.on_invoke_tool
    ws = Path(workspace) if workspace else Path.cwd()
    sid = session_id or f"openai-agents-{os.getpid()}"
    tool_name = getattr(tool, "name", "tool")
    _agent_name = name  # per-instance label

    @functools.wraps(original)
    async def guarded(ctx: Any, input_str: Any) -> Any:
        # ctx (a ToolContext) carries the SDK's active agent for this call.
        # A handoff or an agent-as-tool nested run makes it a subagent, the
        # Agents SDK's equivalent of Claude Code's subagent spawn.
        sub_id, sub_type, parent = _subagent_of(ctx, _agent_name or agent)
        active = getattr(ctx, "agent", None)
        _token = _RUNNING_AGENT.set((id(active), _agent_name or agent) if active is not None else None)
        try:
            return await _run(ctx, input_str, sub_id, sub_type, parent)
        finally:
            _RUNNING_AGENT.reset(_token)

    async def _run(ctx: Any, input_str: Any, sub_id: Optional[str], sub_type: Optional[str],
                   parent: Optional[str] = None) -> Any:
        event = build_event(
            tool_name=tool_name,
            payload=_payload_from_tool_input(input_str),
            event_type=event_type,
            session_id=sid,
            agent=agent,
            kwargs={"input": input_str},
            subagent_id=sub_id,
            subagent_type=sub_type,
        )
        if sub_id and parent:
            # The agent it runs under; its per-agent controls apply on top.
            event["metadata"]["parent_agent_name"] = parent
        _inner = getattr(tool, "_agent_instance", None)  # Agent.as_tool(): the input is a handoff
        if _inner is not None and isinstance(getattr(_inner, "name", None), str):
            event["metadata"]["handoff_to"] = _inner.name
        decision = evaluate_tool_call(
            event=event,
            workspace=ws,
            agent=agent,
            agent_name=_agent_name,
            mode=mode,
            session_id=sid,
            subject=resolve_subject(subject),
        )
        log_observe_findings(decision, mode=mode, tool_name=tool_name)
        if not decision.allow:  # honor the runtime decision (incl. org kill-switch / forced-enforce), not the app-passed mode
            # Headless STEP_UP: no human at the keyboard for an inline "ask", so
            # post an approval request to the control plane and block until an
            # admin approves. Approve → proceed; deny/timeout/not-enrolled → fail
            # closed to the block below.
            if approvals:
                try:
                    from prismor.runtime.enterprise import approvals as _approvals
                    # async variant: the wait runs in a worker thread so this
                    # event loop keeps servicing concurrent tools and streams.
                    outcome = await _approvals.await_step_up_async(
                        decision, event=event, agent=agent, session_id=sid,
                        tool=tool_name, agent_name=_agent_name,
                    )
                    if outcome:
                        if getattr(outcome, "redacted", False):
                            # "Approve redacted": strip flagged values on-device first.
                            input_str = _approvals.redact_approved_payload(input_str, workspace=ws)
                        return redact_tool_result(
                            await original(ctx, input_str), workspace=ws,
                            engine=decision.engine)
                except Exception:
                    pass  # any approval-path error fails closed
            reason = decision.reason or "policy violation"
            if raise_on_block:
                raise PrismorBlocked(reason, decision)
            return f"⛔ Prismor blocked this tool call: {reason}"
        return redact_tool_result(await original(ctx, input_str), workspace=ws,
                                  engine=decision.engine)

    tool.on_invoke_tool = guarded
    tool.__prismor_guarded__ = True
    return tool


def guard_agent(
    agent_obj: Any,
    *,
    subject: Optional[Union[str, Subject]] = None,
    workspace: Optional[Union[str, Path]] = None,
    agent: str = "openai-agents",
    name: str = "",
    mode: str = "observe",
    session_id: Optional[str] = None,
    event_type: str = "shell",
    raise_on_block: bool = False,
    approvals: bool = True,
    goal: Optional[str] = None,
) -> Any:
    """Guard **every** FunctionTool on an Agent in one call — the easy path.

    ::

        agent = Agent(name="ops", tools=[run_shell, fetch_url])
        guard_agent(agent, subject="user:alice")   # all tools now policy-checked

    Defaults to ``raise_on_block=False`` so a blocked call returns a denial
    string to the model (a smoother agent UX) rather than aborting the run; set
    ``raise_on_block=True`` for a hard stop. Returns the same Agent. Hosted
    tools are left untouched.

    Every agent this one can hand off to or runs as a tool (``as_tool``),
    recursively, is guarded too, with the same settings: a subagent runs on its
    parent's authority, so it is held to the same policy and per-agent controls
    (its calls are told apart by ``when: subagent.*``). An agent nobody guarded
    would otherwise run its tools with no policy at all.
    """
    guarded: List[str] = []
    seen_agents: set = set()
    pending = [agent_obj]
    while pending:
        current = pending.pop()
        if id(current) in seen_agents:
            continue
        seen_agents.add(id(current))
        pending.extend(_subagents_of(current))
        for tool in getattr(current, "tools", None) or []:
            if _is_function_tool(tool):
                _guard_function_tool(
                    tool,
                    subject=subject,
                    workspace=workspace,
                    agent=agent,
                    name=name,
                    mode=mode,
                    session_id=session_id,
                    event_type=event_type,
                    raise_on_block=raise_on_block,
                    approvals=approvals,
                )
                if current is agent_obj:
                    guarded.append(getattr(tool, "name", "tool"))
    agent_obj.__prismor_guarded_tools__ = guarded  # type: ignore[attr-defined]
    # Declare the complete SDK roster immediately; no tool needs to be invoked
    # before it appears in the enterprise capability inventory.
    try:
        from prismor.runtime.agents import record_seen
        record_seen(
            name or agent, framework=agent,
            workspace=Path(workspace) if workspace else Path.cwd(),
            tools=[{"name": t, "source": "declared"} for t in guarded],
            session_id=session_id or f"openai-agents-{os.getpid()}",
        )
    except Exception:
        pass
    # Intent capture (R2/R3): synthesize the session's intent-scoped rules from
    # the agent's goal + its real tool names, so evaluate_tool_call enforces
    # "does this serve the task?" for this headless agent too. Best-effort.
    if goal:
        try:
            from prismor.runtime.intent import capture_intent
            capture_intent(
                goal,
                workspace=Path(workspace) if workspace else Path.cwd(),
                session_id=session_id or f"openai-agents-{os.getpid()}",
                available_tools=guarded or None,
                agent=agent,
            )
        except Exception:
            pass
    return agent_obj
