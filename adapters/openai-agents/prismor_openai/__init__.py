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

import functools
import json
import os
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
        return " ".join(str(v) for v in parsed.values()).strip()
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
        # It differs from the statically-guarded top-level agent when the run
        # reached this tool via a handoff or an agent-as-tool nested run —
        # that's the Agents SDK's equivalent of Claude Code's subagent spawn.
        active_agent = getattr(ctx, "agent", None)
        active_name = getattr(active_agent, "name", None)
        sub_id: Optional[str] = None
        sub_type: Optional[str] = None
        if active_name and active_name != (_agent_name or agent):
            sub_type = active_name
            sub_id = f"{active_name}-{id(active_agent)}"
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
                        decision, event=event, agent=agent, session_id=sid
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
    ``raise_on_block=True`` for a hard stop. Returns the same Agent. Non-function
    tools (hosted tools, handoffs) are left untouched.
    """
    guarded: List[str] = []
    for tool in getattr(agent_obj, "tools", None) or []:
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
            guarded.append(getattr(tool, "name", "tool"))
    agent_obj.__prismor_guarded_tools__ = guarded  # type: ignore[attr-defined]
    # Prompt guardrails: the SDK re-reads `instructions` every turn when it is a
    # callable, so appending the operator's guardrails there keeps a console
    # edit in force from the agent's next run. The agent's own instructions,
    # static or dynamic, come first and are untouched.
    if not getattr(agent_obj, "__prismor_guardrails__", False):
        base = getattr(agent_obj, "instructions", None)
        ws = Path(workspace) if workspace else Path.cwd()
        sid = session_id or f"openai-agents-{os.getpid()}"

        async def _instructions(ctx: Any, agent_: Any) -> str:
            text = base(ctx, agent_) if callable(base) else (base or "")
            if hasattr(text, "__await__"):
                text = await text
            try:
                from prismor.runtime.guardrails import current_text
                rails = current_text(ws, name or agent, sid)
            except Exception:
                rails = ""
            return f"{text}\n\n{rails}" if (text and rails) else (text or rails)

        agent_obj.instructions = _instructions
        agent_obj.__prismor_guardrails__ = True  # type: ignore[attr-defined]
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
