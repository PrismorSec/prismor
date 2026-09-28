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
live model) and on OpenAI Agents SDK ``FunctionTool`` objects. Both paths are
thin layers over :class:`prismor.sdk.PrismorClient`.
"""
from __future__ import annotations

import functools
import json
import os
from pathlib import Path
from typing import Any, Callable, List, Optional, Union

from prismor.runtime.principal import Subject, use_subject
from prismor.runtime.runtime import Decision, evaluate_tool_call
from prismor.sdk import BlockContext, PrismorBlocked, PrismorClient
from prismor.sdk import build_event as _sdk_build_event

__all__ = ["prismor_guard", "guard_agent", "use_subject", "PrismorBlocked", "build_event"]


def _evaluate(**kwargs: Any) -> Decision:
    """Resolve ``evaluate_tool_call`` through this module's global at call time.

    A test (or an app) that patches ``prismor.openai.evaluate_tool_call`` keeps
    seeing every call, whether the patch lands before or after guarding.
    """
    return evaluate_tool_call(**kwargs)


def _client(**kwargs: Any) -> PrismorClient:
    return PrismorClient(framework="openai-agents", evaluate=_evaluate, **kwargs)


def _tool_name(tool: Any) -> str:
    return (
        getattr(tool, "name", None)
        or getattr(tool, "__name__", None)
        or tool.__class__.__name__
    )


def _return_decision(decision: Decision, ctx: BlockContext) -> Decision:
    """Plain-callable default when not raising: hand back the ``Decision`` itself."""
    return decision


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
    """Construct a canonical Prismor event for a tool call (see prismor/runtime/hooks.py).

    ``subagent_id`` / ``subagent_type`` name the SDK's active agent for this
    specific call when it differs from the top-level agent the tool was guarded
    under — a handoff or an agent-as-tool nested run — mirroring hooks.py's
    Claude Code subagent fields.
    """
    return _sdk_build_event(
        tool_name=tool_name, payload=payload, event_type=event_type,
        session_id=session_id, agent=agent, args=args, kwargs=kwargs,
        framework="openai-agents", subagent_id=subagent_id, subagent_type=subagent_type,
    )


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
    on_policy_block: Optional[Callable[[Decision, BlockContext], Any]] = None,
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
            ``False``, denied calls return the ``Decision`` instead of running
            (plain callables) or a denial string (``FunctionTool`` objects).
        on_policy_block: ``callback(decision, ctx)`` whose return value becomes
            the tool's result on a denial; takes precedence over ``raise_on_block``.

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
            name=name,
            mode=mode,
            session_id=session_id,
            event_type=event_type,
            raise_on_block=raise_on_block,
            approvals=approvals,
            on_policy_block=on_policy_block,
        )

    # The plain-callable path never ran the approval flow and, when not
    # raising, returns the Decision object itself so a caller can inspect it.
    client = _client(
        workspace=workspace, agent=agent, agent_name=name, mode=mode,
        session_id=session_id or f"openai-agents-{os.getpid()}", subject=subject,
        approvals=False, raise_on_block=raise_on_block,
        on_policy_block=on_policy_block or (None if raise_on_block else _return_decision),
    )
    return client.guard(
        tool, tool_name=_tool_name(tool), event_type=event_type, payload_builder=command_builder,
    )


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
    on_policy_block: Optional[Callable[[Decision, BlockContext], Any]] = None,
) -> Any:
    """Wrap a FunctionTool's ``on_invoke_tool`` so the call is evaluated first.

    On an enforce-mode denial the tool body never runs; the model receives a
    clear denial string (the natural way to feed a tool result back to an agent)
    so it can adjust instead of crashing the run. Returns the same tool object.
    """
    if getattr(tool, "__prismor_guarded__", False):
        return tool

    original = tool.on_invoke_tool
    tool_name = getattr(tool, "name", "tool")
    client = _client(
        workspace=workspace, agent=agent, agent_name=name, mode=mode,
        session_id=session_id or f"openai-agents-{os.getpid()}", subject=subject,
        approvals=approvals, raise_on_block=raise_on_block, on_policy_block=on_policy_block,
    )

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
        if active_name and active_name != (name or agent):
            sub_type = active_name
            sub_id = f"{active_name}-{id(active_agent)}"
        event = client.build_event(
            tool_name, kwargs={"input": input_str},
            payload=_payload_from_tool_input(input_str), event_type=event_type,
            subagent_id=sub_id, subagent_type=sub_type,
        )
        decision = client.check_event(event)
        if not decision.allow:  # honor the runtime decision (incl. org kill-switch / forced-enforce), not the app-passed mode
            # Headless STEP_UP: no human at the keyboard for an inline "ask", so
            # post an approval request to the control plane and block until an
            # admin approves. Approve → proceed; deny/timeout/not-enrolled → fail
            # closed. The async variant waits in a worker thread so this event
            # loop keeps servicing concurrent tools and streams.
            res = await client.resolve_block_async(decision, args=(input_str,), event=event)
            if not res.approved:
                return client.on_blocked(
                    decision, BlockContext(tool_name, (), {"input": input_str}, client.session_id, event),
                )
            input_str = res.args[0]  # "approve redacted" stripped the flagged values
        return client.redact(await original(ctx, input_str), decision)

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
    on_policy_block: Optional[Callable[[Decision, BlockContext], Any]] = None,
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
                on_policy_block=on_policy_block,
            )
            guarded.append(getattr(tool, "name", "tool"))
    agent_obj.__prismor_guarded_tools__ = guarded  # type: ignore[attr-defined]
    # Declare the complete SDK roster immediately (no tool needs to be invoked
    # before it appears in the enterprise capability inventory) and, with a
    # goal, capture intent (R2/R3) so evaluate_tool_call enforces "does this
    # serve the task?" for this headless agent too. Best-effort.
    _client(
        workspace=workspace, agent=agent, agent_name=name,
        session_id=session_id or f"openai-agents-{os.getpid()}",
    ).declare_tools(guarded, goal=goal)
    return agent_obj
