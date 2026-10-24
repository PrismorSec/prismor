"""Prismor adapter for LangChain / LangGraph.

Same control point as the other framework adapters: every tool invocation is
routed through ``prismor.runtime.runtime.evaluate_tool_call`` before the tool runs, so a
LangChain/LangGraph agent gets the exact policy, observe/enforce model, and
per-user attribution a local coding agent already has.

Two surfaces:

* :func:`guard_tools` / :func:`prismor_guard_tool` — wrap a ``BaseTool``'s
  implementation so a denied call never executes (hard enforcement). This is the
  reliable path and what you normally want.
* :class:`PrismorCallbackHandler` — a ``BaseCallbackHandler`` for observability /
  soft-blocking via ``on_tool_start`` (capture every tool call even for tools you
  didn't wrap).

Easy path::

    from langgraph.prebuilt import create_react_agent
    from prismor.langchain import guard_tools

    tools = guard_tools([run_shell, fetch_url], subject="user:alice")
    agent = create_react_agent(model, tools)
"""
from __future__ import annotations

import functools
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, List, Optional, Sequence, Union

from prismor.runtime.redaction import redact_tool_result
from prismor.runtime.principal import Subject, resolve_subject, use_subject
from prismor.runtime.runtime import Decision, evaluate_tool_call, log_observe_findings

__all__ = [
    "guard_tools",
    "prismor_guard_tool",
    "PrismorCallbackHandler",
    "use_subject",
    "PrismorBlocked",
]

_TYPE_FIELD = {
    "shell": "command",
    "file_read": "path",
    "file_write": "path",
    "network": "url",
    "prompt": "content",
    "tool_result": "content",
}


class PrismorBlocked(Exception):
    """Raised when Prismor denies a tool call (hard-stop mode)."""

    def __init__(self, reason: str, decision: Optional[Decision] = None) -> None:
        super().__init__(reason or "blocked by Prismor policy")
        self.decision = decision


def _payload(args: tuple, kwargs: dict) -> str:
    parts = [str(a) for a in args]
    parts += [str(v) for v in kwargs.values()]
    return " ".join(parts).strip()


def _build_event(*, tool_name, payload, event_type, session_id, agent, args=(), kwargs=None, subagent_id=None, subagent_type=None):
    field = _TYPE_FIELD.get(event_type, "command")
    return {
        "ts": datetime.now(timezone.utc).isoformat(),
        "session_id": session_id,
        "agent": agent,
        "agent_event": "PreToolUse",
        "type": event_type,
        field: payload,
        "metadata": {
            "tool_name": tool_name,
            "framework": "langchain",
            "args": list(args),
            "kwargs": dict(kwargs or {}),
            # LangGraph's current graph node for this call, when running inside
            # a multi-agent StateGraph — that framework's equivalent of a
            # spawned subagent. Only PrismorCallbackHandler has access to this
            # (LangChain's run-time callback metadata); the plain func/coroutine
            # wrap in prismor_guard_tool has no per-call context to draw it from.
            "subagent_id": subagent_id,
            "subagent_type": subagent_type,
        },
    }


def _evaluate(*, tool_name, args, kwargs, subject, ws, agent, mode, sid, event_type, agent_name="", subagent_id=None, subagent_type=None) -> Decision:
    event = _build_event(
        tool_name=tool_name,
        payload=_payload(args, kwargs),
        event_type=event_type,
        session_id=sid,
        agent=agent,
        args=args,
        kwargs=kwargs,
        subagent_id=subagent_id,
        subagent_type=subagent_type,
    )
    return evaluate_tool_call(
        event=event, workspace=ws, agent=agent, agent_name=agent_name,
        mode=mode, session_id=sid, subject=resolve_subject(subject),
    )


def _subagent_from_metadata(md: Any) -> tuple:
    """(subagent_id, subagent_type) from LangGraph run metadata, or (None, None).

    ``langgraph_checkpoint_ns`` is the path of graphs the call runs in, e.g.
    ``researcher:<uuid>|tools:<uuid>``. One segment is the top-level graph: the
    main agent, even though its tool node is named ``tools``. More than one
    means the call runs inside a subgraph, which is how a multi-agent graph (and
    langgraph-supervisor) runs each agent; the outer segment names that agent
    and, with its uuid, identifies this run of it.
    """
    if not isinstance(md, dict):
        return None, None
    ns = str(md.get("langgraph_checkpoint_ns") or md.get("checkpoint_ns") or "")
    parts = [p for p in ns.split("|") if p]
    if len(parts) < 2:
        return None, None
    return parts[0], parts[0].split(":", 1)[0]


def _graph_subagent() -> tuple:
    """The calling subagent when a guarded tool runs inside a LangGraph graph."""
    try:
        from langgraph.config import get_config
        return _subagent_from_metadata((get_config() or {}).get("metadata"))
    except Exception:  # not in a graph, or langgraph not installed
        return None, None


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
    agent: str = "langchain",
    name: str = "",
    mode: str = "observe",
    session_id: Optional[str] = None,
    event_type: str = "shell",
    raise_on_block: bool = False,
    approvals: bool = True,
) -> Any:
    """Wrap a LangChain ``BaseTool``'s implementation so calls are policy-checked.

    Wraps both the sync ``func`` and async ``coroutine`` if present. On an
    enforce-mode denial the tool body does not run; by default a denial string is
    returned to the agent (smooth recovery). Returns the same tool object.
    """
    if getattr(tool, "__prismor_guarded__", False):
        return tool
    ws = Path(workspace) if workspace else Path.cwd()
    sid = session_id or f"langchain-{os.getpid()}"
    _agent_name = name  # per-instance label (distinct from framework id)
    tool_name = getattr(tool, "name", None) or getattr(tool, "__name__", "tool")

    def _decide(args: tuple, kwargs: dict):
        sub_id, sub_type = _graph_subagent()
        decision = _evaluate(
            tool_name=tool_name, args=args, kwargs=kwargs, subject=subject, ws=ws,
            agent=agent, agent_name=_agent_name, mode=mode, sid=sid, event_type=event_type,
            subagent_id=sub_id, subagent_type=sub_type,
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
                        # "Approve redacted": the approver let the call through
                        # on condition that the flagged values are stripped
                        # first. Redaction happens here, on-device — the
                        # console only ever saw masked values.
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
        return None  # allowed

    # The Decision's own PolicyEngine, parked by _decide for _redact to reuse
    # rather than rebuild. A list because the guarded callables are re-entrant
    # (and async, in LangChain's case): index 0 is only ever a fresher engine
    # for the same workspace, so a racing overwrite costs nothing.
    _engine: List[Any] = [None]

    def _redact(result: Any) -> Any:
        """Mask the tool's OUTPUT before LangChain feeds it back to the model.

        The pre-call check can only refuse; a tool that reads a file with a
        hardcoded credential in it is allowed, and the credential is in the
        return value. This wrapper holds that value, so it is the one place
        that leak can still be repaired.
        """
        return redact_tool_result(result, workspace=ws, engine=_engine[0])

    original_func = getattr(tool, "func", None)
    if callable(original_func):
        @functools.wraps(original_func)
        def guarded_func(*args: Any, **kwargs: Any) -> Any:
            denial = _decide(args, kwargs)
            if isinstance(denial, _RunWith):
                return _redact(original_func(*denial.args, **denial.kwargs))
            if denial is not None:
                return denial
            return _redact(original_func(*args, **kwargs))
        tool.func = guarded_func

    original_coro = getattr(tool, "coroutine", None)
    if callable(original_coro):
        @functools.wraps(original_coro)
        async def guarded_coro(*args: Any, **kwargs: Any) -> Any:
            # A STEP_UP inside _decide can wait minutes for a human; run the
            # whole decision in a worker thread so this event loop keeps
            # servicing other tools/streams instead of sleeping with it.
            import asyncio

            denial = await asyncio.to_thread(_decide, args, kwargs)
            if isinstance(denial, _RunWith):
                return _redact(await original_coro(*denial.args, **denial.kwargs))
            if denial is not None:
                return denial
            return _redact(await original_coro(*args, **kwargs))
        tool.coroutine = guarded_coro

    tool.__prismor_guarded__ = True
    return tool


def guard_tools(tools: Sequence[Any], **kwargs: Any) -> List[Any]:
    """Guard a list of LangChain tools in one call. Returns the same list.

    Pass ``goal="..."`` to also capture the agent's intent: the session's
    intent-scoped rules are synthesized from the goal + these tools' names so
    ``evaluate_tool_call`` enforces task-alignment for this headless agent (R2/R3).
    """
    goal = kwargs.pop("goal", None)
    guarded = [prismor_guard_tool(t, **kwargs) for t in tools]
    _names = [getattr(t, "name", None) or getattr(t, "__name__", None) for t in tools]
    try:
        from prismor.runtime.agents import record_seen
        _framework = kwargs.get("agent", "langchain")
        record_seen(
            kwargs.get("name") or _framework, framework=_framework,
            workspace=Path(kwargs["workspace"]) if kwargs.get("workspace") else Path.cwd(),
            tools=[{"name": n, "source": "declared"} for n in _names if n],
            session_id=kwargs.get("session_id") or f"langchain-{os.getpid()}",
        )
    except Exception:
        pass
    if goal:
        try:
            from prismor.runtime.intent import capture_intent
            capture_intent(
                goal,
                workspace=Path(kwargs["workspace"]) if kwargs.get("workspace") else Path.cwd(),
                session_id=kwargs.get("session_id") or f"langchain-{os.getpid()}",
                available_tools=[n for n in _names if n] or None,
                agent=kwargs.get("agent", "langchain"),
            )
        except Exception:
            pass
    return guarded


# ── Callback handler (observability / soft block) ───────────────────────────

try:
    from langchain_core.callbacks import BaseCallbackHandler as _BaseCB
except Exception:  # pragma: no cover - langchain not installed
    _BaseCB = object  # type: ignore[assignment,misc]


class PrismorCallbackHandler(_BaseCB):  # type: ignore[misc]
    """Capture every tool call via ``on_tool_start`` and evaluate it.

    Add to any chain/agent run (``config={"callbacks": [PrismorCallbackHandler()]}``)
    to record + evaluate tool calls even for tools you did not wrap. In enforce
    mode it raises :class:`PrismorBlocked` from ``on_tool_start`` (which aborts the
    tool call before the tool runs); in observe mode it only records.
    """

    raise_error = True  # ask LangChain to propagate our exception

    def __init__(
        self,
        *,
        subject: Optional[Union[str, Subject]] = None,
        workspace: Optional[Union[str, Path]] = None,
        agent: str = "langchain",
        mode: str = "observe",
        session_id: Optional[str] = None,
        event_type: str = "shell",
        approvals: bool = True,
    ) -> None:
        self._subject = subject
        self._ws = Path(workspace) if workspace else Path.cwd()
        self._agent = agent
        self._mode = mode
        self._sid = session_id or f"langchain-cb-{os.getpid()}"
        self._event_type = event_type
        self._approvals = approvals

    def on_tool_start(self, serialized: dict, input_str: str, **kwargs: Any) -> None:
        name = (serialized or {}).get("name", "tool")
        # LangGraph stamps the graph path onto callback metadata; a call inside
        # an agent subgraph is that framework's subagent (see _subagent_from_metadata).
        sub_id, sub_type = _subagent_from_metadata(kwargs.get("metadata"))
        decision = _evaluate(
            tool_name=name, args=(input_str,), kwargs={}, subject=self._subject,
            ws=self._ws, agent=self._agent, mode=self._mode, sid=self._sid,
            event_type=self._event_type, subagent_id=sub_id, subagent_type=sub_type,
        )
        log_observe_findings(decision, mode=self._mode, tool_name=name)
        if not decision.allow:  # honor the runtime decision (incl. org kill-switch / forced-enforce), not the app-passed mode
            if self._approvals:
                try:
                    from prismor.runtime.enterprise import approvals as _approvals
                    if _approvals.await_step_up(decision, agent=self._agent, session_id=self._sid, tool=name):
                        return  # approved → allowed
                except Exception:
                    pass
            raise PrismorBlocked(decision.reason or "policy violation", decision)
