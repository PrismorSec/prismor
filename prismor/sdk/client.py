"""prismor/sdk/client.py — ``PrismorClient``: check, enforce, approve, redact.

The decision is made in exactly one place, :func:`prismor.runtime.runtime.
evaluate_tool_call`. This module is the client-side glue around it that every
in-process integration needs and that the framework adapters used to copy:
building the canonical event, rendering a denial, running the headless
approval flow, and masking the tool's output. It adds no policy logic and no
detection patterns of its own.

Fail-closed rules the client keeps:

* a denial is only ever softened by an explicit approval (``resolve_block``),
  and any error on that path counts as "denied";
* ``Decision.allow`` is honored as-is — the runtime has already folded the
  requested mode and any org control (kill-switch, forced enforce) into it, so
  the client never re-derives a verdict from its own ``mode``.
"""
from __future__ import annotations

import asyncio
import contextvars
import functools
import inspect
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Sequence, Tuple, Union

from prismor.runtime import contract
from prismor.runtime import runtime as _runtime
from prismor.runtime.contract import Decision
from prismor.runtime.principal import Subject, resolve_subject
from prismor.runtime.redaction import redact_tool_result

__all__ = [
    "PrismorClient",
    "PrismorBlocked",
    "BlockContext",
    "BlockResolution",
    "build_event",
    "SURFACE_ID",
]

#: ``metadata.surface`` stamped on every event the client builds — the same
#: enforcement point the framework adapters register as (contract.SURFACES).
SURFACE_ID = "sdk-adapter"

_DENIAL_PREFIX = "⛔ Prismor blocked this tool call: "


class PrismorBlocked(Exception):
    """Raised when Prismor denies a tool call and the caller asked for a hard stop.

    ``decision`` carries the :class:`Decision` (findings, blocking rule,
    subject). One class, shared by every adapter, so ``except PrismorBlocked``
    works whichever import path produced it.
    """

    def __init__(self, reason: str, decision: Optional[Decision] = None) -> None:
        super().__init__(reason or "blocked by Prismor policy")
        self.decision = decision


@dataclass
class BlockContext:
    """What the caller was about to run when policy said no.

    Handed to ``on_policy_block`` so an application can decide what the model
    sees instead of the tool's result.
    """

    tool_name: str
    args: tuple = ()
    kwargs: Dict[str, Any] = field(default_factory=dict)
    session_id: str = ""
    event: Optional[Dict[str, Any]] = None


@dataclass
class BlockResolution:
    """Outcome of the headless approval flow for one blocked call.

    ``approved=False`` — denied, timed out, not enrolled, approvals switched
    off, or any error on the approval path (fail closed).
    ``approved=True, redacted=False`` — run the call as-is.
    ``approved=True, redacted=True`` — run it with ``args`` / ``kwargs``, from
    which the approver's flagged values have been stripped on-device.
    """

    approved: bool
    args: tuple = ()
    kwargs: Dict[str, Any] = field(default_factory=dict)
    redacted: bool = False


def _flatten(args: Sequence[Any], kwargs: Dict[str, Any]) -> str:
    """Flatten a call's argument *values* into one matchable string.

    Values only (not ``key=value``) so the payload reads like the underlying
    command/URL/path the rules expect: ``run_shell(command="rm -rf /")`` yields
    ``"rm -rf /"``, which a word-boundary-anchored rule can match.
    """
    parts = [str(a) for a in args]
    parts += [str(v) for v in kwargs.values()]
    return " ".join(parts).strip()


def build_event(
    *,
    tool_name: str,
    payload: str,
    event_type: str = "shell",
    session_id: str = "",
    agent: str = "sdk",
    args: Sequence[Any] = (),
    kwargs: Optional[Dict[str, Any]] = None,
    framework: Optional[str] = None,
    subagent_id: Optional[str] = None,
    subagent_type: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
    budget: Any = None,
) -> Dict[str, Any]:
    """Canonical Prismor event for one tool call.

    ``contract.new_event`` plus the metadata keys the adapters write
    (``tool_name``, ``framework``, ``args``, ``kwargs``, ``subagent_id``,
    ``subagent_type``). Caller-supplied ``metadata`` is merged first and those
    fixed keys win, so a caller cannot mislabel the surface or the tool.
    ``budget`` lands in ``metadata["budget"]`` when given; it must be
    JSON-serialisable because the event is appended to the session store.
    """
    meta: Dict[str, Any] = dict(metadata or {})
    meta.update({
        "tool_name": tool_name,
        "framework": framework or agent,
        "args": list(args),
        "kwargs": dict(kwargs or {}),
        "subagent_id": subagent_id,
        "subagent_type": subagent_type,
        "surface": SURFACE_ID,
    })
    if budget is not None:
        meta["budget"] = budget
    return contract.new_event(
        etype=event_type,
        value=payload,
        agent=agent,
        session_id=session_id,
        surface_id=SURFACE_ID,
        tool_name=tool_name,
        metadata=meta,
    )


async def _in_thread(fn: Callable[..., Any], *args: Any) -> Any:
    """Run ``fn`` in the default executor with the caller's context variables.

    What ``asyncio.to_thread`` does, written out so the client keeps the
    package's Python 3.8 floor. Carrying the context is what keeps a
    ``use_subject`` binding visible inside the worker thread.
    """
    loop = asyncio.get_running_loop()
    ctx = contextvars.copy_context()
    return await loop.run_in_executor(None, functools.partial(ctx.run, fn, *args))


class PrismorClient:
    """One configured entry point to check, enforce, approve and redact tool calls.

    Construct once per agent (or per guarded tool); ``check`` is safe to call
    concurrently. The runtime's own concerns — org-policy pull, heartbeat,
    telemetry, the effective mode — all happen inside ``evaluate_tool_call``
    and need nothing from the client.

    Args:
        workspace: policy + session-store workspace (default: ``$PWD``).
        agent: framework/agent id for telemetry and heartbeat tagging.
        agent_name: per-instance label (dashboard kill-switch, per-agent
            controls); defaults to ``agent`` inside the runtime.
        mode: ``"observe"`` (default) records and warns; ``"enforce"`` blocks.
            An org control can still force a block in observe mode.
        session_id: session to record under; default ``f"{agent}-{pid}"``.
        subject: end user the calls are attributed to (``"user:alice"`` or a
            :class:`Subject`); ``None`` resolves ``use_subject`` /
            ``PRISMOR_SUBJECT`` / device identity at call time.
        approvals: run the headless approval flow on a ``step_up`` denial.
        raise_on_block: raise :class:`PrismorBlocked` on a denial instead of
            returning the denial string.
        on_policy_block: ``callback(decision, BlockContext)``; its return value
            becomes the tool's result and takes precedence over
            ``raise_on_block``. Exceptions it raises propagate.
        budget: free-form value recorded as ``metadata.budget`` on every event
            (session store and telemetry). No built-in rule enforces it.
        framework: fixed ``metadata.framework`` stamp (default: ``agent``).
        evaluate: override for the evaluator (same signature as
            ``evaluate_tool_call``). The bundled adapters pass a module-level
            thunk so their own ``evaluate_tool_call`` name stays the one that
            runs, which keeps tests that patch it observing every call.
    """

    def __init__(
        self,
        *,
        workspace: Optional[Union[str, Path]] = None,
        agent: str = "sdk",
        agent_name: str = "",
        mode: str = "observe",
        session_id: Optional[str] = None,
        subject: Optional[Union[str, Subject]] = None,
        approvals: bool = True,
        raise_on_block: bool = False,
        on_policy_block: Optional[Callable[[Decision, BlockContext], Any]] = None,
        budget: Any = None,
        framework: Optional[str] = None,
        evaluate: Optional[Callable[..., Decision]] = None,
    ) -> None:
        self.workspace = Path(workspace) if workspace else Path.cwd()
        self.agent = agent
        self.agent_name = agent_name
        self.mode = mode
        self.session_id = session_id or f"{agent}-{os.getpid()}"
        self.subject = subject
        self.approvals = approvals
        self.raise_on_block = raise_on_block
        self.on_policy_block = on_policy_block
        self.budget = budget
        self.framework = framework or agent
        self._evaluate = evaluate

    # ── events ───────────────────────────────────────────────────────────────

    def build_event(
        self,
        tool_name: str,
        args: Sequence[Any] = (),
        kwargs: Optional[Dict[str, Any]] = None,
        *,
        event_type: str = "shell",
        payload: Optional[str] = None,
        session_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        budget: Any = None,
        subagent_id: Optional[str] = None,
        subagent_type: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Module-level :func:`build_event` with this client's defaults filled in.

        ``payload`` defaults to the flattened argument values.
        """
        kwargs = dict(kwargs or {})
        return build_event(
            tool_name=tool_name,
            payload=_flatten(args, kwargs) if payload is None else payload,
            event_type=event_type,
            session_id=session_id or self.session_id,
            agent=self.agent,
            args=tuple(args),
            kwargs=kwargs,
            framework=self.framework,
            subagent_id=subagent_id,
            subagent_type=subagent_type,
            metadata=metadata,
            budget=self.budget if budget is None else budget,
        )

    # ── check ────────────────────────────────────────────────────────────────

    def check_event(
        self,
        event: Dict[str, Any],
        *,
        session_id: Optional[str] = None,
        subject: Optional[Union[str, Subject]] = None,
    ) -> Decision:
        """Evaluate a pre-built canonical event. Never raises on a block.

        Runs ``log_observe_findings`` afterwards so observe mode is not
        silent about what enforce mode would have blocked.
        """
        sid = session_id or str(event.get("session_id") or "") or self.session_id
        evaluate = self._evaluate or _runtime.evaluate_tool_call
        decision = evaluate(
            event=event,
            workspace=self.workspace,
            agent=self.agent,
            agent_name=self.agent_name,
            mode=self.mode,
            session_id=sid,
            subject=resolve_subject(self.subject if subject is None else subject),
        )
        tool_name = str((event.get("metadata") or {}).get("tool_name") or "")
        _runtime.log_observe_findings(decision, mode=self.mode, tool_name=tool_name)
        return decision

    def check(
        self,
        tool_name: str,
        args: Sequence[Any] = (),
        kwargs: Optional[Dict[str, Any]] = None,
        *,
        event_type: str = "shell",
        payload: Optional[str] = None,
        session_id: Optional[str] = None,
        subject: Optional[Union[str, Subject]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        budget: Any = None,
        subagent_id: Optional[str] = None,
        subagent_type: Optional[str] = None,
    ) -> Decision:
        """Evaluate one tool call. Never raises on a block.

        ``decision.allow`` says whether the call may proceed; ``verdict``,
        ``rule_id``, ``reason`` and ``findings`` say why.
        """
        event = self.build_event(
            tool_name, args, kwargs,
            event_type=event_type, payload=payload, session_id=session_id,
            metadata=metadata, budget=budget,
            subagent_id=subagent_id, subagent_type=subagent_type,
        )
        return self.check_event(event, session_id=session_id, subject=subject)

    # ── block handling ───────────────────────────────────────────────────────

    def _resolution(self, outcome: Any, args: tuple, kwargs: Dict[str, Any], approvals_mod: Any) -> BlockResolution:
        if not outcome:
            return BlockResolution(False, args, kwargs)
        if getattr(outcome, "redacted", False):
            # "Approve redacted": the approver let the call through on condition
            # that the flagged values are stripped first. Redaction happens
            # here, on-device — the console only ever saw masked values. Any
            # error propagates to the caller's fail-closed branch.
            return BlockResolution(
                True,
                tuple(approvals_mod.redact_approved_payload(args, workspace=self.workspace)),
                dict(approvals_mod.redact_approved_payload(kwargs, workspace=self.workspace)),
                redacted=True,
            )
        return BlockResolution(True, args, kwargs)

    def resolve_block(
        self,
        decision: Decision,
        *,
        args: Sequence[Any] = (),
        kwargs: Optional[Dict[str, Any]] = None,
        event: Optional[Dict[str, Any]] = None,
    ) -> BlockResolution:
        """Headless ``step_up``: post an approval request and wait for a decision.

        Fail closed: approvals off, not enrolled, denied, expired, timed out,
        or any error on the path → ``approved=False``.
        """
        args = tuple(args)
        kwargs = dict(kwargs or {})
        if self.approvals:
            try:
                from prismor.runtime.enterprise import approvals as _approvals
                outcome = _approvals.await_step_up(
                    decision, event=event, agent=self.agent,
                    session_id=str((event or {}).get("session_id") or self.session_id),
                )
                return self._resolution(outcome, args, kwargs, _approvals)
            except Exception:
                pass  # any approval-path error fails closed
        return BlockResolution(False, args, kwargs)

    async def resolve_block_async(
        self,
        decision: Decision,
        *,
        args: Sequence[Any] = (),
        kwargs: Optional[Dict[str, Any]] = None,
        event: Optional[Dict[str, Any]] = None,
    ) -> BlockResolution:
        """:meth:`resolve_block` for ``async`` tools.

        The wait runs in a worker thread so the event loop keeps servicing
        concurrent tools and streams while a human decides.
        """
        args = tuple(args)
        kwargs = dict(kwargs or {})
        if self.approvals:
            try:
                from prismor.runtime.enterprise import approvals as _approvals
                outcome = await _approvals.await_step_up_async(
                    decision, event=event, agent=self.agent,
                    session_id=str((event or {}).get("session_id") or self.session_id),
                )
                return self._resolution(outcome, args, kwargs, _approvals)
            except Exception:
                pass  # any approval-path error fails closed
        return BlockResolution(False, args, kwargs)

    def on_blocked(self, decision: Decision, ctx: BlockContext) -> Any:
        """Render a denied call.

        ``on_policy_block`` decides when set (its return value is the tool
        result; exceptions propagate). Otherwise raise :class:`PrismorBlocked`
        when ``raise_on_block``, else return the denial string the model sees.
        """
        if self.on_policy_block is not None:
            return self.on_policy_block(decision, ctx)
        reason = decision.reason or "policy violation"
        if self.raise_on_block:
            raise PrismorBlocked(reason, decision)
        return _DENIAL_PREFIX + reason

    # ── results ──────────────────────────────────────────────────────────────

    def redact(self, result: Any, decision: Optional[Decision] = None) -> Any:
        """Mask cloaked secrets and data-boundary values in a tool's OUTPUT.

        The pre-call check can only refuse; a tool that reads a file with a
        credential in it is allowed, and the credential is in the return value.
        Pass the ``decision`` so its policy engine is reused. Never raises.
        """
        return redact_tool_result(
            result, workspace=self.workspace,
            engine=decision.engine if decision is not None else None,
        )

    # ── guard ────────────────────────────────────────────────────────────────

    def guard(
        self,
        fn: Callable[..., Any],
        *,
        tool_name: Optional[str] = None,
        event_type: str = "shell",
        payload_builder: Optional[Callable[[tuple, dict], str]] = None,
        is_async: Optional[bool] = None,
    ) -> Callable[..., Any]:
        """Wrap a sync or async callable: check → approve → run → redact.

        A denied call never runs ``fn``; what the caller gets instead is
        decided by :meth:`on_blocked`. ``payload_builder`` maps
        ``(args, kwargs)`` to the matchable string (default: the flattened
        argument values). ``is_async`` overrides coroutine-function detection.
        """
        name = tool_name or getattr(fn, "__name__", None) or fn.__class__.__name__
        if is_async is None:
            is_async = inspect.iscoroutinefunction(fn)

        def _decide(args: tuple, kwargs: Dict[str, Any]) -> Tuple[Decision, Dict[str, Any], Optional[BlockResolution]]:
            payload = payload_builder(args, kwargs) if payload_builder is not None else None
            event = self.build_event(name, args, kwargs, event_type=event_type, payload=payload)
            decision = self.check_event(event)
            if decision.allow:
                return decision, event, None
            return decision, event, self.resolve_block(decision, args=args, kwargs=kwargs, event=event)

        def _context(args: tuple, kwargs: Dict[str, Any], event: Dict[str, Any]) -> BlockContext:
            return BlockContext(name, tuple(args), dict(kwargs),
                                str(event.get("session_id") or self.session_id), event)

        if is_async:
            @functools.wraps(fn)
            async def guarded_async(*args: Any, **kwargs: Any) -> Any:
                # A step_up inside _decide can wait minutes for a human; run the
                # whole decision in a worker thread so this event loop keeps
                # servicing other tools and streams instead of sleeping with it.
                decision, event, res = await _in_thread(_decide, args, kwargs)
                if res is not None:
                    if not res.approved:
                        return self.on_blocked(decision, _context(args, kwargs, event))
                    args, kwargs = res.args, res.kwargs
                return self.redact(await fn(*args, **kwargs), decision)

            guarded_async.__prismor_guarded__ = True  # type: ignore[attr-defined]
            return guarded_async

        @functools.wraps(fn)
        def guarded(*args: Any, **kwargs: Any) -> Any:
            decision, event, res = _decide(args, kwargs)
            if res is not None:
                if not res.approved:
                    return self.on_blocked(decision, _context(args, kwargs, event))
                args, kwargs = res.args, res.kwargs
            return self.redact(fn(*args, **kwargs), decision)

        guarded.__prismor_guarded__ = True  # type: ignore[attr-defined]
        return guarded

    # ── registration ─────────────────────────────────────────────────────────

    def declare_tools(self, names: Optional[Sequence[Any]] = None, *, goal: Optional[str] = None) -> None:
        """Register the agent's tool roster and capture its goal. Best-effort.

        ``names`` (when given, even empty) records the agent and its declared
        tools in the workspace inventory; ``goal`` synthesizes the session's
        intent-scoped rules so ``evaluate_tool_call`` can enforce task
        alignment for this headless agent. Neither ever raises.
        """
        roster = [str(n) for n in (names or []) if n]
        if names is not None:
            try:
                from prismor.runtime.agents import record_seen
                record_seen(
                    self.agent_name or self.agent, framework=self.agent,
                    workspace=self.workspace,
                    tools=[{"name": n, "source": "declared"} for n in roster],
                    session_id=self.session_id,
                )
            except Exception:
                pass
        if goal:
            try:
                from prismor.runtime.intent import capture_intent
                capture_intent(
                    goal, workspace=self.workspace, session_id=self.session_id,
                    available_tools=roster or None, agent=self.agent,
                )
            except Exception:
                pass
