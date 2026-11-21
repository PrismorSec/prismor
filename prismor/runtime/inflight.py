"""Authority checks after the allow (#942).

A tool call is judged before it runs. Two later points matter too:

* **commit** - the moment a slow tool applies its effect (``freeze_account``
  after a minute of lookups). :func:`recheck_before_commit` re-runs the
  decision there; a refusal is ``revoked_before_commit``.
* **while running** - :func:`run_cancellable` (async) and
  :func:`wait_cancellable` (a blocking call in a worker thread) re-check on
  every policy refresh and stop the call when the new policy would refuse it
  (a pause, a subject control, a restricted resource). The outcome is
  ``cancelled_in_flight``.

Both record the refusing rule and policy version on the signed trail.

Both also send the refusal to the console: a block on the session and,
when ``approval_id`` is given, the approval's real outcome.

``resource`` may be a dict or a zero-arg callable returning the current
state, so a re-check judges the account as it is now, not as it was at the
allow. Limits: a sync Python function cannot be stopped mid-run (we stop
waiting for it and refuse its result); harness hooks (Claude Code, Codex,
Copilot) run the tool themselves, so only the pre-call check applies there.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import contextvars
import threading
from typing import Any, Callable, Dict, Optional, Union

Resource = Union[None, Dict[str, Any], Callable[[], Optional[Dict[str, Any]]]]


class Refused(Exception):
    """The call lost its authority after the allow. ``status`` is
    ``revoked_before_commit`` or ``cancelled_in_flight``."""

    def __init__(self, status: str, reason: str, rule: Optional[str] = None) -> None:
        super().__init__(reason)
        self.status = status
        self.reason = reason
        self.rule = rule


def _resolve(resource: Resource) -> Optional[Dict[str, Any]]:
    return resource() if callable(resource) else resource


def interval() -> float:
    try:
        from prismor.runtime.enterprise import remote_policy as _rp
        return _rp._refresh_interval()
    except Exception:
        return 30.0


def still_refused(decision: Any, resource: Optional[Dict[str, Any]] = None, *,
                  refresh: Optional[float] = None) -> Optional[Any]:
    """Re-run ``decision`` now. Returns the refusing Decision, or None when the
    call may proceed. A step-up by the same rule counts as allowed: the caller
    only gets here after that step-up was approved (or never had one).
    ``refresh`` is the policy-refresh debounce (0 forces a fetch). A failing
    re-check fails closed."""
    recheck = getattr(decision, "recheck", None)
    if recheck is None:
        return None  # caller built its own Decision; nothing to re-run
    try:
        from prismor.runtime.enterprise import remote_policy as _rp
        _rp.check_and_refresh(interval=refresh)
    except Exception:
        pass
    try:
        now = recheck(resource)
    except Exception as exc:
        from prismor.runtime.contract import Decision
        return Decision(allow=False, blocking={"ruleId": "recheck-failed"},
                        reason=f"re-check failed: {exc}")
    if now.allow:
        return None
    was = getattr(decision, "blocking", None) or {}
    blk = now.blocking or {}
    if (str(blk.get("action") or "").lower() == "step_up"
            and blk.get("ruleId") and blk.get("ruleId") == was.get("ruleId")):
        return None
    return now


def refusing_rule(now: Any) -> Optional[str]:
    return (now.blocking or {}).get("ruleId") or getattr(now, "rule_id", None)


def _record(status: str, now: Any, *, tool: str, agent: str, session_id: str,
            resource: Optional[Dict[str, Any]], decision: Any = None,
            approval_id: Optional[str] = None) -> Refused:
    """Record a refusal after the allow: the signed trail, the console's
    session (as a block with the refusing rule) and, for an approved call,
    the approval's outcome, which replaces the earlier ``executed``."""
    rule = refusing_rule(now)
    reason = str(now.reason or rule or "policy changed")
    try:
        from prismor.runtime.enterprise import audit_trail as _audit
        if _audit.enabled():
            _audit.append_approval_record(
                status=status, tool=tool, agent=agent, session_id=session_id,
                resource=resource, rules=[rule] if rule else [],
                reason=f"{status.replace('_', ' ')}: {reason}", approval_id=approval_id)
    except Exception:
        pass
    report = getattr(decision, "on_refused", None)
    if callable(report):
        try:
            report(status, now)
        except Exception:
            pass
    if approval_id:
        try:
            from prismor.runtime.enterprise import approvals as _approvals
            from prismor.runtime.enterprise import identity as _identity
            ident = _identity.load_identity()
            if ident:
                _approvals._report_outcome(ident, approval_id, status, rules=[rule] if rule else None,
                                           reason=reason, resource=resource)
        except Exception:
            pass
    return Refused(status, reason, rule)


def recheck_before_commit(decision: Any, *, resource: Resource = None, tool: str = "",
                          agent: str = "", session_id: str = "",
                          approval_id: Optional[str] = None) -> None:
    """Call as the last step before the tool's effect. Raises :class:`Refused`
    (``revoked_before_commit``) when the call is no longer allowed. Forces a
    policy fetch, so a pause set in the console since the allow is seen."""
    res = _resolve(resource)
    now = still_refused(decision, res, refresh=0)
    if now is not None:
        raise _record("revoked_before_commit", now, tool=tool, agent=agent,
                      session_id=session_id, resource=res, decision=decision,
                      approval_id=approval_id)


async def run_cancellable(decision: Any, awaitable: Any, *, resource: Resource = None,
                          tool: str = "", agent: str = "", session_id: str = "",
                          every: Optional[float] = None,
                          approval_id: Optional[str] = None) -> Any:
    """Await ``awaitable`` as a task, re-checking every ``every`` seconds (the
    policy refresh interval by default). Cancels the task and raises
    :class:`Refused` (``cancelled_in_flight``) when a re-check refuses."""
    task = asyncio.ensure_future(awaitable)
    step = every or interval()
    try:
        while True:
            done, _ = await asyncio.wait({task}, timeout=step)
            if done:
                return task.result()
            res = await asyncio.to_thread(_resolve, resource)
            now = await asyncio.to_thread(still_refused, decision, res)
            if now is not None:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
                raise _record("cancelled_in_flight", now, tool=tool, agent=agent,
                              session_id=session_id, resource=res, decision=decision,
                              approval_id=approval_id)
    finally:
        if not task.done():  # our own caller was cancelled
            task.cancel()


def wait_cancellable(decision: Any, fn: Callable[[], Any], *, resource: Resource = None,
                     tool: str = "", agent: str = "", session_id: str = "",
                     every: Optional[float] = None,
                     on_cancel: Optional[Callable[[], None]] = None,
                     approval_id: Optional[str] = None) -> Any:
    """Run blocking ``fn`` in a daemon thread and wait for it, re-checking every
    ``every`` seconds. On refusal, calls ``on_cancel`` (e.g. send MCP
    ``notifications/cancelled``), stops waiting and raises :class:`Refused`.
    The thread itself cannot be killed; its late result is dropped."""
    fut: concurrent.futures.Future = concurrent.futures.Future()

    def _run() -> None:
        try:
            fut.set_result(fn())
        except BaseException as exc:  # noqa: BLE001 - re-raised in the caller
            fut.set_exception(exc)

    ctx = contextvars.copy_context()  # subject / session context of the caller
    threading.Thread(target=ctx.run, args=(_run,), daemon=True, name="prismor-inflight").start()
    step = every or interval()
    while True:
        try:
            return fut.result(timeout=step)
        except concurrent.futures.TimeoutError:
            pass
        res = _resolve(resource)
        now = still_refused(decision, res)
        if now is not None:
            if on_cancel is not None:
                try:
                    on_cancel()
                except Exception:
                    pass
            raise _record("cancelled_in_flight", now, tool=tool, agent=agent,
                          session_id=session_id, resource=res, decision=decision,
                          approval_id=approval_id)
