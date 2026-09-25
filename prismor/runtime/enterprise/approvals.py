"""Async human-in-the-loop approval for headless STEP_UP actions.

Interactive coding agents (Claude/Copilot) render a STEP_UP verdict as an inline
"ask" prompt at the hook boundary (see cli.py). A *headless* framework agent — an
OpenAI Agents / LangChain / CrewAI / browser-use worker running unattended — has
no human at the keyboard, so Phase 1 fails those closed to DENY.

This module is the Phase 2 path: on a STEP_UP verdict, the in-process adapter
posts a pending **approval request** to the control plane and blocks, polling
until an org admin approves or denies (or a timeout elapses). Approve → the tool
call proceeds; deny/timeout/any error → fail closed (blocked). The wait happens
inside the adapter's own long-lived process, so unlike the short-lived hook it
can genuinely pause the action.

Control-plane contract:
  POST {api}/api/approvals            (device bearer) → {id, status}
  GET  {api}/api/approvals/{id}       (device bearer) → {id, status}
Statuses: ``pending`` | ``approved`` | ``denied`` | ``expired``.

Failure posture: never raise into the tool path. Not enrolled, network error,
or timeout all resolve to "not approved" so the caller fails closed. Tunables:
``PRISMOR_APPROVAL_TIMEOUT`` (s, default 300) and ``PRISMOR_APPROVAL_POLL``
(s, default 3).
"""
from __future__ import annotations

from prismor.runtime.http_ua import user_agent as _http_user_agent

import hashlib
import json
import os
import time
from typing import Tuple, Any, Dict, Optional

from prismor.runtime.enterprise import identity as _identity

DEFAULT_TIMEOUT = 300.0
DEFAULT_POLL = 3.0
_PENDING = "pending"
_APPROVED = "approved"
_DECIDED = {"approved", "denied", "expired"}


def _timeout() -> float:
    try:
        return max(1.0, float(os.environ.get("PRISMOR_APPROVAL_TIMEOUT", DEFAULT_TIMEOUT)))
    except (TypeError, ValueError):
        return DEFAULT_TIMEOUT


def _poll_interval() -> float:
    try:
        return max(0.5, float(os.environ.get("PRISMOR_APPROVAL_POLL", DEFAULT_POLL)))
    except (TypeError, ValueError):
        return DEFAULT_POLL


def enabled() -> bool:
    """Master switch for headless approvals (``PRISMOR_APPROVALS``).

    Defaults to on. Set ``PRISMOR_APPROVALS=0`` (or ``false``/``off``/``no``)
    to disable escalation entirely: a STEP_UP verdict is then not posted to the
    control plane and the caller fails closed - exactly the posture of an
    unenrolled install. Per-guard opt-out is available via the adapters'
    ``approvals=False`` keyword; this env var is the fleet-wide override.
    """
    val = str(os.environ.get("PRISMOR_APPROVALS", "1")).strip().lower()
    return val not in ("0", "false", "off", "no")


def step_up_finding(decision: Any) -> Optional[Dict[str, Any]]:
    """The blocking finding iff it is a STEP_UP verdict, else None."""
    blocking = getattr(decision, "blocking", None)
    if isinstance(blocking, dict) and str(blocking.get("action") or "").lower() == "step_up":
        return blocking
    return None


def _fingerprint(session_id: str, tool: str, evidence_hash: str) -> str:
    """Stable id for one logical action, so repeated attempts of the same call
    coalesce onto one approval request instead of spamming the queue."""
    raw = f"{session_id}\x1f{tool}\x1f{evidence_hash}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:32]


def _headers(ident: Dict[str, Any]) -> Dict[str, str]:
    return {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {ident.get('device_key')}",
    }


def _post_request(ident: Dict[str, Any], body: Dict[str, Any], timeout: float) -> Optional[Dict[str, Any]]:
    import urllib.request
    import urllib.error

    base = str(ident.get("api_base") or _identity.api_base()).rstrip("/")
    url = f"{base}/api/approvals"
    req = urllib.request.Request(
        url, data=json.dumps(body).encode("utf-8"), headers=_headers(ident), method="POST"
    )
    req.add_header("User-Agent", _http_user_agent())
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # fixed or operator-configured URL  # nosec B310
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, OSError, ValueError):
        return None


def _get_status(ident: Dict[str, Any], approval_id: str, timeout: float) -> Optional[str]:
    """Current status string, or None on any transport error."""
    status, _mode = _get_status_ex(ident, approval_id, timeout)
    return status


def _get_status_ex(ident: Dict[str, Any], approval_id: str, timeout: float) -> Tuple[Optional[str], str]:
    """``(status, decision_mode)``. ``decision_mode`` is ``"redacted"`` when the
    approver chose "approve with sensitive values stripped" — the runtime then
    redacts locally before the call runs (see :func:`redact_approved_payload`)."""
    import urllib.request
    import urllib.error

    base = str(ident.get("api_base") or _identity.api_base()).rstrip("/")
    url = f"{base}/api/approvals/{approval_id}"
    req = urllib.request.Request(url, headers=_headers(ident), method="GET")
    req.add_header("User-Agent", _http_user_agent())
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # fixed or operator-configured URL  # nosec B310
            data = json.loads(resp.read().decode("utf-8"))
        status = str(data.get("status") or "").lower() or None
        mode = str(data.get("decision_mode") or data.get("decisionMode") or "full").lower()
        return status, mode
    except (urllib.error.URLError, OSError, ValueError):
        return None, "full"


def _audit_outcome(
    body: Dict[str, Any],
    *,
    status: str,
    approval_id: Optional[str],
    agent: str,
    session_id: str,
) -> None:
    """Record the human-approval outcome on the signed audit trail.

    Best-effort: the approval decision itself is already final; the trail
    write must never change it or raise into the tool path."""
    try:
        from prismor.runtime.enterprise import audit_trail as _audit
        if _audit.enabled():
            _audit.append_approval_record(
                status=status,
                approval_id=approval_id,
                tool=str(body.get("tool") or ""),
                rule_id=body.get("rule_id"),
                severity=body.get("severity"),
                reason=str(body.get("reason") or ""),
                fingerprint=str(body.get("fingerprint") or ""),
                agent=agent,
                session_id=session_id,
            )
    except Exception:
        pass


class ApprovalOutcome:
    """Result of a headless step-up: ``approved`` plus whether the approver
    asked for the sensitive values to be stripped first (``redacted``)."""

    __slots__ = ("approved", "redacted", "approval_id", "status")

    def __init__(self, approved: bool, redacted: bool = False, approval_id: Optional[str] = None,
                 status: str = "") -> None:
        self.approved = approved
        self.redacted = redacted
        self.approval_id = approval_id
        self.status = status

    def __bool__(self) -> bool:  # backwards compatible with the old bool return
        return self.approved


def redact_approved_payload(payload: Any, *, workspace: Any = None) -> Any:
    """Strip classified sensitive values from ``payload`` (str / dict / list of
    tool arguments) after an "approve redacted" decision. Uses the same
    classifier as the data-boundary policy so what gets stripped is exactly
    what the approver saw flagged. Best-effort: on any error the original is
    returned unchanged (the call was approved; redaction is the extra ask)."""
    try:
        from prismor.runtime.data_boundary import redact_payload
        return redact_payload(payload, workspace=workspace)
    except Exception:
        return payload


def enqueue_step_up(
    finding: Dict[str, Any],
    *,
    event: Optional[Dict[str, Any]] = None,
    agent: str = "",
    session_id: str = "",
    timeout: float = 2.0,
) -> Optional[str]:
    """Post an approval request and return immediately with its id (or None).

    The fire-and-forget half of :func:`await_step_up`, for callers that cannot
    hold the action open while a human decides. The hosted inference-hook
    channel is the motivating case: it answers Anthropic inside a few-second
    budget, so a STEP_UP is answered ``deny`` *now* and the request is queued
    for the approver to resolve out-of-band (the user retries once granted).

    Never raises and never blocks beyond ``timeout``. Returns None when
    approvals are off, the box is not enrolled, or the post fails — the caller
    must still fail closed on its own.
    """
    if not finding or not enabled():
        return None
    ident = _identity.load_identity()
    if not ident or _identity.revoked_backoff_active():
        return None  # no control plane to approve through → fail closed

    tool = str(finding.get("toolName") or (event or {}).get("type") or "tool")
    body = {
        "fingerprint": _fingerprint(
            session_id, tool,
            str(finding.get("evidence_hash") or finding.get("evidenceHash") or ""),
        ),
        "tool": tool,
        "reason": str(finding.get("title") or "policy step-up"),
        "rule_id": finding.get("ruleId"),
        "severity": finding.get("severity"),
        "session_id": session_id or None,
        "agent": agent or None,
    }
    created = _post_request(ident, body, timeout=timeout)
    approval_id = str(created.get("id")) if created and created.get("id") else None
    try:
        _audit_outcome(
            body,
            status="queued" if approval_id else "request_failed",
            approval_id=approval_id,
            agent=agent,
            session_id=session_id,
        )
    except Exception:
        pass
    return approval_id


def await_step_up(
    decision: Any,
    *,
    event: Optional[Dict[str, Any]] = None,
    agent: str = "",
    session_id: str = "",
) -> "ApprovalOutcome":
    """Post an approval request for a STEP_UP finding and block until decided.

    Returns an :class:`ApprovalOutcome` that is truthy only on an explicit
    ``approved`` (so existing ``if await_step_up(...)`` callers keep working).
    ``outcome.redacted`` is True when the approver chose "approve redacted":
    the caller should pass its arguments through :func:`redact_approved_payload`
    before running the tool. Not enrolled, denied, expired, timeout, or any
    error → falsy (the caller must fail closed). Safe to call for any decision —
    a no-op returning falsy when the verdict is not STEP_UP. Every resolved
    request (approved/denied/expired/timeout/request_failed) is recorded on the
    signed audit trail.
    """
    finding = step_up_finding(decision)
    if finding is None or not enabled():
        return ApprovalOutcome(False)
    ident = _identity.load_identity()
    if not ident or _identity.revoked_backoff_active():
        return ApprovalOutcome(False)  # no control plane to approve through → fail closed

    tool = str(finding.get("toolName") or (event or {}).get("type") or "tool")
    body = {
        "fingerprint": _fingerprint(session_id, tool, str(finding.get("evidence_hash") or finding.get("evidenceHash") or "")),
        "tool": tool,
        "reason": str(finding.get("title") or "policy step-up"),
        "rule_id": finding.get("ruleId"),
        "category": finding.get("category"),
        "severity": finding.get("severity"),
        "session_id": session_id or None,
        "agent": agent or None,
    }
    # Data-boundary context so the approver sees WHAT is being sent, WHERE,
    # and which doc induced it — labels only (classes/tier/kind), the masked
    # evidence the finding already carries, and the destination host.
    if finding.get("dataClasses"):
        body["params"] = {
            "data_classes": list(finding.get("dataClasses") or []),
            "data_subject": finding.get("dataSubject"),
            "dest_host": finding.get("destHost"),
            "dest_trust": finding.get("destTrust"),
            "masked": str(finding.get("evidence") or "")[:200],
            "provenance": finding.get("provenance"),
        }

    def _record(status: str, approval_id: Optional[str] = None) -> None:
        _audit_outcome(
            body, status=status, approval_id=approval_id,
            agent=agent, session_id=session_id,
        )

    poll_timeout = min(10.0, _poll_interval() + 5.0)
    created = _post_request(ident, body, timeout=poll_timeout)
    if not created or not created.get("id"):
        _record("request_failed")
        return ApprovalOutcome(False, status="request_failed")
    approval_id = str(created["id"])
    if str(created.get("status") or "").lower() == _APPROVED:
        _mode = str(created.get("decision_mode") or created.get("decisionMode") or "full").lower()
        _record("approved" if _mode != "redacted" else "approved_redacted", approval_id)
        return ApprovalOutcome(True, redacted=_mode == "redacted", approval_id=approval_id, status="approved")

    deadline = _monotonic() + _timeout()
    interval = _poll_interval()
    while _monotonic() < deadline:
        time.sleep(interval)
        status = _get_status(ident, approval_id, timeout=poll_timeout)
        if status == _APPROVED:
            _st, mode = _get_status_ex(ident, approval_id, timeout=poll_timeout)
            mode = mode if _st == _APPROVED else "full"
            _record("approved" if mode != "redacted" else "approved_redacted", approval_id)
            return ApprovalOutcome(True, redacted=mode == "redacted", approval_id=approval_id, status="approved")
        if status in _DECIDED:  # denied / expired
            _record(status, approval_id)
            return ApprovalOutcome(False, approval_id=approval_id, status=status)
    _record("timeout", approval_id)
    return ApprovalOutcome(False, approval_id=approval_id, status="timeout")  # timed out → fail closed


async def await_step_up_async(
    decision: Any,
    *,
    event: Optional[Dict[str, Any]] = None,
    agent: str = "",
    session_id: str = "",
) -> "ApprovalOutcome":
    """Event-loop-safe :func:`await_step_up`.

    The sync poll loop sleeps for up to ``PRISMOR_APPROVAL_TIMEOUT`` seconds;
    called directly from an ``async def`` tool wrapper it would park the entire
    event loop - stalling every concurrent tool, LLM stream, and (for
    browser-use) the CDP socket - until a human decides. This variant runs the
    wait in a worker thread instead, so the loop keeps servicing. Same
    contract: truthy only on an explicit approval, everything else falsy.
    """
    if step_up_finding(decision) is None or not enabled():
        return ApprovalOutcome(False)
    import asyncio

    return await asyncio.to_thread(
        await_step_up, decision, event=event, agent=agent, session_id=session_id
    )


def _monotonic() -> float:
    return time.monotonic()
