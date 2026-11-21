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


# Per-attempt fields: a retry of the same call differs only in these.
_VOLATILE_EVENT_KEYS = ("ts", "metadata", "session_id")


def call_key(event: Optional[Dict[str, Any]], resource: Optional[Dict[str, Any]] = None) -> str:
    """What one call does: its event minus per-attempt fields, plus the kind
    and id of the resource it acts on (not its attributes, which change while
    an approval waits). An approval or a deferred verdict covers only calls
    with the same key, never another command or account in the same session."""
    view = {k: v for k, v in event.items() if k not in _VOLATILE_EVENT_KEYS} if isinstance(event, dict) else {}
    meta = event.get("metadata") if isinstance(event, dict) else None
    if isinstance(meta, dict) and meta.get("tool_name"):
        view["_tool"] = meta["tool_name"]
    if isinstance(resource, dict) and (resource.get("kind") or resource.get("id")):
        view["_resource"] = [resource.get("kind"), resource.get("id")]
    if not view:
        return ""
    return hashlib.sha256(json.dumps(view, sort_keys=True, default=str).encode("utf-8")).hexdigest()[:32]


def _fingerprint(session_id: str, tool: str, evidence_hash: str, key: str = "") -> str:
    """Stable id for one logical action, so repeated attempts of the same call
    coalesce onto one approval request instead of spamming the queue. ``key``
    (:func:`call_key`) keeps two different calls of one tool apart: runtime
    findings carry no evidence hash, so without it every held call of a tool
    in a session reused the first approval."""
    raw = f"{session_id}\x1f{tool}\x1f{evidence_hash}\x1f{key}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:32]


def _headers(ident: Dict[str, Any]) -> Dict[str, str]:
    from prismor.runtime.http_ua import user_agent
    return {
        "Content-Type": "application/json",
        "User-Agent": user_agent(),
        "Authorization": f"Bearer {ident.get('device_key')}",
    }


def _post_request(ident: Dict[str, Any], body: Dict[str, Any], timeout: float,
                  path: str = "/api/approvals") -> Optional[Dict[str, Any]]:
    import urllib.request
    import urllib.error

    base = str(ident.get("api_base") or _identity.api_base()).rstrip("/")
    url = f"{base}{path}"
    req = urllib.request.Request(
        url, data=json.dumps(body).encode("utf-8"), headers=_headers(ident), method="POST"
    )
    req.add_header("User-Agent", _http_user_agent())
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # fixed or operator-configured URL  # nosec B310
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, OSError, ValueError):
        return None


def _report_outcome(ident: Dict[str, Any], approval_id: Optional[str], outcome: str,
                    rules: Optional[list] = None, reason: Optional[str] = None,
                    resource: Optional[Dict[str, Any]] = None) -> None:
    """Tell the console what happened after the approval (``executed`` or a
    refusal on re-check), so its history matches the signed trail
    (prismor-web#510). Kind and id of the resource only, never attributes.
    Best-effort: an old console answers 404/405 and nothing changes."""
    if not approval_id:
        return
    body: Dict[str, Any] = {"outcome": outcome}
    if rules:
        body["rule_id"] = str(rules[0])
    if reason:
        body["reason"] = str(reason)[:500]
    if isinstance(resource, dict) and (resource.get("kind") or resource.get("id")):
        body["resource"] = {"kind": resource.get("kind"), "id": resource.get("id")}
    try:
        _post_request(ident, body, timeout=3.0, path=f"/api/approvals/{approval_id}")
    except Exception:
        pass


def _decision_mode(data: Dict[str, Any]) -> str:
    """``"full"`` only when the response says so explicitly; a missing or
    unrecognised mode reads as ``"redacted"``. An approval never grants more
    than the approver can be shown to have chosen (#667)."""
    mode = str(data.get("decision_mode") or data.get("decisionMode") or "").strip().lower()
    return "full" if mode == "full" else "redacted"


def _get_status_ex(ident: Dict[str, Any], approval_id: str, timeout: float) -> Tuple[Any, ...]:
    """``(status, decision_mode, approver)``. ``approver`` is the console's
    ``decided_by`` (``{"id", "email"}``) and ``decided_via``, or None. ``decision_mode`` is ``"redacted"`` when the
    approver chose "approve with sensitive values stripped" — the runtime then
    redacts locally before the call runs (see :func:`redact_approved_payload`).
    Status and mode come from the same response; callers must not re-fetch one
    without the other."""
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
        who = data.get("decided_by") if isinstance(data.get("decided_by"), dict) else None
        approver = {**who, "via": data.get("decided_via")} if who else None
        return status, _decision_mode(data), approver
    except (urllib.error.URLError, OSError, ValueError, AttributeError):
        return None, "redacted", None


def _audit_outcome(
    body: Dict[str, Any],
    *,
    status: str,
    approval_id: Optional[str],
    agent: str,
    session_id: str,
    approver: Optional[Dict[str, Any]] = None,
    resource: Optional[Dict[str, Any]] = None,
    rules: Optional[list] = None,
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
                agent_name=str(body.get("agent") or ""),
                session_id=session_id,
                approver=approver,
                resource=resource,
                rules=rules,
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
    what the approver saw flagged. Fails closed: any error propagates, so the
    caller blocks the call instead of forwarding the unredacted payload the
    approver only allowed on condition of redaction."""
    from prismor.runtime.data_boundary import redact_payload
    return redact_payload(payload, workspace=workspace)


def enqueue_step_up(
    finding: Dict[str, Any],
    *,
    event: Optional[Dict[str, Any]] = None,
    agent: str = "",
    session_id: str = "",
    timeout: float = 2.0,
    tool: str = "",
    agent_name: str = "",
) -> "ApprovalOutcome":
    """Post an approval request and return immediately with its outcome.

    The fire-and-forget half of :func:`await_step_up`, for callers that cannot
    hold the action open while a human decides. The hosted inference-hook
    channel is the motivating case: it answers Anthropic inside a few-second
    budget, so a STEP_UP is answered ``deny`` *now* and the request is queued
    for the approver to resolve out-of-band (the user retries once granted).

    The retry re-posts the same fingerprint, and the console answers it with
    the approval already granted: the outcome is truthy only then. A
    ``redacted`` approval is not truthy — this path cannot strip values from
    the call. Never raises and never blocks beyond ``timeout``; approvals off,
    not enrolled, or a failed post all give a falsy outcome with no id.
    """
    if not finding or not enabled():
        return ApprovalOutcome(False, status="disabled")
    ident = _identity.load_identity()
    if not ident or _identity.revoked_backoff_active():
        return ApprovalOutcome(False, status="not_enrolled")  # no control plane → fail closed

    tool = str(tool or finding.get("toolName") or (event or {}).get("type") or "tool")
    body = {
        "fingerprint": _fingerprint(
            session_id, tool,
            str(finding.get("evidence_hash") or finding.get("evidenceHash") or ""),
            call_key(event),
        ),
        "tool": tool,
        "reason": str(finding.get("title") or "policy step-up"),
        "rule_id": finding.get("ruleId"),
        "severity": finding.get("severity"),
        "session_id": session_id or None,
        "agent": agent_name or agent or None,
    }
    created = _post_request(ident, body, timeout=timeout)
    approval_id = str(created.get("id")) if created and created.get("id") else None
    approved = bool(approval_id) and str(created.get("status") or "").lower() == _APPROVED \
        and _decision_mode(created) != "redacted"
    status = "approved" if approved else "queued" if approval_id else "request_failed"
    try:
        _audit_outcome(body, status=status, approval_id=approval_id, agent=agent, session_id=session_id)
    except Exception:
        pass
    return ApprovalOutcome(approved, approval_id=approval_id, status=status)


def await_step_up(
    decision: Any,
    *,
    event: Optional[Dict[str, Any]] = None,
    agent: str = "",
    session_id: str = "",
    tool: str = "",
    agent_name: str = "",
    resource: Optional[Dict[str, Any]] = None,
) -> "ApprovalOutcome":
    """Post an approval request for a STEP_UP finding and block until decided.

    An approval is re-checked before it is returned: policy is refreshed and
    the call re-evaluated (against ``resource`` when the caller passes its
    current state). If anything other than the approved step-up now applies -
    the account was restricted, the agent paused, a rule added - the outcome
    is falsy with status ``revoked_after_approval``.

    ``tool`` and ``agent_name`` label the request for the approver: SDK
    findings carry no ``toolName``, so without them every request read
    tool "tool" and agent "<framework>" instead of the guarded instance.

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

    tool = str(tool or finding.get("toolName") or (event or {}).get("type") or "tool")
    body = {
        "fingerprint": _fingerprint(
            session_id, tool, str(finding.get("evidence_hash") or finding.get("evidenceHash") or ""),
            getattr(decision, "call_key", None) or call_key(event, resource),
        ),
        "tool": tool,
        "reason": str(finding.get("title") or "policy step-up"),
        "rule_id": finding.get("ruleId"),
        "category": finding.get("category"),
        "severity": finding.get("severity"),
        "session_id": session_id or None,
        "agent": agent_name or agent or None,
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

    # Which account/record the call acts on (kind + id only, never attributes),
    # so the approver sees it and the console can search and show it on every
    # row, not only after a refusal.
    if isinstance(resource, dict) and (resource.get("kind") or resource.get("id")):
        body.setdefault("params", {})["resource"] = {
            "kind": resource.get("kind"), "id": resource.get("id")}

    # How long this agent will poll before failing closed, so the console stops
    # offering an approve that can no longer change anything.
    body["wait_seconds"] = round(_timeout())

    def _record(status: str, approval_id: Optional[str] = None, reason: Optional[str] = None,
                approver: Optional[Dict[str, Any]] = None, rules: Optional[list] = None) -> None:
        if status == "revoked_after_approval":
            _report_outcome(ident, approval_id, status, rules=rules, reason=reason, resource=resource)
        _audit_outcome(
            {**body, "reason": reason} if reason else body,
            status=status, approval_id=approval_id,
            agent=agent, session_id=session_id, approver=approver,
            resource=resource, rules=rules,
        )

    poll_timeout = min(10.0, _poll_interval() + 5.0)
    created = _post_request(ident, body, timeout=poll_timeout)
    if not created or not created.get("id"):
        _record("request_failed")
        return ApprovalOutcome(False, status="request_failed")
    approval_id = str(created["id"])
    if str(created.get("status") or "").lower() == _APPROVED:
        _mode = _decision_mode(created)
        _record("approved" if _mode != "redacted" else "approved_redacted", approval_id)
        if _revoked_since(decision, finding, resource, _record, approval_id):
            return ApprovalOutcome(False, approval_id=approval_id, status="revoked_after_approval")
        _report_outcome(ident, approval_id, "executed")
        return ApprovalOutcome(True, redacted=_mode == "redacted", approval_id=approval_id, status="approved")

    deadline = _monotonic() + _timeout()
    interval = _poll_interval()
    while _monotonic() < deadline:
        time.sleep(interval)
        # Keep approval and its redaction requirement from the same response.
        res = _get_status_ex(ident, approval_id, timeout=poll_timeout)
        status, mode = res[0], res[1]
        approver = res[2] if len(res) > 2 else None
        if status == _APPROVED:
            _record("approved" if mode != "redacted" else "approved_redacted", approval_id, approver=approver)
            if _revoked_since(decision, finding, resource, _record, approval_id):
                return ApprovalOutcome(False, approval_id=approval_id, status="revoked_after_approval")
            _report_outcome(ident, approval_id, "executed")
            return ApprovalOutcome(True, redacted=mode == "redacted", approval_id=approval_id, status="approved")
        if status in _DECIDED:  # denied / expired
            _record(status, approval_id, approver=approver)
            return ApprovalOutcome(False, approval_id=approval_id, status=status)
    _record("timeout", approval_id)
    return ApprovalOutcome(False, approval_id=approval_id, status="timeout")  # timed out → fail closed


def _revoked_since(
    decision: Any,
    finding: Dict[str, Any],
    resource: Optional[Dict[str, Any]],
    record: Any,
    approval_id: Optional[str],
) -> bool:
    """True when the approved call must not run after all.

    Refreshes the org policy, then re-runs the evaluation. Still allowed, or
    held only by the same step-up rule the human just approved -> run it.
    Anything else (a block, a different step-up) -> refuse, and record why.
    Fails closed if the re-check itself errors."""
    from prismor.runtime import inflight as _inflight
    if getattr(decision, "recheck", None) is None:
        return False  # caller built its own Decision; nothing to re-run
    now = _inflight.still_refused(decision, resource, refresh=0)
    if now is None:
        return False
    # Name the rule that refused it, not the step-up rule the human approved.
    refusing = _inflight.refusing_rule(now)
    record("revoked_after_approval", approval_id,
           "approved, then refused on re-check: " + str(now.reason or refusing or "policy changed"),
           rules=[refusing] if refusing else None)
    return True


async def await_step_up_async(
    decision: Any,
    *,
    event: Optional[Dict[str, Any]] = None,
    agent: str = "",
    session_id: str = "",
    tool: str = "",
    agent_name: str = "",
    resource: Optional[Dict[str, Any]] = None,
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
        await_step_up, decision, event=event, agent=agent, session_id=session_id,
        tool=tool, agent_name=agent_name, resource=resource,
    )


def _monotonic() -> float:
    return time.monotonic()
