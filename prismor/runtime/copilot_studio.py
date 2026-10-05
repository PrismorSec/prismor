"""Microsoft Copilot Studio external threat detection on the eval-server.

Copilot Studio calls an external provider before every tool its generative
orchestrator runs, and blocks the tool when the provider says so. The provider
contract (api-version 2025-05-01) is two endpoints under a base URL:

    POST {base}/validate                  -> {"isSuccessful": true, "status": "OK"}
    POST {base}/analyze-tool-execution    -> {"blockAction": bool, "reasonCode",
                                              "reason", "diagnostics"}

A request maps onto Prismor events like this:

    plannerContext.previousToolOutputs  -> one ``tool_result`` event each,
                                           screened as untrusted content first
    toolDefinition.name + inputValues   -> the tool call (MCP pre-call shape:
                                           arguments as JSON text)
    plannerContext.userMessage/thought  -> metadata only (the user's own text)
    conversationMetadata.user.id        -> subject;  agent.tenantId -> tenant

The events share one ``InMemoryTaintStore``, as on the inference-hook channel,
so an injection planted in an earlier tool's output is visible to the call that
acts on it. Copilot Studio treats an answer slower than 1s as allow, so the
evaluation runs against a budget (default 800ms) and a miss returns the
configured fail verdict (block unless ``PRISMOR_COPILOT_STUDIO_FAIL_OPEN=1``).
The LLM judge never runs here: it cannot fit the budget.

Auth is an Entra ID bearer token: RS256, issued by the caller's tenant,
audience = this provider's base URL, from an allowlisted app id.

    PRISMOR_COPILOT_STUDIO_AUDIENCE          base URL (enables the routes)
    PRISMOR_COPILOT_STUDIO_ALLOWED_APP_IDS   comma list of Entra app ids
    PRISMOR_COPILOT_STUDIO_ALLOWED_TENANTS   comma list of tenant ids (optional)
    PRISMOR_COPILOT_STUDIO_INSECURE_NO_AUTH  1 = skip auth; localhost bind only
    PRISMOR_COPILOT_STUDIO_BUDGET_MS         evaluation budget (default 800)
    PRISMOR_COPILOT_STUDIO_FAIL_OPEN         1 = allow on timeout/error

See docs/copilot-studio.md.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

PREFIX = "/copilot-studio"
VALIDATE_PATH = PREFIX + "/validate"
ANALYZE_PATH = PREFIX + "/analyze-tool-execution"
AGENT_ID = "copilot-studio"
LOCAL_HOSTS = ("127.0.0.1", "localhost", "::1")

#: Stable reasonCode per finding category. Copilot Studio logs the code; keep
#: existing values fixed and append new ones.
REASON_CODES: Dict[str, int] = {
    "secret_exfiltration": 1, "secret_access": 1, "cloaked_secret": 1,
    "prompt_injection": 2, "prompt_injection_semantic": 2,
    "data_boundary": 3, "pii_exposure": 3,
    "network_isolation": 4, "egress": 4,
    "lethal_trifecta": 5,
    "destructive_command": 6, "db_modification": 6,
    "remote_execution": 7, "rce_canary": 7,
    "agent-control": 8, "iam": 8,
}
REASON_OTHER = 99
REASON_FAIL = 100  # evaluation timed out or errored; fail posture applied

_GUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_pool = ThreadPoolExecutor(max_workers=16)


class CopilotStudioError(Exception):
    """An error reply in Copilot Studio's error shape."""

    def __init__(self, http_status: int, message: str, error_code: Optional[int] = None) -> None:
        super().__init__(message)
        self.http_status = http_status
        self.message = message
        self.error_code = error_code if error_code is not None else http_status

    def body(self) -> Dict[str, Any]:
        return {"errorCode": self.error_code, "message": self.message, "httpStatus": self.http_status}


# ── config + auth ──────────────────────────────────────────────────────────


def _csv(name: str) -> List[str]:
    return [v.strip().lower() for v in os.environ.get(name, "").split(",") if v.strip()]


def insecure(bound_host: str) -> bool:
    """The dev escape: honored only when the server listens on loopback."""
    return os.environ.get("PRISMOR_COPILOT_STUDIO_INSECURE_NO_AUTH") == "1" and bound_host in LOCAL_HOSTS


def enabled(bound_host: str) -> bool:
    return bool(os.environ.get("PRISMOR_COPILOT_STUDIO_AUDIENCE")) or insecure(bound_host)


def _jwks_client(uri: str):
    from prismor.runtime.identity_token import _jwks_client as cached

    return cached(uri)


def authenticate(authorization: str, bound_host: str) -> Dict[str, Any]:
    """Verify the Entra bearer token. Returns its claims; raises 401/403."""
    if insecure(bound_host):
        return {}
    audience = os.environ.get("PRISMOR_COPILOT_STUDIO_AUDIENCE", "").strip()
    app_ids = _csv("PRISMOR_COPILOT_STUDIO_ALLOWED_APP_IDS")
    tenants = _csv("PRISMOR_COPILOT_STUDIO_ALLOWED_TENANTS")
    if not audience or not app_ids:
        raise CopilotStudioError(401, "provider misconfigured: set PRISMOR_COPILOT_STUDIO_AUDIENCE "
                                      "and PRISMOR_COPILOT_STUDIO_ALLOWED_APP_IDS")
    token = authorization[7:].strip() if authorization[:7].lower() == "bearer " else ""
    if not token:
        raise CopilotStudioError(401, "missing bearer token")
    try:
        import jwt
    except ImportError:
        raise CopilotStudioError(401, "token verification unavailable: pip install 'prismor[identity]'") from None
    try:
        # Unverified read of `tid` only, to pick the tenant's issuer and keys.
        # Nothing from it is trusted: the verified decode below re-checks iss.
        tid = str(jwt.decode(token, options={"verify_signature": False}).get("tid") or "")
    except jwt.InvalidTokenError as exc:
        raise CopilotStudioError(401, f"invalid token: {exc}") from None
    if not _GUID.match(tid):
        raise CopilotStudioError(401, "invalid token: no tenant (tid) claim")
    if tenants and tid.lower() not in tenants:
        raise CopilotStudioError(403, f"tenant {tid} is not allowed")
    base = "https://login.microsoftonline.com/" + tid
    try:
        key = _jwks_client(base + "/discovery/v2.0/keys").get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token, key.key, algorithms=["RS256"],
            audience=list({audience, audience.rstrip("/"), audience.rstrip("/") + "/"}),
            leeway=60, options={"require": ["exp", "iss", "aud"]},
        )
        # Checked by hand: a list `issuer=` needs a newer PyJWT than we pin.
        if claims.get("iss") not in (base + "/v2.0", f"https://sts.windows.net/{tid}/"):
            raise jwt.InvalidIssuerError(f"issuer {claims.get('iss')!r} is not tenant {tid}")
    except jwt.PyJWKClientError as exc:
        raise CopilotStudioError(401, f"signing key: {exc}") from None
    except jwt.InvalidTokenError as exc:
        raise CopilotStudioError(401, f"invalid token: {type(exc).__name__}: {exc}") from None
    app = str(claims.get("appid") or claims.get("azp") or "").lower()
    if app not in app_ids:
        raise CopilotStudioError(403, f"app {app or '?'} is not allowed")
    return claims


# ── request mapping ────────────────────────────────────────────────────────


def _text(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, default=str, ensure_ascii=False)


def _output_text(outputs: Any) -> str:
    """Tool outputs arrive as an object or as [{name, description, type, value}]."""
    if isinstance(outputs, list):
        return "\n".join(
            f"{o.get('name')}: {_text(o.get('value'))}" if isinstance(o, dict) else _text(o)
            for o in outputs
        )
    return _text(outputs) if outputs is not None else ""


def _event(session_id: str, index: int, **fields: Any) -> Dict[str, Any]:
    meta = fields.pop("metadata", {})
    return {
        "ts": datetime.now(timezone.utc).isoformat(),
        "session_id": session_id,
        "agent": AGENT_ID,
        "agent_event": "PreToolUse",
        # The LLM judge cannot fit Copilot Studio's 1s window. The engine skips
        # the semantic layer for bulk scans; this is the same constraint.
        # ponytail: skips the heuristic pre-screen too; a per-event
        # heuristic-only flag in policy_engine if that recall matters here.
        "_bulk_scan": True,
        **fields,
        "metadata": {"framework": AGENT_ID, "surface": AGENT_ID, "index": index, **meta},
    }


def to_events(body: Any) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """An analyze-tool-execution body -> (events in order, request context)."""
    if not isinstance(body, dict):
        raise CopilotStudioError(400, "request body must be a JSON object")
    tool = body.get("toolDefinition")
    if not isinstance(tool, dict) or not str(tool.get("name") or tool.get("id") or ""):
        raise CopilotStudioError(400, "toolDefinition is required and must name the tool")
    planner = body.get("plannerContext") if isinstance(body.get("plannerContext"), dict) else {}
    meta = body.get("conversationMetadata") if isinstance(body.get("conversationMetadata"), dict) else {}
    agent = meta.get("agent") if isinstance(meta.get("agent"), dict) else {}
    user = meta.get("user") if isinstance(meta.get("user"), dict) else {}
    inputs = body.get("inputValues") if isinstance(body.get("inputValues"), dict) else {}

    # Stateless per request: Copilot Studio re-sends the plan's prior outputs
    # every step, so nothing needs to survive between calls.
    sid = "-".join(str(v) for v in (meta.get("conversationId"), meta.get("planStepId")) if v)
    session_id = f"cs-{sid or time.time_ns()}"
    ctx = {
        "session_id": session_id,
        "tenant_id": str(agent.get("tenantId") or user.get("tenantId") or ""),
        "subject": f"user:{user['id']}" if user.get("id") else None,
        "agent_name": str(agent.get("id") or ""),
        "tool_name": str(tool.get("name") or tool.get("id")),
    }

    events: List[Dict[str, Any]] = []
    # The docs spell it both ways.
    prior = planner.get("previousToolOutputs") or planner.get("previousToolsOutputs") or []
    for out in prior if isinstance(prior, list) else []:
        if not isinstance(out, dict):
            continue
        text = _output_text(out.get("outputs"))
        if text:
            events.append(_event(session_id, len(events), type="tool_result", response=text, metadata={
                "tool_name": str(out.get("toolName") or out.get("toolId") or ""),
                "tool_id": out.get("toolId"), "source": "previous_tool_output"}))

    events.append(_event(
        session_id, len(events),
        # Same shape the MCP path gives a local tool's pre-call: the arguments
        # as JSON text, so secret / injection / data-boundary rules see them.
        type="tool_result", response=_text(inputs),
        metadata={
            "tool_name": ctx["tool_name"], "tool_id": tool.get("id"), "tool_type": tool.get("type"),
            "tool_description": tool.get("description"),
            "args": list(inputs.values()), "kwargs": inputs,
            "user_message": planner.get("userMessage"), "thought": planner.get("thought"),
            "tenant_id": ctx["tenant_id"], "conversation_id": meta.get("conversationId"),
            "plan_id": meta.get("planId"), "plan_step_id": meta.get("planStepId"),
            "agent_id": agent.get("id"), "environment_id": agent.get("environmentId"),
            "trigger": meta.get("trigger"),
        }))
    return events, ctx


def to_response(blocking: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if blocking is None:
        return {"blockAction": False}
    category = str(blocking.get("category") or "")
    return {
        "blockAction": True,
        "reasonCode": REASON_CODES.get(category, REASON_OTHER),
        "reason": str(blocking.get("title") or blocking.get("ruleId") or "blocked by policy"),
        "diagnostics": json.dumps({
            "rule": blocking.get("ruleId"), "severity": blocking.get("severity"),
            "category": category or None,
        }),
    }


def _evaluate(events: List[Dict[str, Any]], ctx: Dict[str, Any], workspace: Path) -> Optional[Dict[str, Any]]:
    from prismor.runtime.policy_engine import InMemoryTaintStore
    from prismor.runtime.principal import resolve_subject
    from prismor.runtime.runtime import evaluate_tool_call

    taint = InMemoryTaintStore()
    subject = resolve_subject(ctx["subject"]) if ctx["subject"] else None
    for event in events:
        decision = evaluate_tool_call(
            event=event, workspace=workspace, agent=AGENT_ID, agent_name=ctx["agent_name"],
            mode="enforce", session_id=ctx["session_id"], subject=subject,
            # A shared server: no per-tenant transcript on disk, no inventory.
            persist=False, register_agent=False, taint_store=taint,
        )
        if decision.blocking is not None:
            return decision.blocking  # deny wins; the first denial is the reason
    # A credential in the arguments is leaving through the connector. The
    # inference-hook channel's DLP check, on the call's arguments only.
    from prismor.runtime.inference_hook import screen_secrets

    call = events[-1]
    found = screen_secrets([{"type": "text", "content": call["response"],
                             "metadata": {"source": ctx["tool_name"]}}])
    if not found:
        return None
    vendor = str(found[0]["title"]).partition("(")[2].rstrip(")") or "unknown key"
    return {**found[0], "ruleId": "copilot-studio-credential-in-arguments",
            "title": f"Credential in tool arguments ({vendor})", "channel": AGENT_ID}


def analyze(body: Any, workspace: Path) -> Dict[str, Any]:
    """Screen one tool execution. Raises CopilotStudioError on a bad request."""
    events, ctx = to_events(body)
    budget = float(os.environ.get("PRISMOR_COPILOT_STUDIO_BUDGET_MS") or 800) / 1000
    t0 = time.perf_counter()
    future = _pool.submit(_evaluate, events, ctx, workspace)
    try:
        return to_response(future.result(timeout=budget))
    except Exception as exc:
        what = "timed out" if isinstance(exc, FutureTimeout) else f"error: {exc}"
        sys.stderr.write(f"[prismor] copilot-studio: evaluation {what} after "
                         f"{int((time.perf_counter() - t0) * 1000)}ms (tenant={ctx['tenant_id'] or '-'})\n")
        if os.environ.get("PRISMOR_COPILOT_STUDIO_FAIL_OPEN") == "1":
            return {"blockAction": False, "diagnostics": json.dumps({"fail": "open", "detail": what})}
        return {"blockAction": True, "reasonCode": REASON_FAIL,
                "reason": f"Prismor could not finish screening this tool call ({what}); blocked fail-closed",
                "diagnostics": json.dumps({"fail": "closed", "detail": what})}


def handle(path: str, headers: Any, body: Any, *, workspace: Path, bound_host: str) -> Tuple[int, Dict[str, Any]]:
    """Route one Copilot Studio request: (HTTP status, JSON body)."""
    try:
        authenticate(headers.get("Authorization") or "", bound_host)
        if path == VALIDATE_PATH:
            return 200, {"isSuccessful": True, "status": "OK"}
        return 200, analyze(body, workspace)
    except CopilotStudioError as exc:
        return exc.http_status, exc.body()
