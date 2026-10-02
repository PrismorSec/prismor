"""OpenID AuthZEN Authorization API 1.0 on the eval-server.

Gateways and SaaS that speak AuthZEN can ask Prismor for a decision without a
Prismor adapter. A request maps onto one tool call:

    action.name         -> the tool              action.properties -> its arguments
    resource.type/id    -> resource.kind/id      resource.properties -> resource.attr
    subject.type/id     -> the asserted user ("user:<id>")
    context             -> event_type, agent_name, session_id, explain (all optional)

``subject.properties`` is deliberately NOT read as principal attributes: a
caller asserting its own roles is exactly what verified identity exists to
prevent. Roles come from the user's token in ``X-Prismor-Identity``, as on
/v1/evaluate.

Endpoints: POST /access/v1/evaluation, POST /access/v1/evaluations (with
evaluations_semantic), GET /.well-known/authzen-configuration.
"""
from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional, Tuple

SEMANTICS = ("execute_all", "deny_on_first_deny", "permit_on_first_permit")
EVALUATION_PATH = "/access/v1/evaluation"
EVALUATIONS_PATH = "/access/v1/evaluations"
METADATA_PATH = "/.well-known/authzen-configuration"


class AuthZenError(ValueError):
    """A malformed request (HTTP 400)."""


def _obj(req: Dict[str, Any], key: str, *required: str) -> Dict[str, Any]:
    value = req.get(key)
    if not isinstance(value, dict):
        raise AuthZenError(f"'{key}' is required and must be an object")
    for field in required:
        if not isinstance(value.get(field), str) or not value[field]:
            raise AuthZenError(f"'{key}.{field}' is required and must be a non-empty string")
    props = value.get("properties", {})
    if props is not None and not isinstance(props, dict):
        raise AuthZenError(f"'{key}.properties' must be an object")
    return value


def to_call(req: Dict[str, Any]) -> Dict[str, Any]:
    """One AuthZEN evaluation -> the arguments for a Prismor tool-call check."""
    subject = _obj(req, "subject", "type", "id")
    resource = _obj(req, "resource", "type", "id")
    action = _obj(req, "action", "name")
    context = req.get("context") or {}
    if not isinstance(context, dict):
        raise AuthZenError("'context' must be an object")
    return {
        "tool_name": action["name"],
        "arguments": action.get("properties") or {},
        "subject": f"{subject['type']}:{subject['id']}",
        "resource": {"kind": resource["type"], "id": resource["id"],
                     "attr": resource.get("properties") or {}},
        "event_type": str(context.get("event_type") or "shell"),
        "agent_name": str(context.get("agent_name") or ""),
        "session_id": str(context.get("session_id") or ""),
        "explain": bool(context.get("explain")),
    }


def to_response(decision: Dict[str, Any]) -> Dict[str, Any]:
    """A Prismor Decision (wire form) -> an AuthZEN evaluation response."""
    ctx: Dict[str, Any] = {"verdict": decision.get("verdict")}
    if decision.get("rule_id"):
        ctx["rule_id"] = decision["rule_id"]
    if decision.get("reason"):
        ctx["reason"] = decision["reason"]
    if decision.get("subject"):
        ctx["subject"] = decision["subject"]
    if "explain" in decision:
        ctx["explain"] = decision["explain"]
    return {"decision": bool(decision.get("allow")), "context": ctx}


def evaluate_one(req: Dict[str, Any], decide: Callable[[Dict[str, Any]], Dict[str, Any]]) -> Dict[str, Any]:
    return to_response(decide(to_call(req)))


def evaluate_batch(body: Dict[str, Any], decide: Callable[[Dict[str, Any]], Dict[str, Any]]) -> Dict[str, Any]:
    items = body.get("evaluations")
    if not isinstance(items, list) or not items:
        raise AuthZenError("'evaluations' is required and must be a non-empty array")
    semantic = str((body.get("options") or {}).get("evaluations_semantic") or "execute_all")
    if semantic not in SEMANTICS:
        raise AuthZenError(f"options.evaluations_semantic must be one of {', '.join(SEMANTICS)}")
    defaults = {k: body[k] for k in ("subject", "resource", "action", "context") if k in body}
    results: List[Dict[str, Any]] = []
    for i, item in enumerate(items):
        if not isinstance(item, dict):
            raise AuthZenError(f"evaluations[{i}] must be an object")
        try:
            res = evaluate_one({**defaults, **item}, decide)
        except AuthZenError as exc:
            if semantic == "execute_all":
                raise AuthZenError(f"evaluations[{i}]: {exc}") from None
            # Short-circuiting semantics treat an error as a deny and stop.
            res = {"decision": False, "context": {"error": f"evaluations[{i}]: {exc}"}}
        results.append(res)
        if semantic == "deny_on_first_deny" and not res["decision"]:
            break
        if semantic == "permit_on_first_permit" and res["decision"]:
            break
    return {"evaluations": results}


def metadata(base_url: str) -> Dict[str, Any]:
    base = base_url.rstrip("/")
    return {
        "policy_decision_point": base,
        "access_evaluation_endpoint": base + EVALUATION_PATH,
        "access_evaluations_endpoint": base + EVALUATIONS_PATH,
    }
