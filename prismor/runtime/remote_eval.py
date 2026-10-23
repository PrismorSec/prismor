"""Hosted evaluation: ask a Prismor-run eval-server instead of the local engine.

When ``PRISMOR_EVAL_URL`` is set, :func:`prismor.runtime.runtime.evaluate_tool_call`
posts the canonical event it already built to ``{url}/v1/evaluate`` and returns
the server's verdict as the same :class:`Decision`. Every Python adapter funnels
through that one function, so all of them gain hosted mode with no change.

The hosted server records the call and reports it to the org (it holds the
org's agent key), so the client writes nothing locally: no session store, no
telemetry, no heartbeat. A call is recorded once, on the server.

Failure semantics match the TypeScript adapter: if the server cannot be reached
or answers with an error, ``enforce`` fails closed (the call is refused with a
reason naming the hosted endpoint) and ``observe`` fails open.

Environment:
    PRISMOR_EVAL_URL       base URL of the hosted eval-server (unset = local engine)
    PRISMOR_EVAL_KEY       bearer token the server was started with
    PRISMOR_EVAL_TIMEOUT   seconds per request (default 5)
"""
from __future__ import annotations

import json
import os
import sys
import threading
import urllib.error
import urllib.request
from typing import Any, Dict, Optional

from prismor.runtime.contract import COMBINED_FIELDS, TEXT_TYPES, TYPE_FIELD, Decision
from prismor.runtime.principal import Subject

# A server evaluates locally even if PRISMOR_EVAL_URL leaks into its
# environment, so it can never forward to itself. SERVING covers a whole
# process (eval-server, Lambda); _thread marks one request thread, which also
# covers a server embedded in a process that is itself a client.
SERVING = False
_thread = threading.local()


def serving_this_thread() -> None:
    _thread.serving = True


def remote_url() -> Optional[str]:
    if SERVING or getattr(_thread, "serving", False):
        return None
    url = (os.environ.get("PRISMOR_EVAL_URL") or "").strip().rstrip("/")
    return url or None


def _subject_string(subject: Optional[Subject]) -> Optional[str]:
    if subject is None or not subject.is_identified:
        return None
    parts = [f"user={subject.user_id}"]
    if subject.team_id:
        parts.append(f"team={subject.team_id}")
    if subject.org_id:
        parts.append(f"org={subject.org_id}")
    return ";".join(parts)


def _canonical(event: Dict[str, Any]) -> Dict[str, Any]:
    """The server validates posted events strictly. Move a text value to its
    type's preferred field (some adapters write `content` for a prompt) and make
    the value a string, so a valid call is never refused for its shape."""
    etype = event.get("type")
    field = TYPE_FIELD.get(str(etype))
    if field:
        if etype in TEXT_TYPES and not event.get(field):
            for alt in COMBINED_FIELDS:
                if isinstance(event.get(alt), str) and event[alt]:
                    event[field] = event[alt]
                    break
        if field in event and not isinstance(event[field], str):
            event[field] = "" if event[field] is None else str(event[field])
    return event


def _unavailable(mode: str, url: str, why: str, subject: Optional[Subject]) -> Decision:
    reason = f"hosted evaluation unavailable ({url}): {why}"
    if mode == "observe":
        sys.stderr.write(f"[prismor] {reason}; observe mode, call allowed\n")
        return Decision(allow=True, subject=subject, reason=reason)
    finding = {
        "ruleId": "hosted-eval-unavailable",
        "category": "agent-control",
        "severity": "HIGH",
        "action": "block",
        "mode": "enforce",
        "title": f"Prismor could not reach hosted evaluation: {why}",
    }
    return Decision(allow=False, findings=[finding], blocking=finding,
                    reason=f"[HIGH] {reason}; enforce mode fails closed", subject=subject)


def evaluate_remote(
    url: str,
    *,
    event: Dict[str, Any],
    agent: str,
    agent_name: str,
    mode: str,
    session_id: str,
    subject: Optional[Subject],
    identity_token: Optional[str],
    explain: bool,
) -> Decision:
    body: Dict[str, Any] = {
        "event": _canonical(event), "agent": agent, "agent_name": agent_name,
        "mode": mode, "session_id": session_id, "explain": explain,
    }
    sub = _subject_string(subject)
    if sub:
        body["subject"] = sub
    from prismor.runtime.http_ua import user_agent
    headers = {"Content-Type": "application/json", "User-Agent": user_agent()}
    key = os.environ.get("PRISMOR_EVAL_KEY")
    if key:
        headers["Authorization"] = f"Bearer {key}"
    if identity_token:
        headers["X-Prismor-Identity"] = f"Bearer {identity_token}"
    try:
        timeout = float(os.environ.get("PRISMOR_EVAL_TIMEOUT") or 5)
    except ValueError:
        timeout = 5.0
    req = urllib.request.Request(f"{url}/v1/evaluate", method="POST", headers=headers,
                                 data=json.dumps(body, default=str).encode("utf-8"))
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310  # nosec B310 - operator-set URL
            data = json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as exc:
        return _unavailable(mode, url, f"HTTP {exc.code}", subject)
    except Exception as exc:
        return _unavailable(mode, url, type(exc).__name__, subject)
    if not isinstance(data, dict) or "allow" not in data:
        return _unavailable(mode, url, "malformed response", subject)
    return Decision(
        allow=bool(data["allow"]),
        findings=list(data.get("findings") or []),
        blocking=data.get("blocking"),
        reason=data.get("reason"),
        subject=subject,
        explain=data.get("explain"),
    )
