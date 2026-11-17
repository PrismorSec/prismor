"""False-positive reports and human verdicts, between this device and the console.

The loop: a block names its event id and a review link. The agent may think the
block was wrong; it then runs ``prismor report-fp <event-id> --reason ...``,
which only ASKS (the console stores an ``agent_suspected_fp`` report, never a
label) and hands the user the link. A person labels the event on the console.
``prismor learn --console`` pulls those labels back and the learner uses them:
a confirmed false positive proposes a narrow allowlist entry; a confirmed true
positive pins the rule so it is never proposed for relaxing.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, Optional

from prismor.runtime.enterprise import identity as _identity


def _base(ident: Dict[str, Any]) -> str:
    return str(ident.get("api_base") or _identity.api_base()).rstrip("/")


def review_url(event_id: Optional[str], session_id: Optional[str]) -> Optional[str]:
    """Console link to one event in its session, or None when not enrolled."""
    if not event_id or not session_id:
        return None
    ident = _identity.load_identity()
    if not ident:
        return None
    return (f"{_base(ident)}/admin/sessions/{urllib.parse.quote(str(session_id), safe='')}"
            f"?event={urllib.parse.quote(str(event_id), safe='')}")


def _request(ident: Dict[str, Any], method: str, path: str, body: Optional[Dict[str, Any]] = None,
             timeout: float = 15) -> Dict[str, Any]:
    from prismor.runtime import http_ua as _http_ua
    req = urllib.request.Request(
        f"{_base(ident)}{path}",
        data=json.dumps(body).encode("utf-8") if body is not None else None,
        method=method,
        headers={"Content-Type": "application/json", "User-Agent": _http_ua.user_agent(),
                 "Authorization": f"Bearer {ident.get('device_key')}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # pinned to the enrolled api_base  # nosec B310
            return {"ok": True, **json.loads(resp.read().decode("utf-8"))}
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:300] if exc.fp else ""
        try:
            detail = json.loads(detail).get("message") or detail
        except (ValueError, AttributeError):
            pass
        return {"ok": False, "status": exc.code, "error": detail or str(exc.reason)}
    except (urllib.error.URLError, ValueError, OSError) as exc:
        return {"ok": False, "error": str(exc)}


def report(event_id: str, reason: str) -> Dict[str, Any]:
    """Ask a human to review one of this device's events as a likely false positive."""
    ident = _identity.load_identity()
    if not ident:
        return {"ok": False, "error": "This machine is not enrolled. Run `prismor enroll <token>` first."}
    res = _request(ident, "POST", f"/api/devices/events/{urllib.parse.quote(event_id, safe='')}/report-fp",
                   {"reason": reason})
    if res.get("ok"):
        res["url"] = review_url(event_id, res.get("sessionId"))
    return res


def pull_labels(workspace: Path, max_pages: int = 20) -> Dict[str, Any]:
    """Fetch new human labels on this device's events into the local store."""
    from prismor.runtime import learning
    ident = _identity.load_identity()
    if not ident:
        return {"ok": False, "error": "not enrolled"}
    saved = 0
    for _ in range(max_pages):
        since = learning.console_labels_cursor(workspace)
        q = f"?since={urllib.parse.quote(since)}" if since else ""
        res = _request(ident, "GET", f"/api/devices/labels{q}")
        if not res.get("ok"):
            return {**res, "saved": saved}
        labels = res.get("labels") or []
        saved += learning.save_console_labels(workspace, labels)
        if not res.get("hasMore") or not labels:
            break
    return {"ok": True, "saved": saved}
