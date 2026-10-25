"""Microsoft 365 Copilot activity from the Microsoft 365 audit log.

Copilot Studio agents call Prismor before every tool (copilot_studio.py), but
Microsoft 365 Copilot itself, and the agents people build in its Agent
Builder, give third parties no such hook. What they do leave is an audit
record per interaction (``CopilotInteraction``, RecordType 261) in the
Office 365 Management Activity API. This module pulls those records and
reports each one to the org's sinks as an observed event, so the console sees
who used Copilot, in which app, through which agent, and what it read.

It reports; it cannot block. The records land minutes to hours after the
interaction, and nothing here is on Copilot's path.

Microsoft's own detections ride along as findings:

    Messages[].JailbreakDetected          -> prompt_injection (m365-copilot-jailbreak)
    AccessedResources[].XPIADetected      -> prompt_injection (m365-copilot-xpia)

Setup: an Entra app in the customer's tenant with the Office 365 Management
APIs application permission ``ActivityFeed.Read`` (admin consent), a client
secret, and Purview auditing on. Then:

    PRISMOR_M365_TENANT_ID       tenant id (GUID)
    PRISMOR_M365_CLIENT_ID       the app's client id
    PRISMOR_M365_CLIENT_SECRET   its secret (keep it in `prismor cloak`)

    prismor m365-copilot pull            # loop, every 5 min
    prismor m365-copilot pull --once     # one pass (cron)

Run with the org's ``PRISMOR_AGENT_KEY`` (or on an enrolled device) and the
records land in that org. The read position lives in
``$PRISMOR_HOME/m365-audit-cursor.json``.
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

AGENT_ID = "m365-copilot"
RECORD_TYPE = 261
CONTENT_TYPE = "Audit.General"
MANAGE = "https://manage.office.com"
#: The API keeps content for 7 days and lists at most 24h per request.
_MAX_BACK = timedelta(days=7)
_WINDOW = timedelta(hours=24)
#: Content can become listable a little after its window; re-list this much.
_OVERLAP = timedelta(minutes=30)
_SEEN_MAX = 5000


class AuditError(Exception):
    pass


def settings() -> Dict[str, str]:
    cfg = {k: (os.environ.get(f"PRISMOR_M365_{k.upper()}") or "").strip()
           for k in ("tenant_id", "client_id", "client_secret")}
    missing = [f"PRISMOR_M365_{k.upper()}" for k, v in cfg.items() if not v]
    if missing:
        raise AuditError("set " + ", ".join(missing))
    return cfg


# ── Management Activity API ────────────────────────────────────────────────

def _request(method: str, url: str, token: Optional[str] = None,
             data: Optional[bytes] = None) -> Tuple[Any, Dict[str, str]]:
    req = urllib.request.Request(url, data=data, method=method)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    if data is not None and not token:
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read()
            return (json.loads(body) if body else None), dict(resp.headers)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:500]
        raise AuditError(f"{method} {url.split('?')[0]} -> HTTP {exc.code}: {detail}") from None


def token(cfg: Dict[str, str]) -> str:
    form = urllib.parse.urlencode({
        "client_id": cfg["client_id"], "client_secret": cfg["client_secret"],
        "grant_type": "client_credentials", "scope": f"{MANAGE}/.default",
    }).encode()
    body, _ = _request("POST", f"https://login.microsoftonline.com/{cfg['tenant_id']}/oauth2/v2.0/token",
                       data=form)
    return body["access_token"]


def _feed(cfg: Dict[str, str]) -> str:
    return f"{MANAGE}/api/v1.0/{cfg['tenant_id']}/activity/feed"


def start_subscription(cfg: Dict[str, str], tok: str) -> None:
    """Idempotent: an already-running subscription is fine."""
    try:
        _request("POST", f"{_feed(cfg)}/subscriptions/start?contentType={CONTENT_TYPE}", tok, data=b"")
    except AuditError as exc:
        if "AF20024" not in str(exc):  # "The subscription is already enabled"
            raise


def _fmt(t: datetime) -> str:
    return t.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


def content_blobs(cfg: Dict[str, str], tok: str, start: datetime, end: datetime) -> Iterator[Dict[str, Any]]:
    """Every content blob that became available in [start, end)."""
    while start < end:
        stop = min(start + _WINDOW, end)
        url: Optional[str] = (f"{_feed(cfg)}/subscriptions/content?contentType={CONTENT_TYPE}"
                              f"&startTime={_fmt(start)}&endTime={_fmt(stop)}")
        while url:
            body, headers = _request("GET", url, tok)
            yield from body or []
            url = headers.get("NextPageUri") or headers.get("nextpageuri")
        start = stop


# ── record -> Prismor event ────────────────────────────────────────────────

def _flag(value: Any) -> bool:
    return value is True or str(value).lower() == "true"


def _dicts(value: Any) -> List[Dict[str, Any]]:
    return [v for v in value if isinstance(v, dict)] if isinstance(value, list) else []


def is_copilot(rec: Any) -> bool:
    return isinstance(rec, dict) and (rec.get("RecordType") == RECORD_TYPE
                                      or rec.get("Operation") == "CopilotInteraction")


def to_report(rec: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any], List[Dict[str, Any]]]:
    """A CopilotInteraction record -> (event, context, findings)."""
    data = rec.get("CopilotEventData") if isinstance(rec.get("CopilotEventData"), dict) else {}
    host = str(data.get("AppHost") or "Copilot")
    agent = str(data.get("AgentName") or rec.get("AgentName") or "")
    resources = _dicts(data.get("AccessedResources"))
    messages = _dicts(data.get("Messages"))
    plugins = [str(p.get("Id")) for p in _dicts(data.get("AISystemPlugin")) if p.get("Id")]
    thread = str(data.get("ThreadId") or rec.get("Id") or time.time_ns())

    event = {
        "type": "prompt",
        "session_id": f"m365-{thread}",
        "agent": AGENT_ID,
        # When it happened, not when we read it: records arrive hours late.
        "occurred_at": rec.get("CreationTime") and f"{str(rec['CreationTime']).rstrip('Z')}Z",
        "metadata": {
            "framework": AGENT_ID, "surface": AGENT_ID, "source": "m365_audit",
            "tool_name": host, "app_host": host,
            "agent_id": data.get("AgentId") or rec.get("AgentId"), "agent_name": agent or None,
            "audit_id": rec.get("Id"), "tenant_id": rec.get("OrganizationId"),
            "plugins": plugins, "web_search": "BingWebSearch" in plugins,
            "resource_count": len(resources),
            "labelled_resources": sum(1 for r in resources if r.get("SensitivityLabelId")),
            "resource_types": sorted({str(r.get("Type")) for r in resources if r.get("Type")}),
            "models": [m.get("ModelName") for m in _dicts(data.get("ModelTransparencyDetails"))
                       if m.get("ModelName")],
        },
    }
    ctx = {
        "session_id": event["session_id"],
        "subject": f"user:{rec['UserId']}" if rec.get("UserId") else None,
        "agent_name": agent or f"Microsoft 365 Copilot ({host})",
    }
    findings: List[Dict[str, Any]] = []
    if any(_flag(m.get("JailbreakDetected")) for m in messages):
        findings.append({"ruleId": "m365-copilot-jailbreak", "category": "prompt_injection",
                         "severity": "HIGH", "action": "warn", "mode": "observe",
                         "title": "Microsoft flagged a jailbreak attempt in a Copilot prompt"})
    if any(_flag(r.get("XPIADetected")) for r in resources):
        findings.append({"ruleId": "m365-copilot-xpia", "category": "prompt_injection",
                         "severity": "HIGH", "action": "warn", "mode": "observe",
                         "title": "Microsoft flagged a prompt injection in content Copilot read"})
    if not findings:
        findings.append({"ruleId": "m365-copilot-interaction", "category": "audit",
                         "severity": "info", "action": "allow",
                         "title": f"Microsoft 365 Copilot interaction ({host})"})
    return event, ctx, findings


# ── cursor + pull ──────────────────────────────────────────────────────────

def _cursor_path() -> Path:
    return Path(os.environ.get("PRISMOR_HOME", str(Path.home() / ".prismor"))) / "m365-audit-cursor.json"


def _load_cursor() -> Dict[str, Any]:
    try:
        return json.loads(_cursor_path().read_text())
    except (OSError, ValueError):
        return {}


def _save_cursor(cur: Dict[str, Any]) -> None:
    path = _cursor_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(cur))
    tmp.replace(path)


def _report(event: Dict[str, Any], ctx: Dict[str, Any], findings: List[Dict[str, Any]],
            workspace: Path) -> None:
    from prismor.runtime.policy_engine import PolicyEngine
    from prismor.runtime.principal import resolve_subject
    from prismor.runtime.runtime import _dispatch_telemetry

    _dispatch_telemetry(
        engine=PolicyEngine(workspace=workspace), findings=findings, event=event,
        workspace=workspace, agent=AGENT_ID, agent_name=ctx["agent_name"], mode="observe",
        session_id=ctx["session_id"], subject=resolve_subject(ctx["subject"]),
    )


def pull(workspace: Path, since_hours: Optional[float] = None, record: bool = True,
         now: Optional[datetime] = None) -> Dict[str, int]:
    """One pass: list new content, report its Copilot records, advance the
    cursor. Returns counts."""
    cfg = settings()
    tok = token(cfg)
    start_subscription(cfg, tok)
    now = now or datetime.now(timezone.utc)
    cur = _load_cursor()
    if since_hours is not None:
        start = now - timedelta(hours=since_hours)
    elif cur.get("end"):
        start = datetime.fromisoformat(cur["end"]) - _OVERLAP
    else:
        start = now - timedelta(hours=24)
    start = max(start, now - _MAX_BACK + timedelta(minutes=5))
    seen = list(cur.get("seen") or [])
    seen_set = set(seen)
    counts = {"blobs": 0, "records": 0, "copilot": 0, "flagged": 0}
    for blob in content_blobs(cfg, tok, start, now):
        cid = str(blob.get("contentId") or blob.get("contentUri"))
        if cid in seen_set:
            continue
        records, _ = _request("GET", blob["contentUri"], tok)
        counts["blobs"] += 1
        for rec in records or []:
            counts["records"] += 1
            if not is_copilot(rec):
                continue
            counts["copilot"] += 1
            event, ctx, findings = to_report(rec)
            counts["flagged"] += any(f["category"] != "audit" for f in findings)
            if record:
                try:
                    _report(event, ctx, findings, workspace)
                except Exception as exc:  # one bad record must not stall the feed
                    sys.stderr.write(f"[prismor] m365-copilot: report failed: {exc}\n")
        seen.append(cid)
        seen_set.add(cid)
    _save_cursor({"end": now.isoformat(), "seen": seen[-_SEEN_MAX:]})
    return counts
