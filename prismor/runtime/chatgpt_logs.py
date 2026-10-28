"""`prismor chatgpt-logs sync`: screen ChatGPT conversations after the fact.

ChatGPT chat runs on OpenAI's servers, so no local hook sees it. On ChatGPT
Enterprise and Edu, OpenAI's Compliance Logs Platform publishes every message
as JSON Lines files. This pulls the CONVERSATION_MESSAGE files, screens each
message with the same engine the hooks use (user text as a prompt, model text
as untrusted content, the way the inference hook does), and reports through
the usual telemetry sinks, so conversations show up in the console under the
`chatgpt` agent with the sender as the subject. Nothing can be blocked: the
message was sent before the log existed.

The compliance key reads every conversation in the workspace, which is why
this runs on the customer's machine rather than in the console.

API (https://developers.openai.com/cookbook/examples/chatgpt/compliance_api/logs_platform):
  GET {base}/{workspaces|organizations}/{id}/logs?event_type=&after=&limit=
      -> {data: [{id, ...}], has_more, last_end_time}, oldest first
  GET {base}/{scope}/{id}/logs/{log_id} -> 307 to a signed URL serving JSONL
Re-querying with the same `after` returns the boundary file again, so the id
of the last file read is kept alongside the cursor and skipped.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional

AGENT_ID = "chatgpt"
EVENT_TYPE = "CONVERSATION_MESSAGE"
DEFAULT_BASE = "https://api.chatgpt.com/v1/compliance"
KEY_ENV = "OPENAI_COMPLIANCE_API_KEY"
MAX_TEXT = 200_000


class ApiError(RuntimeError):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):  # surface the 307 instead of following it
        return None


_opener = urllib.request.build_opener(_NoRedirect)


def _get(url: str, headers: Dict[str, str], timeout: float = 60) -> bytes:
    req = urllib.request.Request(url, headers=headers)
    try:
        with _opener.open(req, timeout=timeout) as resp:
            return resp.read()
    except urllib.error.HTTPError as exc:
        if exc.code in (301, 302, 303, 307, 308) and exc.headers.get("Location"):
            # The signed URL carries its own authorization. Never forward the
            # compliance key to whatever host the redirect names.
            loc = urllib.parse.urljoin(url, exc.headers["Location"])
            if urllib.parse.urlsplit(loc).scheme not in ("https", "http"):
                raise ApiError(f"refusing to follow a redirect to {loc.split('?')[0]}")
            req = urllib.request.Request(loc, headers={"User-Agent": _ua()})
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310 - scheme checked above
                return resp.read()
        body = exc.read()[:300].decode("utf-8", "replace")
        raise ApiError(f"HTTP {exc.code} from {url.split('?')[0]}: {body}") from None


class Client:
    def __init__(self, key: str, principal_id: str, base: str = DEFAULT_BASE,
                 fetch: Callable[[str, Dict[str, str]], bytes] = _get):
        scope = "organizations" if principal_id.startswith("org-") else "workspaces"
        self.root = f"{base.rstrip('/')}/{scope}/{urllib.parse.quote(principal_id)}/logs"
        self.headers = {"Authorization": f"Bearer {key}", "User-Agent": _ua()}
        self.fetch = fetch

    def list(self, after: str, limit: int = 100) -> Dict[str, Any]:
        q = urllib.parse.urlencode({"event_type": EVENT_TYPE, "after": after, "limit": limit})
        return json.loads(self.fetch(f"{self.root}?{q}", self.headers))

    def download(self, log_id: str) -> bytes:
        return self.fetch(f"{self.root}/{urllib.parse.quote(log_id)}", self.headers)


def _ua() -> str:
    try:
        from prismor.runtime.http_ua import user_agent
        return user_agent()
    except Exception:
        return "prismor"


# ── cursor ───────────────────────────────────────────────────────────────────

def state_path(principal_id: str) -> Path:
    from prismor.runtime.store import prismor_home
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in principal_id)
    return prismor_home() / "chatgpt-logs" / f"{safe}.json"


def load_state(principal_id: str) -> Dict[str, Any]:
    try:
        return json.loads(state_path(principal_id).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save_state(principal_id: str, state: Dict[str, Any]) -> None:
    p = state_path(principal_id)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(state), encoding="utf-8")
    os.replace(tmp, p)


def iter_files(client: Client, state: Dict[str, Any], since: str) -> Iterator[tuple]:
    """Yield (log_id, jsonl bytes) oldest first, advancing ``state`` as each
    file is handed over, so a crash re-reads at most one file."""
    while True:
        after = state.get("last_end_time") or since
        page = client.list(after)
        files = [f for f in page.get("data") or [] if f.get("id") != state.get("last_file_id")]
        for f in files:
            yield f["id"], client.download(f["id"])
            state["last_file_id"] = f["id"]
        if page.get("last_end_time"):
            state["last_end_time"] = page["last_end_time"]
        if not files or not page.get("has_more"):
            return


# ── records → canonical events ──────────────────────────────────────────────

def _text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, dict):
        for k in ("value", "text", "parts"):
            v = content.get(k)
            if isinstance(v, str):
                return v
            if isinstance(v, list):
                return "\n".join(_text(x) for x in v)
    if isinstance(content, list):
        return "\n".join(_text(x) for x in content)
    return ""


def to_event(rec: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """One CONVERSATION_MESSAGE record as a canonical event, or None when it
    carries no text. User text is a prompt; anything the model or a tool wrote
    is screened as untrusted content (type tool_result), as in inference_hook."""
    if rec.get("type") != EVENT_TYPE:
        return None
    msg = rec.get("message") or {}
    text = _text(msg.get("content")).strip()[:MAX_TEXT]
    if not text:
        return None
    author = msg.get("author") or {}
    conv = rec.get("conversation") or {}
    role = str(author.get("type") or "user")
    meta = {
        "framework": AGENT_ID,
        "channel": "chatgpt_compliance_logs",
        "source": role,
        "message_id": msg.get("id"),
        "conversation_title": conv.get("title"),
        "client_type": author.get("client_type"),
        "model": author.get("model"),
        "tools_used": author.get("tools_used"),
        "temporary_chat": conv.get("is_temporary_chat"),
    }
    event: Dict[str, Any] = {
        "ts": datetime.now(timezone.utc).isoformat(),
        # When the message was sent; telemetry reports this instead of now.
        "occurred_at": msg.get("created_at") or rec.get("timestamp"),
        "session_id": str(conv.get("id") or rec.get("event_id") or ""),
        "agent": AGENT_ID,
        "metadata": {k: v for k, v in meta.items() if v not in (None, "", [])},
    }
    if role == "user":
        return {**event, "agent_event": "UserPromptSubmit", "type": "prompt", "prompt": text}
    return {**event, "agent_event": "PreToolUse", "type": "tool_result", "content": text}


def subject_of(rec: Dict[str, Any]):
    from prismor.runtime.principal import Subject
    actor = rec.get("actor") or {}
    user = actor.get("user_email") or actor.get("user_id")
    org = (rec.get("principal") or {}).get("id")
    return Subject(user_id=user, org_id=org, source="chatgpt") if user else Subject(source="chatgpt")


# ── sync ─────────────────────────────────────────────────────────────────────

def _mask_secrets(event: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Find pasted credentials (the inference hook's DLP pass, which the
    engine leaves to the hook layer) and mask them in ``event`` in place, so
    no live secret reaches a finding, a sink or the console."""
    from prismor.runtime.inference_hook import screen_secrets
    findings = screen_secrets([event])
    if findings:
        from prismor.runtime.data_boundary import classify, mask
        field = "prompt" if event["type"] == "prompt" else "content"
        for m in classify(event[field], context="prompt"):
            if m.kind == "secret":
                event[field] = event[field].replace(m.value, mask(m.value))
        for f in findings:
            f["channel"] = "chatgpt_compliance_logs"
    return findings


_engines: Dict[str, Any] = {}


def screen(rec: Dict[str, Any], workspace: Path) -> List[Dict[str, Any]]:
    from prismor.runtime.policy_engine import PolicyEngine
    from prismor.runtime.runtime import _dispatch_telemetry, evaluate_tool_call
    event = to_event(rec)
    if event is None:
        return []
    secrets = _mask_secrets(event)
    subject = subject_of(rec)
    decision = evaluate_tool_call(
        event=event, workspace=workspace, agent=AGENT_ID, agent_name=AGENT_ID,
        mode="observe", session_id=event["session_id"], subject=subject,
        # Reported once, below, together with the secret findings. The
        # conversation lives with OpenAI, so nothing goes to this machine's store.
        record=False, persist=False, register_agent=False, flush_at_exit=False,
    )
    # The message was sent before the log existed: every finding is observed,
    # whatever an enrolled device's enforce mode would make of it.
    findings = [dict(f, mode="observe") for f in secrets + list(decision.findings)]
    engine = _engines.get(str(workspace)) or _engines.setdefault(str(workspace), PolicyEngine(workspace=workspace))
    _dispatch_telemetry(engine=engine, findings=findings, event=event, workspace=workspace,
                        agent=AGENT_ID, mode="observe", session_id=event["session_id"],
                        subject=subject, eval_ms=None)
    return findings


def sync(client: Client, principal_id: str, workspace: Path, *, since: str,
         out=sys.stdout) -> Dict[str, int]:
    state = load_state(principal_id)
    counts = {"files": 0, "messages": 0, "findings": 0}
    try:
        for log_id, body in iter_files(client, state, since):
            for line in body.decode("utf-8", "replace").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                findings = screen(rec, workspace)
                counts["messages"] += rec.get("type") == EVENT_TYPE
                counts["findings"] += len(findings)
                for f in findings:
                    who = (rec.get("actor") or {}).get("user_email") or "?"
                    print(f"  {str(f.get('severity', '?')).lower():<8} {f.get('ruleId')}  {who}  "
                          f"conversation {(rec.get('conversation') or {}).get('id')}", file=out)
            counts["files"] += 1
            save_state(principal_id, state)
    finally:
        save_state(principal_id, state)
        try:
            from prismor.runtime.enterprise import heartbeat
            heartbeat.flush_at_exit()
        except Exception:
            pass
    return counts


def default_since(hours: float) -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")


def cmd_sync(principal_id: str, workspace: Optional[str], since_hours: float, base: str) -> int:
    key = os.environ.get(KEY_ENV, "").strip()
    if not key:
        print(f"[prismor] set {KEY_ENV} to the ChatGPT Enterprise Compliance API key "
              "(Enterprise and Edu workspaces only).", file=sys.stderr)
        return 2
    ws = Path(workspace).resolve() if workspace else Path.cwd()
    try:
        counts = sync(Client(key, principal_id, base), principal_id, ws, since=default_since(since_hours))
    except (ApiError, urllib.error.URLError, OSError, ValueError) as exc:
        print(f"[prismor] chatgpt-logs: {exc}", file=sys.stderr)
        return 1
    print(f"[prismor] chatgpt-logs: {counts['files']} file(s), {counts['messages']} message(s), "
          f"{counts['findings']} finding(s)")
    return 0
