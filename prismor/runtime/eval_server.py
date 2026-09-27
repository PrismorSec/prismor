"""prismor/runtime/eval_server.py — HTTP evaluation endpoint for non-Python adapters.

Exposes the Prismor policy pipeline as a local HTTP service so TypeScript,
Go, or any other language can call evaluate_tool_call without embedding the
Python runtime.

Usage:
    immunity eval-server [--port 7071] [--host 127.0.0.1] [--workspace .]

Endpoints:
    POST /v1/evaluate   → evaluate a tool call, return allow/block decision
    POST /v1/redact     → {"result": <any JSON>} → the same value with cloaked
                          secrets / data-boundary values masked, + "redacted"
    GET  /health        → {"status": "ok", "ts": "<iso>"}

Request body (POST /v1/evaluate):
    {
      "tool_name":  "run_shell",        # required
      "arguments":  {"command": "..."},  # required — tool arguments as object
      "event_type": "shell",             # optional, default "shell"
      "agent":      "vercel-ai",         # optional, default "sdk"
      "mode":       "enforce",           # optional, default "enforce"
      "session_id": "req-abc123",        # optional
      "subject":    "user:alice",        # optional — user:<id> or user=x;team=y
      "agent_name": "support-bot",       # optional — per-instance name (enables kill-switch + control)
      "workspace":  "/path/to/project"   # optional, overrides server default
    }

    X-Prismor-Agent-Name header also accepted (takes precedence over body field).

Response:
    {
      "allow":    false,
      "reason":   "[HIGH] destructive-command matched ...",
      "findings": [...],
      "subject":  {"user_id": "alice", "team_id": null, ...}
    }

Non-2xx on server errors only. Policy denials are always 200 with allow=false.
"""
from __future__ import annotations

import hmac
import json
import os
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from socketserver import ThreadingMixIn
from typing import Any, Optional

from prismor.runtime.principal import resolve_subject
from prismor.runtime.runtime import evaluate_tool_call

#: Canonical value field per event type — imported rather than restated, so an
#: SDK adapter posting here produces the same event a hook would.
#:
#: This previously mapped prompt/tool_result to "content" while every other
#: surface wrote "prompt"/"response". Category rules were unaffected (the
#: engine folds all five text fields into one blob) but a rule scoped to
#: `fields: [response]` silently never matched an event that arrived this way.
from prismor.runtime.contract import TYPE_FIELD as _TYPE_FIELD


def _build_event(
    *,
    tool_name: str,
    arguments: dict,
    event_type: str,
    agent: str,
    session_id: str,
    subject_str: Optional[str],
    available_tools: Optional[list[str]] = None,
) -> dict:
    field = _TYPE_FIELD.get(event_type, "command")
    # Serialize arguments to a single value string (values only — for regex matching)
    value = " ".join(str(v) for v in arguments.values() if v is not None).strip()
    return {
        "ts": datetime.now(timezone.utc).isoformat(),
        "session_id": session_id,
        "agent": agent,
        "agent_event": "PreToolUse",
        "type": event_type,
        field: value,
        "metadata": {
            "tool_name": tool_name,
            "framework": agent,
            "args": list(arguments.values()),
            "kwargs": arguments,
            "subject": subject_str,
            "available_tools": available_tools or [],
            "surface": "eval-server",
        },
    }


class _ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


class EvalHandler(BaseHTTPRequestHandler):
    workspace: Path = Path.cwd()
    # When set, /v1/evaluate requires `Authorization: Bearer <api_key>` — the
    # hosted/exposed mode. /health stays open (liveness probes). Compared
    # constant-time. None (default) preserves the open localhost behavior.
    api_key: Optional[str] = None

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        pass  # silence per-request logs; server startup message is printed separately

    def _send_json(self, data: Any, status: int = 200) -> None:
        body = json.dumps(data, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Prismor-Subject, X-Warden-Subject")
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/health":
            self._send_json({"status": "ok", "ts": datetime.now(timezone.utc).isoformat()})
        elif self.path == "/v1/contract":
            # Self-describing, so a non-Python caller can discover the event
            # shape and verdict vocabulary from the server it is already
            # talking to rather than tracking a doc that may drift from it.
            from prismor.runtime import contract as _contract
            self._send_json({
                "contract_version": _contract.CONTRACT_VERSION,
                "event_types": {t: _contract.TYPE_FIELD[t] for t in _contract.EVENT_TYPES},
                "verdicts": list(_contract.VERDICTS),
                "verdict_rank": _contract.VERDICT_RANK,
                "pre_action_events": list(_contract.PRE_ACTION_EVENTS),
                "surfaces": [
                    {"id": s.id, "title": s.title, "kind": s.kind,
                     "can_refuse": s.can_refuse, "can_rewrite": s.can_rewrite,
                     "can_redact": s.can_redact}
                    for s in _contract.SURFACES
                ],
            })
        else:
            self._send_json({"error": "not found"}, 404)

    def do_POST(self) -> None:  # noqa: N802
        if self.path not in ("/v1/evaluate", "/v1/redact"):
            self._send_json({"error": "not found"}, 404)
            return

        if self.api_key:
            auth = self.headers.get("Authorization", "")
            presented = auth[7:] if auth.startswith("Bearer ") else ""
            if not presented or not hmac.compare_digest(presented, self.api_key):
                self._send_json({"error": "unauthorized: missing or invalid API key"}, 401)
                return

        length = int(self.headers.get("Content-Length", 0))
        try:
            body = json.loads(self.rfile.read(length))
        except Exception as exc:
            self._send_json({"error": f"invalid JSON: {exc}"}, 400)
            return

        if self.path == "/v1/redact":
            # Result-side masking for adapters that cannot import Python (the
            # TypeScript one): the same redact_tool_result the in-process
            # adapters run on a tool's return value before the model sees it.
            from prismor.runtime.redaction import redact_payload_values
            ws_str = body.get("workspace")
            try:
                result, changed = redact_payload_values(
                    body.get("result"), workspace=Path(ws_str) if ws_str else self.workspace)
            except Exception as exc:
                self._send_json({"error": f"redaction error: {exc}"}, 500)
                return
            self._send_json({"result": result, "redacted": changed})
            return

        # A caller that has already normalized (an external proxy shaping MCP
        # JSON-RPC, a test asserting one event across surfaces) may post the
        # canonical event directly. The tool_name+arguments form below is
        # lossy by design — it joins every argument value into one string —
        # which is fine for regex matching but wrong when a field must stay
        # addressable (a file_write's path vs its content).
        raw_event = body.get("event")
        if isinstance(raw_event, dict):
            self._evaluate_raw_event(body, raw_event)
            return

        tool_name = body.get("tool_name")
        if not tool_name:
            self._send_json(
                {"error": "tool_name is required (or post a canonical 'event')"}, 400)
            return

        arguments: dict = body.get("arguments", {})
        event_type: str = body.get("event_type", "shell")
        agent: str = body.get("agent", "sdk")
        mode: str = body.get("mode", "enforce")
        session_id: str = body.get("session_id", f"eval-{os.getpid()}")
        # Agent name: prefer X-Prismor-Agent-Name header, then body field.
        # X-Warden-Agent-Name is accepted for backward compatibility with
        # clients built before the Prismor rename.
        agent_name: str = (
            self.headers.get("X-Prismor-Agent-Name")
            or self.headers.get("X-Warden-Agent-Name")
            or body.get("agent_name", "")
        )

        # Subject: prefer X-Prismor-Subject header, then body field
        # (X-Warden-Subject accepted for backward compatibility).
        subject_str: Optional[str] = (
            self.headers.get("X-Prismor-Subject")
            or self.headers.get("X-Warden-Subject")
            or body.get("subject")
        )
        subject = resolve_subject(subject_str)

        # Workspace: prefer body field, then server default
        ws_str: Optional[str] = body.get("workspace")
        workspace = Path(ws_str) if ws_str else self.workspace

        event = _build_event(
            tool_name=tool_name,
            arguments=arguments,
            event_type=event_type,
            agent=agent,
            session_id=session_id,
            subject_str=subject_str,
            available_tools=[str(t) for t in body.get("available_tools", []) if t][:200]
            if isinstance(body.get("available_tools"), list) else [],
        )

        try:
            decision = evaluate_tool_call(
                event=event,
                workspace=workspace,
                agent=agent,
                agent_name=agent_name,
                mode=mode,
                session_id=session_id,
                subject=subject,
            )
        except Exception as exc:
            self._send_json({"error": f"evaluation error: {exc}"}, 500)
            return

        self._send_json(decision.as_dict())

    def _evaluate_raw_event(self, body: dict, event: dict) -> None:
        """Evaluate a pre-normalized canonical event (contract.py shape)."""
        from prismor.runtime.contract import validate_event

        problems = validate_event(event)
        if problems:
            self._send_json({"error": "invalid event", "problems": problems}, 400)
            return

        agent = str(body.get("agent") or event.get("agent") or "sdk")
        session_id = str(
            body.get("session_id") or event.get("session_id") or f"eval-{os.getpid()}")
        subject_str = (
            self.headers.get("X-Prismor-Subject")
            or self.headers.get("X-Warden-Subject")
            or body.get("subject")
        )
        ws_str = body.get("workspace")
        event.setdefault("session_id", session_id)
        event.setdefault("agent", agent)
        event.setdefault("agent_event", "PreToolUse")
        event.setdefault("metadata", {}).setdefault("surface", "eval-server")
        try:
            decision = evaluate_tool_call(
                event=event,
                workspace=Path(ws_str) if ws_str else self.workspace,
                agent=agent,
                agent_name=str(body.get("agent_name") or ""),
                mode=str(body.get("mode") or "enforce"),
                session_id=session_id,
                subject=resolve_subject(subject_str),
            )
        except Exception as exc:
            self._send_json({"error": f"evaluation error: {exc}"}, 500)
            return
        self._send_json(decision.as_dict())


def run_eval_server(
    host: str = "127.0.0.1",
    port: int = 7071,
    workspace: Optional[Path] = None,
    api_key: Optional[str] = None,
) -> None:
    """Start the evaluation HTTP server (blocking).

    ``api_key`` (or the PRISMOR_EVAL_KEY env var) turns on bearer-token auth
    for /v1/evaluate so the server can be exposed beyond localhost.
    """
    ws = workspace or Path.cwd()
    EvalHandler.workspace = ws
    EvalHandler.api_key = api_key or os.environ.get("PRISMOR_EVAL_KEY") or None

    server = _ThreadingHTTPServer((host, port), EvalHandler)
    if host not in ("127.0.0.1", "localhost", "::1") and not EvalHandler.api_key:
        print("[prismor] WARNING: binding beyond localhost with NO API key — "
              "anyone who can reach this port can evaluate against your policy. "
              "Pass --api-key or set PRISMOR_EVAL_KEY.")
    print(f"[prismor] eval-server listening on http://{host}:{port}"
          + (" (bearer auth ON)" if EvalHandler.api_key else ""))
    print(f"[prismor] workspace: {ws}")
    print(f"[prismor] POST /v1/evaluate  →  tool call → Decision")
    print(f"[prismor] GET  /health       →  liveness check")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[prismor] eval-server stopped.")


if __name__ == "__main__":
    import argparse as _ap
    _p = _ap.ArgumentParser(description="Prismor HTTP evaluation server")
    _p.add_argument("--port", type=int, default=7071)
    _p.add_argument("--host", default="127.0.0.1")
    _p.add_argument("--workspace", default=None)
    _p.add_argument("--api-key", default=None,
                    help="Require Authorization: Bearer <key> on /v1/evaluate (default: $PRISMOR_EVAL_KEY)")
    _a = _p.parse_args()
    run_eval_server(host=_a.host, port=_a.port,
                    workspace=Path(_a.workspace) if _a.workspace else None,
                    api_key=_a.api_key)
