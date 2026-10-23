"""AWS Lambda entrypoint for Prismor-hosted evaluation (one function per org).

Serves the eval-server routes (POST /v1/evaluate, /v1/redact, the AuthZEN
paths, GET /health, /v1/contract) behind a Lambda Function URL or an API
Gateway HTTP API, by running the request through ``EvalHandler`` itself, so
the hosted endpoint and ``prismor eval-server`` can never answer differently.

Function environment:
    PRISMOR_AGENT_KEY   the org's agent key: pulls its signed policy, reports telemetry
    PRISMOR_EVAL_KEY    bearer token callers must present (required; requests are
                        refused without it, so a function can never run open)

Lambda's only writable path is /tmp, so PRISMOR_HOME and HOME default there,
and the workspace is marked managed so the org policy applies. Session memory
(cross-call taint) lives in /tmp and so lasts as long as the warm instance.
"""
from __future__ import annotations

import base64
import io
import json
import os
import time
from email.message import Message
from pathlib import Path
from typing import Any, Dict, Tuple

os.environ.setdefault("PRISMOR_HOME", "/tmp/prismor")  # Lambda's only writable dir, private per instance  # nosec B108
os.environ.setdefault("HOME", "/tmp")  # Lambda's only writable dir, private per instance  # nosec B108
os.environ.setdefault("PRISMOR_WORKSPACE_SCOPE", "managed")

from prismor.runtime import remote_eval  # noqa: E402
from prismor.runtime.eval_server import EvalHandler  # noqa: E402

remote_eval.SERVING = True
WORKSPACE = Path(os.environ.get("PRISMOR_WORKSPACE", "/tmp/prismor/ws"))  # private per Lambda instance  # nosec B108
WORKSPACE.mkdir(parents=True, exist_ok=True)
EvalHandler.workspace = WORKSPACE
EvalHandler.api_key = os.environ.get("PRISMOR_EVAL_KEY") or None

_CORS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Prismor-Subject, "
                                    "X-Prismor-Identity, X-Prismor-Agent-Name, X-Request-ID",
}


class _Server:
    server_address = ("0.0.0.0", 443)  # placeholder for EvalHandler; no socket is opened  # nosec B104


class _Call(EvalHandler):
    """One Lambda request run through EvalHandler's routes, without a socket."""

    def __init__(self, path: str, headers: Dict[str, str], body: bytes) -> None:  # noqa: D107
        self.path = path
        self.headers = Message()
        for k, v in (headers or {}).items():
            self.headers[k] = v
        del self.headers["Content-Length"]
        self.headers["Content-Length"] = str(len(body))
        self.rfile = io.BytesIO(body)
        self.server = _Server()
        self.result: Tuple[int, Any] = (500, {"error": "no response"})

    def _send_json(self, data: Any, status: int = 200) -> None:
        self.result = (status, data)


def _warm() -> float:
    """Pull the org policy and load the engine once per cold start, so the
    first real call does not pay for it. Records nothing."""
    t0 = time.perf_counter()
    try:
        from prismor.runtime.runtime import evaluate_tool_call
        evaluate_tool_call(
            event={"type": "shell", "command": "true", "agent_event": "PreToolUse",
                   "session_id": "warmup", "metadata": {"tool_name": "warmup"}},
            workspace=WORKSPACE, agent="warmup", session_id="warmup",
            record=False, persist=False, register_agent=False, flush_at_exit=False,
        )
    except Exception as exc:  # never fail the cold start
        print(f"[prismor] warmup failed: {exc}")
    return time.perf_counter() - t0


COLD_START_SECONDS = _warm()


def _flush() -> None:
    """Ship spooled telemetry before returning. Elsewhere it rides the 60s
    heartbeat tick, but a Lambda instance is frozen between requests and can be
    reclaimed at any time, taking /tmp (and the spool) with it."""
    try:
        from prismor.runtime.enterprise import heartbeat
        from prismor.runtime.enterprise import telemetry_spool as spool
        from prismor.runtime.sinks import upload_telemetry
        if spool.pending_count():
            upload_telemetry([], timeout=3)
        heartbeat.maybe_flush(timeout=3)
    except Exception as exc:
        print(f"[prismor] telemetry flush failed: {exc}")


def handler(event: Dict[str, Any], context: Any = None) -> Dict[str, Any]:
    http = (event.get("requestContext") or {}).get("http") or {}
    method = (http.get("method") or event.get("httpMethod") or "GET").upper()
    path = event.get("rawPath") or event.get("path") or "/"
    if event.get("rawQueryString"):
        path = f"{path}?{event['rawQueryString']}"
    raw = event.get("body") or ""
    body = base64.b64decode(raw) if event.get("isBase64Encoded") else raw.encode("utf-8")

    if method == "OPTIONS":
        return {"statusCode": 204, "headers": _CORS, "body": ""}
    if method == "POST" and not EvalHandler.api_key:
        status, out = 503, {"error": "PRISMOR_EVAL_KEY is not set on this function; refusing to evaluate unauthenticated"}
    else:
        call = _Call(path, event.get("headers") or {}, body)
        (call.do_POST if method == "POST" else call.do_GET)()
        status, out = call.result
    _flush()
    headers = {"Content-Type": "application/json", **_CORS}
    req_id = (event.get("headers") or {}).get("x-request-id")
    if req_id:
        headers["X-Request-ID"] = req_id
    return {"statusCode": status, "headers": headers, "body": json.dumps(out, default=str)}
