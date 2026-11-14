"""prismor/runtime/inference_hook_server.py — HTTP surface for the turn channel.

Serves the **AI security server** side of Claude Inference Hooks: Anthropic
POSTs a signed prompt frame to whatever URL the org's admin configured, and we
answer ``{"action": "allow"}`` or ``{"action": "deny", ...}`` inside the org's
verdict timeout. The evaluation lives in ``inference_hook.py``; this file owns
the things that only matter because the caller is remote and multi-tenant:

* **Signature verification, not bearer auth.** Anthropic signs every request
  (Standard Webhooks: ``webhook-id`` / ``webhook-timestamp`` /
  ``webhook-signature``, HMAC-SHA256 with the ``whsec_`` secret the admin got
  from claude.ai). The tenant is read from the frame's ``tenant_id`` and the
  secret is looked up per tenant — a valid signature for org A can never be
  presented as org B, because the body (with its ``tenant_id``) is what's
  signed. Bearer keys remain available for non-Anthropic callers.
* **Always HTTP 200 for a verdict.** Anthropic treats *any* non-200 as a
  "webhook failure" — it applies the org's fail-open/closed setting and counts
  toward a circuit breaker that stops enforcement. So a policy deny, a
  timeout, and a crash all return 200 with the right verdict; only an
  unauthenticated request gets a 401 (a forged request must not receive a
  verdict at all).
* **A hard timeout.** We sit on the critical path of somebody's prompt.
* **Idempotency on ``webhook-id``.** Anthropic retries once on connection
  failure with the same id; we answer from a small cache rather than
  re-evaluate (and re-log) the turn.

This is the stdlib server, right for a sidecar and for running the channel end
to end locally. For a large org put it behind a TLS-terminating front door
(nginx/Caddy/ALB) with a body limit of at least 10 MB — Anthropic sends the
whole transcript untruncated — and scale it horizontally; the evaluation core
is framework-free so re-hosting on ASGI is a re-host, not a rewrite.
"""
from __future__ import annotations

import hmac
import json
import os
import sys
import threading
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from socketserver import ThreadingMixIn
from typing import Any, Dict, List, Optional, Tuple

from prismor.runtime.inference_hook import (
    AGENT_ID,
    ChannelConfig,
    ConfigError,
    Frame,
    TurnVerdict,
    evaluate_turn,
    fail_verdict,
    load_config_file,
    parse_frame,
    resolve_config,
    verify_signature,
)

# Anthropic caps a prompt frame at 10 MB. We accept a little more so a proxy
# that adds framing never turns a legitimate transcript into a webhook failure
# (which, under fail-open, would let an oversized prompt through uninspected).
MAX_BODY_BYTES = 12 * 1024 * 1024
# How many recent webhook-ids to remember for idempotency.
DEDUPE_SIZE = 4096
# Default listen port. 7071 is `prismor eval-server`.
DEFAULT_PORT = 7072
# Conventional path; the server answers on any path (Anthropic posts to the
# exact URL the admin configured, so there is no fixed suffix in the contract).
DEFAULT_PATH = "/v1/inference-hook"


class _ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


class _VerdictCache:
    """Tiny LRU keyed on webhook-id → wire body. Thread-safe."""

    def __init__(self, size: int = DEDUPE_SIZE) -> None:
        self._d: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()
        self._size = size
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        if not key:
            return None
        with self._lock:
            val = self._d.get(key)
            if val is not None:
                self._d.move_to_end(key)
            return val

    def put(self, key: str, val: Dict[str, Any]) -> None:
        if not key:
            return
        with self._lock:
            self._d[key] = val
            self._d.move_to_end(key)
            while len(self._d) > self._size:
                self._d.popitem(last=False)


def _env_overrides(cfg: ChannelConfig) -> ChannelConfig:
    """Environment fills in what the config file did not set (single-tenant
    deployments usually have no config file at all)."""
    if not cfg.signing_secret and os.environ.get("PRISMOR_INFERENCE_HOOK_SECRET"):
        cfg.signing_secret = os.environ["PRISMOR_INFERENCE_HOOK_SECRET"].strip()
    if not cfg.previous_signing_secret and os.environ.get("PRISMOR_INFERENCE_HOOK_PREVIOUS_SECRET"):
        cfg.previous_signing_secret = os.environ["PRISMOR_INFERENCE_HOOK_PREVIOUS_SECRET"].strip()
    if not cfg.api_key and os.environ.get("PRISMOR_INFERENCE_HOOK_KEY"):
        cfg.api_key = os.environ["PRISMOR_INFERENCE_HOOK_KEY"].strip()
    if os.environ.get("PRISMOR_INFERENCE_HOOK_ALLOW_UNSIGNED", "").lower() in ("1", "true", "yes"):
        cfg.allow_unsigned = True
    if os.environ.get("PRISMOR_INFERENCE_HOOK_FAIL_OPEN", "").lower() in ("1", "true", "yes"):
        cfg.fail_open = True
    mode = os.environ.get("PRISMOR_INFERENCE_HOOK_MODE", "").lower()
    if mode in ("observe", "shadow"):
        cfg.mode = "observe"
    return cfg


def _bearer(headers: Any) -> str:
    auth = headers.get("Authorization") or ""
    return auth[7:].strip() if auth.lower().startswith("bearer ") else ""


_CREDENTIAL_KEYS = ("signing_secret", "previous_signing_secret", "api_key")


def _has_credential(entry: Any) -> bool:
    return isinstance(entry, dict) and any(
        isinstance(entry.get(k), str) and entry[k].strip() for k in _CREDENTIAL_KEYS)


def credentialed_orgs(file_config: Optional[Dict[str, Any]]) -> List[str]:
    """Orgs in the channel config that carry a credential of their own."""
    orgs = (file_config or {}).get("orgs")
    return sorted(o for o, e in orgs.items() if _has_credential(e)) if isinstance(orgs, dict) else []


def authenticate(
    cfg: ChannelConfig,
    headers: Any,
    raw: bytes,
    frame: Frame,
    *,
    cli_overrides: Optional[Dict[str, Any]] = None,
    file_config: Optional[Dict[str, Any]] = None,
) -> Tuple[bool, str, str]:
    """Decide whether this request may receive a verdict.

    Returns ``(ok, method, detail)`` where method is one of ``signature``,
    ``bearer``, ``unsigned-bootstrap``, ``unsigned-allowed`` or ``rejected``.

    Order of trust:
      1. A valid Standard Webhooks signature for this tenant's secret(s).
      2. A bearer key (non-Anthropic callers: proxies, test rigs).
      3. Unsigned, only when the org has *no* secret yet (bootstrap — the
         claude.ai "Test connection" before the first save is unsigned) or the
         operator explicitly set ``allow_unsigned``.
    A request that *is* signed but fails verification is always rejected, even
    if unsigned requests would have been accepted: a bad signature is evidence
    of forgery or misconfiguration, never a reason to fall back.
    """
    overrides = cli_overrides or {}
    fallback_key = overrides.get("api_key")

    sig = verify_signature(cfg.signing_secrets, headers, raw)
    if sig.ok:
        return True, "signature", "verified"
    if sig.status != "unsigned":
        return False, "rejected", f"signature {sig.status}"

    presented = _bearer(headers)
    if presented:
        for candidate in (cfg.api_key, fallback_key):
            if candidate and hmac.compare_digest(str(candidate), presented):
                return True, "bearer", "key matched"
        return False, "rejected", "bearer key mismatch"

    if cfg.allow_unsigned:
        return True, "unsigned-allowed", "allow_unsigned is set"
    if not cfg.is_signed and not cfg.api_key and not fallback_key:
        # Once any org has a credential the server is set up: a tenant that is
        # empty or not configured is not a new org bootstrapping, it is a
        # caller dodging its own org's secret (or forging another's org_id).
        orgs = (file_config or {}).get("orgs")
        known = isinstance(orgs, dict) and bool(frame.tenant_id) and frame.tenant_id in orgs
        if credentialed_orgs(file_config) and not known:
            return False, "rejected", "unknown tenant"
        # No credential of any kind configured for this org: bootstrap state.
        return True, "unsigned-bootstrap", "no signing secret configured yet"
    return False, "rejected", "unsigned request but a signing secret is configured"


class InferenceHookHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"  # keep-alive between verdicts
    workspace: Path = Path.cwd()
    file_config: Dict[str, Any] = {}
    cli_overrides: Dict[str, Any] = {}
    config_error: Optional[str] = None
    # Bounded pool so a burst cannot spawn unbounded evaluation threads. Each
    # request still gets its own worker; the queue is what absorbs the burst,
    # and the per-request timeout is what keeps the queue from growing forever.
    pool: ThreadPoolExecutor = ThreadPoolExecutor(max_workers=16)
    cache: _VerdictCache = _VerdictCache()
    _bootstrap_warned = False
    verbose: bool = False

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A002
        pass  # per-request logging belongs in telemetry, not stderr

    # ── plumbing ────────────────────────────────────────────────────────────

    def _send_json(self, data: Any, status: int = 200) -> None:
        body = json.dumps(data, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _drain(self, length: int) -> bytes:
        return self.rfile.read(length) if length > 0 else b""

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?")[0]
        if path in ("/health", "/healthz", "/livez"):
            # Liveness only — deliberately unauthenticated and free of org
            # detail so a load balancer can poll it.
            self._send_json({
                "status": "degraded" if self.config_error else "ok",
                "channel": "inference_hook",
                "ts": datetime.now(timezone.utc).isoformat(),
            }, status=200 if not self.config_error else 503)
            return
        # Anything else on GET: a human found the URL in a browser. Say what
        # this is without leaking configuration.
        self._send_json({
            "service": "prismor-inference-hook",
            "protocol": "claude-inference-hooks",
            "usage": f"POST a signed prompt frame to this URL (conventionally {DEFAULT_PATH}); GET /health for liveness",
        })

    # ── the endpoint ────────────────────────────────────────────────────────

    def do_POST(self) -> None:  # noqa: N802
        path = self.path.split("?")[0]
        if path in ("/health", "/healthz", "/livez"):
            self._send_json({"error": "method not allowed"}, 405)
            return

        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            length = 0

        # A config we could not parse means we do not know anybody's posture,
        # including whether they chose fail-open. Deny and say so.
        if self.config_error:
            self._drain(min(length, MAX_BODY_BYTES))
            self._send_json(TurnVerdict(
                allow=False, basis="fail_closed",
                reason="Security screening is misconfigured, so this request was blocked. Contact your administrator.",
            ).to_wire())
            return

        if length > MAX_BODY_BYTES:
            # Refused unread. This is a genuine webhook failure (Anthropic's
            # posture applies) — the alternative is allocating on demand.
            self._send_json({"error": "payload too large"}, 413)
            return

        raw = self._drain(length)
        try:
            body = json.loads(raw or b"{}")
            if not isinstance(body, dict):
                raise ValueError("body must be a JSON object")
        except Exception as exc:
            # An unparseable body is an unscreenable one. Fail posture, not 400:
            # a caller that can't be understood must not be allowed through just
            # because the failure was its fault. Tenant unknown → default posture.
            sys.stderr.write(f"[prismor] inference-hook: bad request body: {exc}\n")
            cfg = _env_overrides(resolve_config("", file_config=self.file_config, workspace=self.workspace))
            self._send_json(fail_verdict(cfg, f"bad request body: {exc}").to_wire())
            return

        frame = parse_frame(body)
        cfg = _env_overrides(resolve_config(frame.tenant_id, file_config=self.file_config, workspace=self.workspace))
        if self.cli_overrides.get("fail_open"):
            cfg.fail_open = True
        if self.cli_overrides.get("mode"):
            cfg.mode = self.cli_overrides["mode"]
        if self.cli_overrides.get("allow_unsigned"):
            cfg.allow_unsigned = True

        ok, method, detail = authenticate(cfg, self.headers, raw, frame, cli_overrides=self.cli_overrides,
                                     file_config=self.file_config)
        if not ok:
            # 401 rather than a deny verdict: this is not a policy outcome, and
            # a forged or misconfigured caller must not learn our verdicts.
            sys.stderr.write(f"[prismor] inference-hook: rejected request ({detail}; tenant={frame.tenant_id or '-'})\n")
            self._send_json({"error": "unauthorized", "detail": detail}, 401)
            return
        if method == "unsigned-bootstrap" and not InferenceHookHandler._bootstrap_warned:
            InferenceHookHandler._bootstrap_warned = True
            sys.stderr.write(
                "[prismor] inference-hook: accepted an UNSIGNED request because no signing secret is "
                "configured. Fine for the first claude.ai 'Test connection'; set the secret "
                "(--signing-secret / PRISMOR_INFERENCE_HOOK_SECRET / config) before enforcing.\n"
            )

        # Idempotency: Anthropic's one retry reuses webhook-id and the body.
        webhook_id = self.headers.get("webhook-id") or frame.request_id
        cached = self.cache.get(webhook_id)
        if cached is not None:
            self._send_json(cached)
            return

        future = self.pool.submit(
            evaluate_turn, body,
            config=cfg, session_id=frame.session_id, subject=frame.subject, workspace=self.workspace,
        )
        try:
            verdict = future.result(timeout=cfg.timeout_s)
        except FutureTimeout:
            # The work keeps running on its pool thread; we stop waiting on it.
            future.cancel()
            sys.stderr.write(
                f"[prismor] inference-hook: evaluation exceeded {cfg.timeout_s}s "
                f"(tenant={frame.tenant_id or 'default'}) — applying fail posture\n"
            )
            verdict = fail_verdict(cfg, "evaluation timed out")
        except Exception as exc:
            sys.stderr.write(f"[prismor] inference-hook: evaluation error: {exc}\n")
            verdict = fail_verdict(cfg, f"evaluation error: {exc}")

        wire = verdict.to_wire(org_id=frame.tenant_id, footer=cfg.deny_footer)
        wire["prismor"]["auth"] = method
        wire["prismor"]["application"] = frame.application or None
        self.cache.put(webhook_id, wire)
        self._send_json(wire)

        if self.verbose:
            sys.stderr.write(
                f"[prismor] inference-hook: {verdict.action:5s} basis={verdict.basis} "
                f"app={frame.application or '-'} tenant={frame.tenant_id or '-'} "
                f"actor={frame.actor_email or frame.actor_id or '-'} events={verdict.events_evaluated} "
                f"ms={verdict.eval_ms} ref={verdict.reference_id}\n"
            )
        _record_receipt(verdict, frame=frame, cfg=cfg, workspace=self.workspace)


def _record_receipt(verdict: TurnVerdict, *, frame: Frame, cfg: ChannelConfig, workspace: Path) -> None:
    """Append one signed turn record to the audit trail.

    Signed with this host's key and carrying a null ``device_id``: there is no
    enrolled device on this path, so the record attests that *this service*
    reached this verdict, not that a known machine did. That is genuinely weaker
    non-repudiation than the local channel and is left visible in the record
    rather than papered over. The record carries the ``reference_id`` we
    returned so a denial in Anthropic's Activity Feed joins to it.

    Runs after the response is written — the provider is waiting, and a receipt
    is not worth latency on their critical path.
    """
    try:
        from prismor.runtime.enterprise import audit_trail
        if not audit_trail.enabled():
            return
        event = {
            "type": "prompt",
            "agent_event": "UserPromptSubmit",
            "session_id": frame.session_id,
            "metadata": {
                "channel": "inference_hook",
                "protocol": "claude-inference-hooks",
                "org_id": frame.tenant_id or None,
                "application": frame.application or None,
                "model": frame.model or None,
                "request_id": frame.request_id or None,
                "reference_id": verdict.reference_id,
                "attestation": "service",
                "basis": verdict.basis,
                "events_evaluated": verdict.events_evaluated,
                "transcript_truncated": verdict.truncated,
                "approval_id": verdict.approval_id,
                "downgraded_action": verdict.downgraded_action,
                "shadow_action": verdict.shadow_action,
            },
        }
        subject: Dict[str, Any] = {}
        if frame.tenant_id:
            subject["org_id"] = frame.tenant_id
        if frame.actor_email or frame.actor_id:
            subject["user_id"] = frame.actor_email or frame.actor_id
        audit_trail.append_action_record(
            event=event,
            findings=verdict.findings,
            blocking=verdict.blocking,
            workspace=workspace,
            agent=AGENT_ID,
            agent_name=AGENT_ID,
            session_id=frame.session_id,
            subject=subject,
            mode=cfg.mode,
            eval_ms=verdict.eval_ms,
        )
    except Exception as exc:
        sys.stderr.write(f"[prismor] inference-hook: receipt write failed: {exc}\n")


def _preflight(workspace: Path) -> None:
    """Warn about local-only assumptions that do not survive being hosted.

    The semantic guard's ``hybrid`` mode shells out to a local Claude CLI. On a
    developer's laptop that is the point; on a hosted box there is no CLI and no
    per-user session, so it would fail every call and silently degrade the guard
    to nothing. ``api`` mode is the hosted equivalent.
    """
    try:
        from prismor.runtime.policy_engine import PolicyEngine
        cfg = PolicyEngine(workspace=workspace).semantic_guard_config or {}
        if not cfg.get("enabled"):
            return
        mode = str(cfg.get("mode", "hybrid")).lower()
        if mode == "hybrid":
            print(
                "[prismor] warning: semantic_guard.mode is 'hybrid', which shells out to a "
                "local Claude CLI that does not exist on a hosted host.\n"
                "[prismor]          Set settings.semantic_guard.mode to 'api' (needs "
                "ANTHROPIC_API_KEY) or 'heuristic' for this channel."
            )
        elif mode == "api" and not os.environ.get("ANTHROPIC_API_KEY"):
            print(
                "[prismor] warning: semantic_guard.mode is 'api' but ANTHROPIC_API_KEY is "
                "unset — the guard will fall back to the heuristic signature bank."
            )
    except Exception:
        pass


def _budget_judge(timeout_s: float) -> None:
    """Give the LLM judge a deadline inside the turn's timeout.

    The judge took 1.5-7.7s against a 3s turn budget, so the turn timed out
    and the fail posture decided: an injection the regex layer had already
    caught was denied by timeout, and would have been ALLOWED under
    --fail-open. With a per-event budget the judge's overrun falls back to the
    heuristic verdict (``_analyze_within``) and the turn answers on time with
    whatever the rules found. An operator-set budget is left alone.
    """
    if not os.environ.get("PRISMOR_SEMANTIC_BUDGET_MS"):
        # ponytail: one budget per judged event; a turn that fans out to
        # several long events can still overrun. Split by event count if seen.
        os.environ["PRISMOR_SEMANTIC_BUDGET_MS"] = str(max(300, int(timeout_s * 1000 * 0.4)))


def run_inference_hook_server(
    host: str = "127.0.0.1",
    port: int = DEFAULT_PORT,
    workspace: Optional[Path] = None,
    api_key: Optional[str] = None,
    config_path: Optional[Path] = None,
    signing_secret: Optional[str] = None,
    previous_signing_secret: Optional[str] = None,
    allow_unsigned: bool = False,
    fail_open: bool = False,
    mode: Optional[str] = None,
    verbose: bool = False,
) -> None:
    """Start the inference-hook server (blocking)."""
    ws = workspace or Path.cwd()
    InferenceHookHandler.workspace = ws
    InferenceHookHandler.verbose = verbose
    InferenceHookHandler.cli_overrides = {
        "api_key": api_key or None,
        "allow_unsigned": bool(allow_unsigned),
        "fail_open": bool(fail_open),
        "mode": ("observe" if mode in ("observe", "shadow") else ("enforce" if mode == "enforce" else None)),
    }
    if signing_secret:
        os.environ["PRISMOR_INFERENCE_HOOK_SECRET"] = signing_secret
    if previous_signing_secret:
        os.environ["PRISMOR_INFERENCE_HOOK_PREVIOUS_SECRET"] = previous_signing_secret

    try:
        InferenceHookHandler.file_config = load_config_file(config_path)
        InferenceHookHandler.config_error = None
    except ConfigError as exc:
        # Serve anyway, denying everything: a security server that exits on a
        # config typo takes the org's Claude down with it, and a running server
        # that says why is easier to diagnose than a crashed one.
        InferenceHookHandler.file_config = {}
        InferenceHookHandler.config_error = str(exc)
        sys.stderr.write(f"[prismor] inference-hook: {exc}\n")
        sys.stderr.write("[prismor] inference-hook: serving in fail-closed mode until fixed.\n")

    default_cfg = _env_overrides(resolve_config("", file_config=InferenceHookHandler.file_config, workspace=ws))
    orgs = InferenceHookHandler.file_config.get("orgs")
    org_count = len(orgs) if isinstance(orgs, dict) else 0
    has_default_cred = bool(default_cfg.is_signed or default_cfg.api_key or api_key)
    signed_orgs = credentialed_orgs(InferenceHookHandler.file_config)
    open_orgs = sorted(set(orgs) - set(signed_orgs)) if isinstance(orgs, dict) else []
    if not has_default_cred and signed_orgs and open_orgs and not InferenceHookHandler.config_error:
        sys.stderr.write(
            "[prismor] inference-hook: tenant(s) with no credential accept UNSIGNED requests "
            f"(bootstrap): {', '.join(open_orgs)}. Unknown tenants are refused.\n")
    if not has_default_cred and not signed_orgs and not InferenceHookHandler.config_error:
        sys.stderr.write(
            "[prismor] inference-hook: no signing secret configured — running in BOOTSTRAP mode "
            "(unsigned requests accepted).\n"
            "[prismor] inference-hook: this is what you want for the first claude.ai 'Test connection'. "
            "After you save the endpoint and copy the whsec_ secret, restart with "
            "--signing-secret (or PRISMOR_INFERENCE_HOOK_SECRET) so forged requests are refused.\n"
        )

    _preflight(ws)
    _budget_judge(default_cfg.timeout_s)

    server = _ThreadingHTTPServer((host, port), InferenceHookHandler)
    effective_mode = InferenceHookHandler.cli_overrides["mode"] or default_cfg.mode
    print(f"[prismor] inference-hook server listening on http://{host}:{port}")
    print(f"[prismor] workspace: {ws}")
    print(f"[prismor] mode: {effective_mode}"
          + ("  (shadow — logs would-be denies, returns allow)" if effective_mode == "observe" else ""))
    print(f"[prismor] fail posture: {'open' if (fail_open or default_cfg.fail_open) else 'closed'} "
          f"· timeout {default_cfg.timeout_s}s · judge budget {os.environ['PRISMOR_SEMANTIC_BUDGET_MS']}ms/event · deny floor: {', '.join(sorted(default_cfg.deny_categories))}")
    print(f"[prismor] auth: "
          + ("signature (whsec_ configured)" if default_cfg.is_signed else
             ("bearer key" if (default_cfg.api_key or api_key) else
              "per-tenant (unknown tenants refused)" if signed_orgs else "BOOTSTRAP (unsigned accepted)"))
          + (f" · {org_count} tenant override(s)" if org_count else ""))
    print(f"[prismor] POST <any path>   →  prompt frame → {{action: allow|deny}}")
    print(f"[prismor] GET  /health       →  liveness check")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[prismor] inference-hook server stopped.")
    finally:
        InferenceHookHandler.pool.shutdown(wait=False)


if __name__ == "__main__":
    import argparse as _ap
    _p = _ap.ArgumentParser(description="Prismor inference-hook security server")
    _p.add_argument("--port", type=int, default=DEFAULT_PORT)
    _p.add_argument("--host", default="127.0.0.1")
    _p.add_argument("--workspace", default=None)
    _p.add_argument("--api-key", default=None)
    _p.add_argument("--config", default=None)
    _p.add_argument("--signing-secret", default=None)
    _p.add_argument("--allow-unsigned", action="store_true")
    _p.add_argument("--fail-open", action="store_true")
    _p.add_argument("--mode", default=None)
    _p.add_argument("-v", "--verbose", action="store_true")
    _a = _p.parse_args()
    run_inference_hook_server(
        host=_a.host, port=_a.port,
        workspace=Path(_a.workspace) if _a.workspace else None,
        api_key=_a.api_key,
        config_path=Path(_a.config) if _a.config else None,
        signing_secret=_a.signing_secret,
        allow_unsigned=_a.allow_unsigned,
        fail_open=_a.fail_open,
        mode=_a.mode,
        verbose=_a.verbose,
    )
