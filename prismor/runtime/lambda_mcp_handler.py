"""AWS Lambda entrypoint for Prismor-hosted MCP endpoints (one function per org).

Serves ``POST /mcp/<key>`` (MCP streamable HTTP, JSON responses) behind a Lambda
Function URL. The key in the path is a real Prismor agent key: an endpoint
("Spin up MCP instance") or one person's grant on it. Each request:

1. resolves the key with the control plane (``GET /api/mcp/fleet/resolve``),
   which returns the endpoint's registry servers, with their secrets, and the
   bound subject. Revoked keys are refused there, so the kill switch needs no
   state here. Resolution is cached for ``RESOLVE_TTL`` seconds; a stale entry is
   used only while the control plane is unreachable, and a key never resolved
   fails closed.
2. hands the JSON-RPC message to the unmodified ``prismor mcp-gateway`` running
   as that key (its own PRISMOR_HOME under /tmp), so policy, the trifecta
   ledger, result screening, telemetry and the signed-policy pull are the
   runtime's own. The gateway process stays up while the instance is warm.
3. flushes the key's telemetry and saves its state snapshot before returning:
   Lambda freezes the instance between requests and may reclaim it, /tmp and all.

Function environment:
    PRISMOR_WEB_URL           the control plane, e.g. https://www.prismor.dev
    PRISMOR_ORG_ID            the org this function serves; keys from any other org
                              are refused even though the control plane would resolve them
    HOSTED_MCP_STATE_BUCKET   optional S3 bucket for per-key state snapshots, so a new
                              instance resumes the session (trifecta ledger) of the last
    HOSTED_MCP_STATE_PREFIX   optional key prefix in that bucket (default "mcp-state/")

Browser-driving servers (Playwright, Puppeteer) are not started here: there is no
browser to drive. Run those in a local ``prismor mcp-gateway``.
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import subprocess  # runs the prismor CLI from this same install.  # nosec B404
import sys
import tarfile
import threading
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

ROOT = os.environ.get("HOSTED_MCP_ROOT", "/tmp/prismor-mcp")  # Lambda's only writable dir.  # nosec B108
RESOLVE_TTL = float(os.environ.get("HOSTED_MCP_RESOLVE_TTL", "30"))
CALL_MARGIN_MS = 3000  # leave this much of the invocation for flush + snapshot
BROWSER_SERVERS = ("@playwright/mcp", "playwright-mcp", "puppeteer", "@modelcontextprotocol/server-puppeteer")

try:
    from prismor import __version__ as VERSION
except Exception:  # pragma: no cover - version lookup must never break the handler
    VERSION = "unknown"

_JSON = {"Content-Type": "application/json"}


def _reply(status: int, body: Any = None, headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    out = {"statusCode": status, "headers": {**_JSON, **(headers or {})}}
    out["body"] = "" if body is None else (body if isinstance(body, str) else json.dumps(body))
    return out


# ── control-plane resolve ────────────────────────────────────────────────────

_resolved: Dict[str, Tuple[float, Dict[str, Any]]] = {}


def _fetch_config(key: str) -> Tuple[int, Optional[Dict[str, Any]]]:
    """(status, config) from the control plane. Status 0 means unreachable."""
    base = (os.environ.get("PRISMOR_WEB_URL") or "https://www.prismor.dev").rstrip("/")
    req = urllib.request.Request(
        f"{base}/api/mcp/fleet/resolve",
        headers={"Authorization": f"Bearer {key}", "User-Agent": f"prismor-hosted-mcp/{VERSION}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:  # fixed control-plane URL.  # nosec B310
            return r.status, json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, None
    except (urllib.error.URLError, OSError, ValueError):
        return 0, None


def resolve(key: str, now: Optional[float] = None) -> Tuple[int, Optional[Dict[str, Any]]]:
    """(200, config) for a usable key, else (status, None). Fails closed."""
    now = time.time() if now is None else now
    cached = _resolved.get(key)
    if cached and now - cached[0] < RESOLVE_TTL:
        return 200, cached[1]
    status, cfg = _fetch_config(key)
    if status == 200 and cfg:
        org = os.environ.get("PRISMOR_ORG_ID")
        if org and cfg.get("org_id") != org:
            _resolved.pop(key, None)
            return 403, None
        _resolved[key] = (now, cfg)
        return 200, cfg
    if status in (401, 403, 404):
        _resolved.pop(key, None)
        _stop(key)
        return 403, None
    # Control plane unreachable or erroring: a key that resolved before keeps
    # working on its last config; one that never did is refused.
    if cached:
        return 200, cached[1]
    return 503, None


# ── one gateway process per key ──────────────────────────────────────────────

def _key_id(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:24]


def _paths(key: str) -> Dict[str, str]:
    base = os.path.join(ROOT, _key_id(key))
    return {"base": base, "home": os.path.join(base, "home"), "prismor_home": os.path.join(base, "home", ".prismor"),
            "workspace": os.path.join(base, "workspace"), "config": os.path.join(base, "mcp-gateway.json")}


def hosted_servers(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """The endpoint's servers this function can run (browser drivers left out)."""
    out = {}
    for name, spec in (cfg.get("mcpServers") or {}).items():
        argv = " ".join([str(spec.get("command") or "")] + [str(a) for a in spec.get("args") or []])
        if spec.get("command") and any(b in argv for b in BROWSER_SERVERS):
            print(f"[hosted-mcp] skipping '{name}': browser servers run in a local gateway only")
            continue
        out[name] = spec
    return out


def _fingerprint(cfg: Dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps([hosted_servers(cfg), cfg.get("subject")], sort_keys=True).encode()).hexdigest()


class Gateway:
    """The real `prismor mcp-gateway` over stdio, for one key."""

    def __init__(self, key: str, cfg: Dict[str, Any]) -> None:
        self.key, self.cfg, self.fingerprint = key, cfg, _fingerprint(cfg)
        self.paths = _paths(key)
        self._waiting: Dict[Any, List[Any]] = {}
        self._lock = threading.Lock()
        for d in ("home", "prismor_home", "workspace"):
            os.makedirs(self.paths[d], exist_ok=True)
        with open(self.paths["config"], "w", encoding="utf-8") as f:
            json.dump({"mcpServers": hosted_servers(cfg)}, f)
        os.chmod(self.paths["config"], 0o600)  # carries the servers' secrets
        self.proc = subprocess.Popen(  # fixed argv, no shell.  # nosec B603
            [sys.executable, "-m", "prismor.runtime.immunity_cli", "mcp-gateway",
             "--config", self.paths["config"], "--workspace", self.paths["workspace"],
             "--mode", "enforce", "--session-id", f"hosted-{cfg.get('instance_id', 'unknown')}"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=sys.stderr,
            env=gateway_env(key, cfg, self.paths), text=True, bufsize=1,
        )
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self) -> None:
        assert self.proc.stdout is not None
        for line in self.proc.stdout:
            try:
                msg = json.loads(line)
            except ValueError:
                continue
            with self._lock:
                slot = self._waiting.get(msg.get("id")) if isinstance(msg, dict) else None
            if slot is not None:  # a response; server-initiated notifications are dropped (no SSE here)
                slot[1] = msg
                slot[0].set()

    def alive(self) -> bool:
        return self.proc.poll() is None

    def send(self, msg: Dict[str, Any], timeout: float) -> Optional[Dict[str, Any]]:
        """Write one JSON-RPC message; return its response, or None for a notification."""
        rid = msg.get("id")
        slot = None
        if rid is not None:
            slot = [threading.Event(), None]
            with self._lock:
                self._waiting[rid] = slot
        assert self.proc.stdin is not None
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()
        if slot is None:
            return None
        try:
            if not slot[0].wait(timeout):
                return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32001, "message": "gateway timed out"}}
            return slot[1]
        finally:
            with self._lock:
                self._waiting.pop(rid, None)

    def stop(self) -> None:
        try:
            self.proc.terminate()
            self.proc.wait(timeout=5)
        except Exception:
            self.proc.kill()


def gateway_env(key: str, cfg: Dict[str, Any], paths: Dict[str, str]) -> Dict[str, str]:
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("PRISMOR_", "HOSTED_MCP_", "AWS_SECRET", "AWS_SESSION"))}
    env.update({
        "HOME": paths["home"], "PRISMOR_HOME": paths["prismor_home"],
        "PRISMOR_AGENT_KEY": key, "PRISMOR_WORKSPACE_SCOPE": "managed",
        "npm_config_cache": os.path.join(ROOT, "npm-cache"), "npm_config_update_notifier": "false",
        "UV_CACHE_DIR": os.path.join(ROOT, "uv-cache"), "XDG_CACHE_HOME": os.path.join(ROOT, "cache"),
    })
    if os.environ.get("PRISMOR_WEB_URL"):
        env["PRISMOR_API_BASE"] = os.environ["PRISMOR_WEB_URL"].rstrip("/")
    if cfg.get("subject"):
        env["PRISMOR_SUBJECT"] = str(cfg["subject"])
    return env


_gateways: Dict[str, Gateway] = {}


def _stop(key: str) -> None:
    gw = _gateways.pop(key, None)
    if gw:
        gw.stop()


def gateway_for(key: str, cfg: Dict[str, Any]) -> Gateway:
    gw = _gateways.get(key)
    if gw and gw.alive() and gw.fingerprint == _fingerprint(cfg):
        return gw
    if gw:  # crashed, or the endpoint's servers / subject changed: start over on the new config
        _stop(key)
    restore_state(key, cfg)
    gw = _gateways[key] = Gateway(key, cfg)
    return gw


# ── state between instances (optional S3) ───────────────────────────────────

def _state_dirs(paths: Dict[str, str]) -> List[str]:
    return [paths["prismor_home"], os.path.join(paths["workspace"], ".prismor")]


def _workspace_policy(paths: Dict[str, str]) -> str:
    return os.path.join(paths["workspace"], ".prismor", "policy.yaml")


def snapshot(paths: Dict[str, str]) -> bytes:
    """Gzipped tar of the key's runtime state. Never a workspace policy file: an
    endpoint follows only its org's signed policy."""
    skip = _workspace_policy(paths).lstrip("/")
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for d in _state_dirs(paths):
            if os.path.isdir(d):
                tar.add(d, arcname=d.lstrip("/"), filter=lambda i: None if i.name == skip else i)
    return buf.getvalue()


def restore(paths: Dict[str, str], data: bytes) -> None:
    base = paths["base"].lstrip("/")
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        safe = [m for m in tar.getmembers()
                if m.name.startswith(base + "/") and ".." not in m.name.split("/") and (m.isfile() or m.isdir())]
        kw = {"filter": "data"} if hasattr(tarfile, "data_filter") else {}
        tar.extractall("/", members=safe, **kw)  # members filtered to this key's own tree.  # nosec B202
    try:
        os.remove(_workspace_policy(paths))
    except FileNotFoundError:
        pass


def _s3():
    bucket = os.environ.get("HOSTED_MCP_STATE_BUCKET")
    if not bucket:
        return None, None
    import boto3  # in the Lambda base image
    return boto3.client("s3"), bucket


def _state_key(cfg: Dict[str, Any], key: str) -> str:
    prefix = os.environ.get("HOSTED_MCP_STATE_PREFIX", "mcp-state/")
    return f"{prefix}{cfg.get('instance_id', 'unknown')}/{_key_id(key)}.tgz"


def restore_state(key: str, cfg: Dict[str, Any]) -> None:
    s3, bucket = _s3()
    if not s3:
        return
    try:
        data = s3.get_object(Bucket=bucket, Key=_state_key(cfg, key))["Body"].read()
        restore(_paths(key), data)
    except Exception as exc:  # no snapshot yet, or unreadable: start fresh
        if "NoSuchKey" not in str(exc):
            print(f"[hosted-mcp] state restore skipped: {exc}")


def save_state(key: str, cfg: Dict[str, Any]) -> None:
    s3, bucket = _s3()
    if not s3:
        return
    try:
        s3.put_object(Bucket=bucket, Key=_state_key(cfg, key), Body=snapshot(_paths(key)),
                      ServerSideEncryption="AES256")
    except Exception as exc:
        print(f"[hosted-mcp] state save failed: {exc}")


def flush_telemetry(key: str) -> None:
    """Ship what the key's gateway spooled. Lambda freezes the instance after we
    return and may reclaim it, so nothing rides a later heartbeat."""
    paths = _paths(key)
    saved = {k: os.environ.get(k) for k in ("PRISMOR_HOME", "PRISMOR_AGENT_KEY", "HOME", "PRISMOR_API_BASE")}
    os.environ.update({"PRISMOR_HOME": paths["prismor_home"], "PRISMOR_AGENT_KEY": key, "HOME": paths["home"]})
    if os.environ.get("PRISMOR_WEB_URL"):
        os.environ["PRISMOR_API_BASE"] = os.environ["PRISMOR_WEB_URL"].rstrip("/")
    try:
        from prismor.runtime.enterprise import telemetry_spool as spool
        from prismor.runtime.sinks import upload_telemetry
        if spool.pending_count():
            upload_telemetry([], timeout=3)
    except Exception as exc:
        print(f"[hosted-mcp] telemetry flush failed: {exc}")
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


# ── Lambda entrypoint ────────────────────────────────────────────────────────

def _parse(event: Dict[str, Any]) -> Tuple[str, str, bytes]:
    http = (event.get("requestContext") or {}).get("http") or {}
    method = (http.get("method") or event.get("httpMethod") or "GET").upper()
    path = event.get("rawPath") or event.get("path") or "/"
    raw = event.get("body") or ""
    body = base64.b64decode(raw) if event.get("isBase64Encoded") else raw.encode("utf-8")
    return method, path, body


def handler(event: Dict[str, Any], context: Any = None) -> Dict[str, Any]:
    method, path, body = _parse(event)
    parts = [p for p in path.split("/") if p]
    if parts == ["health"] and method == "GET":
        return _reply(200, {"ok": True, "version": VERSION})
    if len(parts) != 2 or parts[0] != "mcp" or not parts[1]:
        return _reply(404, {"error": "prismor hosted MCP: POST /mcp/<key>"})
    key = parts[1]
    if method == "DELETE":  # a client ending its MCP session; the gateway outlives it
        return _reply(204)
    if method != "POST":
        return _reply(405, {"error": "POST JSON-RPC to this endpoint (no SSE stream)"}, {"Allow": "POST, DELETE"})

    status, cfg = resolve(key)
    if status != 200 or cfg is None:
        msg = "control plane unreachable" if status == 503 else "invalid or revoked instance key"
        return _reply(status, {"error": msg})

    try:
        payload = json.loads(body.decode("utf-8") or "null")
    except ValueError:
        return _reply(400, {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}})
    batch = payload if isinstance(payload, list) else [payload]
    if not batch or not all(isinstance(m, dict) for m in batch):
        return _reply(400, {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "invalid request"}})

    remaining = (context.get_remaining_time_in_millis() if context and hasattr(context, "get_remaining_time_in_millis")
                 else 300_000)
    timeout = max(1.0, (remaining - CALL_MARGIN_MS) / 1000.0)
    gw = gateway_for(key, cfg)
    replies = [r for r in (gw.send(m, timeout) for m in batch) if r is not None]

    flush_telemetry(key)
    save_state(key, cfg)
    if not replies:
        return _reply(202)
    return _reply(200, replies if isinstance(payload, list) else replies[0])
