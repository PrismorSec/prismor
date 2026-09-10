"""Telemetry sinks — forward Prismor findings to external systems.

Supported sink types (configured under ``settings.outputs`` in policy.yaml):

  outputs:
    - type: webhook
      url: https://siem.example.com/ingest
      headers: { "X-API-Key": "${SIEM_TOKEN}" }
    - type: syslog
      host: siem.example.com
      port: 514
      facility: local7
    - type: file
      path: ~/.prismor/audit.log
      format: json     # or: cef, ocsf
    - type: splunk              # Splunk HTTP Event Collector (OCSF body)
      url: https://splunk.example.com:8088/services/collector
      token: ${SPLUNK_HEC_TOKEN}
      sourcetype: prismor:prismor:ocsf
    - type: datadog            # Datadog Logs intake (OCSF body)
      api_key: ${DD_API_KEY}
      site: datadoghq.com
    - type: otel               # OpenTelemetry collector (OTLP/HTTP logs)
      endpoint: http://localhost:4318   # base URL; the sink appends /v1/logs
      headers: { "Authorization": "Bearer ${OTEL_TOKEN}" }
    - type: prismor              # first-party control-plane sink
      # No config needed — the device key + endpoint come from the enrolled
      # identity at ~/.prismor/identity.json (see `prismor enroll`). Sends a
      # *redacted* telemetry record by default; full content only when the
      # org's resolved policy sets full_capture: true.

Each sink receives one JSON event per finding. Dispatch is best-effort
and non-blocking — a sink failure logs a warning but never blocks the
user's tool call.

The ``prismor`` sink is special: instead of the generic SIEM event built by
``_build_event``, it forwards the privacy-bounded record from
``prismor.runtime.telemetry`` so raw commands/secrets never leave the machine unless an
org admin has explicitly opted into full capture.
"""
from __future__ import annotations

from prismor.runtime.http_ua import user_agent as _http_user_agent

import json
import os
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

_FACILITIES = {
    "kern": 0, "user": 1, "mail": 2, "daemon": 3, "auth": 4, "syslog": 5,
    "lpr": 6, "news": 7, "uucp": 8, "cron": 9, "authpriv": 10, "ftp": 11,
    "local0": 16, "local1": 17, "local2": 18, "local3": 19,
    "local4": 20, "local5": 21, "local6": 22, "local7": 23,
}
# Spool depth that forces a control-plane upload even between heartbeat
# ticks, so a burst of findings is not held back by a quiet minute.
FLUSH_BATCH = 50

_SEVERITY_TO_SYSLOG = {
    "CRITICAL": 2,  # critical
    "HIGH": 3,      # error
    "MEDIUM": 4,    # warning
    "LOW": 6,       # info
}


def _expand_env(value: Any) -> Any:
    """Substitute ${VAR} references in string values with os.environ."""
    if isinstance(value, str):
        return os.path.expandvars(value)
    if isinstance(value, dict):
        return {k: _expand_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand_env(v) for v in value]
    return value


def _build_event(finding: Dict[str, Any], extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    event: Dict[str, Any] = {
        "@timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "source": "prismor",
        "hostname": _hostname(),
        "severity": finding.get("severity"),
        "category": finding.get("category"),
        "rule_id": finding.get("ruleId"),
        "action": finding.get("action"),
        "title": finding.get("title"),
        "evidence": finding.get("evidence"),
        "session_id": (finding.get("id") or "").split(":", 1)[0] if ":" in (finding.get("id") or "") else None,
        "finding_id": finding.get("id"),
    }
    if extra:
        event.update(extra)
    return event


def _hostname() -> str:
    try:
        return socket.gethostname()
    except OSError:
        return "unknown"


def _dispatch_webhook(cfg: Dict[str, Any], event: Dict[str, Any]) -> None:
    import urllib.request
    import urllib.error

    url = cfg.get("url")
    if not url:
        return
    headers = {"Content-Type": "application/json"}
    extra_headers = cfg.get("headers") or {}
    if isinstance(extra_headers, dict):
        for k, v in extra_headers.items():
            headers[str(k)] = str(v)
    timeout = float(cfg.get("timeout_seconds", 3))
    data = json.dumps(event).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    req.add_header("User-Agent", _http_user_agent())
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        resp.read(16)  # drain


def _dispatch_syslog(cfg: Dict[str, Any], event: Dict[str, Any]) -> None:
    host = cfg.get("host", "127.0.0.1")
    port = int(cfg.get("port", 514))
    facility = _FACILITIES.get(str(cfg.get("facility", "local7")).lower(), 23)
    severity_name = str(event.get("severity", "LOW")).upper()
    severity = _SEVERITY_TO_SYSLOG.get(severity_name, 6)
    priority = (facility * 8) + severity
    tag = cfg.get("tag", "prismor")
    msg = json.dumps(event)
    payload = f"<{priority}>{datetime.now().strftime('%b %d %H:%M:%S')} {_hostname()} {tag}: {msg}"

    transport = str(cfg.get("transport", "udp")).lower()
    if transport == "tcp":
        with socket.create_connection((host, port), timeout=3) as sock:
            sock.sendall(payload.encode("utf-8") + b"\n")
    else:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(3)
            sock.sendto(payload.encode("utf-8"), (host, port))


def _dispatch_file(cfg: Dict[str, Any], event: Dict[str, Any]) -> None:
    raw_path = cfg.get("path")
    if not raw_path:
        return
    path = Path(os.path.expanduser(str(raw_path)))
    path.parent.mkdir(parents=True, exist_ok=True)
    fmt = str(cfg.get("format", "json")).lower()
    if fmt == "cef":
        line = _format_cef(event)
    elif fmt == "ocsf":
        line = json.dumps(_format_ocsf(event))
    else:
        line = json.dumps(event)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")


def _dispatch_splunk_hec(cfg: Dict[str, Any], event: Dict[str, Any]) -> None:
    """Splunk HTTP Event Collector. Wraps the OCSF finding in the HEC envelope
    and authenticates with a token. Config: url, token, [sourcetype], [index]."""
    import urllib.request

    url = cfg.get("url")
    token = cfg.get("token")
    if not url or not token:
        return
    envelope: Dict[str, Any] = {"event": _format_ocsf(event), "sourcetype": cfg.get("sourcetype", "prismor:prismor:ocsf")}
    if cfg.get("index"):
        envelope["index"] = cfg["index"]
    data = json.dumps(envelope).encode("utf-8")
    headers = {"Authorization": f"Splunk {token}", "Content-Type": "application/json"}
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    req.add_header("User-Agent", _http_user_agent())
    with urllib.request.urlopen(req, timeout=float(cfg.get("timeout_seconds", 3))) as resp:
        resp.read(16)


def _dispatch_datadog(cfg: Dict[str, Any], event: Dict[str, Any]) -> None:
    """Datadog Logs intake. Sends the OCSF finding with a DD-API-KEY header.
    Config: api_key, [site] (default datadoghq.com), [service]."""
    import urllib.request

    api_key = cfg.get("api_key")
    if not api_key:
        return
    site = cfg.get("site", "datadoghq.com")
    url = cfg.get("url") or f"https://http-intake.logs.{site}/api/v2/logs"
    payload = {
        "ddsource": "prismor",
        "service": cfg.get("service", "prismor"),
        "ddtags": f"severity:{str(event.get('severity', '')).lower()},category:{event.get('category', '')}",
        "message": json.dumps(_format_ocsf(event)),
    }
    data = json.dumps([payload]).encode("utf-8")
    headers = {"DD-API-KEY": str(api_key), "Content-Type": "application/json"}
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    req.add_header("User-Agent", _http_user_agent())
    with urllib.request.urlopen(req, timeout=float(cfg.get("timeout_seconds", 3))) as resp:
        resp.read(16)


# OTLP severity numbers (spec): 9 INFO, 13 WARN, 17 ERROR, 21 FATAL.
_OTLP_SEVERITY = {"CRITICAL": 21, "HIGH": 17, "MEDIUM": 13, "LOW": 9}


def _otlp_attr(key: str, value: Any) -> Dict[str, Any]:
    """One OTLP KeyValue. Everything is stringified — findings carry free-form
    evidence and nested subjects, and a collector must never reject the batch
    over a type mismatch."""
    if isinstance(value, (dict, list)):
        value = json.dumps(value)
    return {"key": key, "value": {"stringValue": str(value)}}


def _format_otlp_logs(event: Dict[str, Any]) -> Dict[str, Any]:
    """Map a Prismor finding event to an OTLP/JSON ExportLogsServiceRequest.

    Logs, not spans: a finding is a point-in-time detection, not a unit of work
    with a duration. Any OTel collector fans this out to Grafana, Datadog,
    Honeycomb and friends without Prismor knowing which one is downstream.
    """
    sev_name = str(event.get("severity", "LOW")).upper()
    try:
        ts = datetime.fromisoformat(str(event.get("@timestamp", "")).replace("Z", "+00:00"))
    except ValueError:
        ts = datetime.now(timezone.utc)

    # Everything _build_event and its `extra` produced, minus the fields already
    # carried by dedicated log-record/resource slots, becomes an attribute — so
    # runtime extras (agent, mode, workspace, subject) ride along untouched.
    skip = {"@timestamp", "severity", "title", "source", "hostname"}
    attributes = [
        _otlp_attr(f"prismor.{k}", v)
        for k, v in event.items()
        if k not in skip and v is not None
    ]

    return {
        "resourceLogs": [{
            "resource": {"attributes": [
                _otlp_attr("service.name", "prismor"),
                _otlp_attr("host.name", event.get("hostname") or _hostname()),
            ]},
            "scopeLogs": [{
                "scope": {"name": "prismor.runtime.sinks"},
                "logRecords": [{
                    "timeUnixNano": str(int(ts.timestamp() * 1_000_000_000)),
                    "severityNumber": _OTLP_SEVERITY.get(sev_name, 9),
                    "severityText": sev_name,
                    "body": {"stringValue": event.get("title") or event.get("evidence") or "Prismor finding"},
                    "attributes": attributes,
                }],
            }],
        }],
    }


def _dispatch_otel(cfg: Dict[str, Any], event: Dict[str, Any]) -> None:
    """OTLP/HTTP logs exporter. Config: endpoint (base URL, /v1/logs appended
    unless already present), [headers], [timeout_seconds]."""
    import urllib.request

    endpoint = cfg.get("endpoint") or cfg.get("url")
    if not endpoint:
        return
    url = str(endpoint).rstrip("/")
    if not url.endswith("/v1/logs"):
        url = f"{url}/v1/logs"
    headers = {"Content-Type": "application/json"}
    extra_headers = cfg.get("headers") or {}
    if isinstance(extra_headers, dict):
        for k, v in extra_headers.items():
            headers[str(k)] = str(v)
    data = json.dumps(_format_otlp_logs(event)).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    req.add_header("User-Agent", _http_user_agent())
    with urllib.request.urlopen(req, timeout=float(cfg.get("timeout_seconds", 3))) as resp:
        resp.read(16)  # drain


def _format_cef(event: Dict[str, Any]) -> str:
    """Minimal ArcSight CEF formatter — enough for Splunk/QRadar ingest."""
    sev_map = {"CRITICAL": 10, "HIGH": 8, "MEDIUM": 5, "LOW": 3}
    severity = sev_map.get(str(event.get("severity", "")).upper(), 3)
    header = (
        "CEF:0|Prismor|Prismor|1.1.0|"
        f"{event.get('rule_id','unknown')}|"
        f"{event.get('title','finding')}|"
        f"{severity}"
    )
    extensions = {
        "act": event.get("action", ""),
        "cat": event.get("category", ""),
        "msg": event.get("evidence", ""),
        "dhost": event.get("hostname", ""),
        "rt": event.get("@timestamp", ""),
    }
    ext_str = " ".join(f"{k}={v}" for k, v in extensions.items() if v)
    return f"{header}|{ext_str}"


# OCSF severity_id: 0 Unknown, 1 Informational, 2 Low, 3 Medium, 4 High,
# 5 Critical, 6 Fatal. Map Prismor's four levels onto Low..Critical.
_OCSF_SEVERITY = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2}


def _format_ocsf(event: Dict[str, Any]) -> Dict[str, Any]:
    """Map a Prismor finding event to an OCSF Detection Finding (class_uid 2004).

    OCSF (Open Cybersecurity Schema Framework) is the schema-standard format
    SIEMs such as Splunk, Datadog and Amazon Security Lake ingest natively, so
    findings land as structured detections rather than opaque blobs. Returns a
    dict (callers JSON-encode it). Activity is "Create" (1); type_uid is
    class_uid * 100 + activity_id = 200401.
    """
    ts = event.get("@timestamp")
    sev_name = str(event.get("severity", "LOW")).upper()
    return {
        "activity_id": 1,
        "category_uid": 2,            # Findings
        "class_uid": 2004,            # Detection Finding
        "type_uid": 200401,
        "severity_id": _OCSF_SEVERITY.get(sev_name, 2),
        "severity": sev_name.capitalize(),
        "status_id": 1,               # New
        "time": ts,
        "message": event.get("title") or event.get("evidence") or "Prismor finding",
        "metadata": {
            "product": {"name": "Prismor", "vendor_name": "Prismor", "version": "1.1.0"},
            "version": "1.1.0",       # OCSF schema version
            "log_name": "prismor",
        },
        "finding_info": {
            "title": event.get("title") or event.get("rule_id") or "finding",
            "uid": event.get("finding_id"),
            "types": [event.get("category")] if event.get("category") else [],
        },
        "evidences": [{"data": event.get("evidence")}] if event.get("evidence") else [],
        "observables": [
            {"name": "device.hostname", "type": "Hostname", "value": event.get("hostname")},
        ],
        # Prismor-specific fields under the OCSF "unmapped" escape hatch.
        "unmapped": {
            "rule_id": event.get("rule_id"),
            "category": event.get("category"),
            "action": event.get("action"),
            "session_id": event.get("session_id"),
            "subject": event.get("subject"),
        },
    }


def _dispatch_prismor(
    cfg: Dict[str, Any],
    findings: List[Dict[str, Any]],
    raw_event: Dict[str, Any],
    extra: Dict[str, Any],
) -> None:
    """First-party control-plane sink: batch-upload redacted telemetry records
    to prismor-web using the enrolled device key.

    No-op (silent) when the machine is not enrolled — the sink can be left on
    in default policy without effect until `prismor enroll` runs.
    """
    import urllib.request
    import urllib.error

    from prismor.runtime.enterprise import identity as _identity
    from prismor.runtime.enterprise import telemetry as _telemetry

    ident = _identity.load_identity()
    if not ident:
        return  # not enrolled — nothing to upload
    if _identity.revoked_backoff_active():
        return  # device key was rejected — don't hammer a control plane that said no

    full_capture = bool(cfg.get("full_capture", False))
    scrub_patterns: List[str] = []
    if full_capture:
        try:
            from prismor.runtime.cloaking.patterns import all_patterns
            scrub_patterns = all_patterns()
        except Exception:
            scrub_patterns = []

    device_extra = {
        **extra,
        "device_id": ident.get("device_id"),
    }
    records = []
    for finding in findings:
        rec = _telemetry.build_record(
            finding,
            raw_event,
            extra=device_extra,
            full_capture=full_capture,
            scrub_patterns=scrub_patterns,
        )
        _telemetry.assert_redacted(rec)  # fail closed if redacted path leaks
        # Tamper-evident chain link. Best-effort: a chain failure degrades to
        # an unchained record (reported, not fatal) — telemetry must never
        # block on chain state.
        try:
            from prismor.runtime.enterprise import chain as _chain
            seq, prev_hash, digest = _chain.next_link(rec)
            rec["chain_seq"] = seq
            rec["prev_hash"] = prev_hash
            rec["hash"] = digest
        except Exception:
            pass
        # Ed25519 signature over {hash, ts, identity}: binds the immutable chain
        # hash to the receipt's identity claims (non-repudiation + R6 identity
        # binding). Best-effort — no-op without `cryptography`, and never fatal.
        try:
            from prismor.runtime.enterprise import receipt_signing as _signing
            _signing.sign_record(rec)
        except Exception:
            pass
        records.append(rec)

    if not records:
        return

    # SECURITY: the prismor sink carries the device-key bearer credential
    # (see upload_telemetry's Authorization header). A local policy.yaml could
    # otherwise set `url:` and redirect that credential to an attacker endpoint,
    # so the destination is PINNED to the enrolled identity's api_base and a
    # local `url` override is ignored for type:prismor.
    if cfg.get("url"):
        sys.stderr.write(
            "[prismor] ignoring `url` on the prismor sink — telemetry is pinned to the "
            "enrolled control plane (a local url override cannot redirect the device key)\n"
        )
    # Batch by default. One POST per finding was affordable while findings were
    # rare; under full_capture every evaluated call is a finding (runtime.py
    # synthesizes `audit-allowed` for the unflagged ones), so that is now one
    # request per tool call -- hundreds a minute from a busy agent, each one a
    # serverless invocation and a connection against the pooler.
    #
    # The offline spool is already an outbox with at-least-once delivery, so
    # observed/warned records ride it and ship on the next flush: the
    # heartbeat's 60s tick, or right here once FLUSH_BATCH have piled up.
    # Blocked verdicts still upload immediately -- an alert 60s late is not an
    # alert. Row volume at the control plane is unchanged; this is about
    # request amplification and keeping the hot path off the network.
    from prismor.runtime.enterprise import telemetry_spool as _spool

    timeout = float(cfg.get("timeout_seconds", 6))
    if any(r.get("verdict") == "blocked" for r in records):
        upload_telemetry(records, timeout=timeout)
        return
    _spool.append(records)
    if _spool.pending_count() >= FLUSH_BATCH:
        upload_telemetry([], timeout=timeout)


def upload_telemetry(
    records: List[Dict[str, Any]],
    timeout: float = 6.0,
    url_base: Optional[str] = None,
) -> None:
    """Shared control-plane uploader for telemetry records (findings AND
    agent_activity heartbeats).

    Drains previously-spooled records (offline periods, slow control plane)
    into the batch — at-least-once delivery without a background daemon. On
    network failure the whole batch is spooled and the error re-raised (callers
    log it best-effort). On 401/403 the device is marked revoked and nothing is
    spooled — uploads stay rejected until re-enrollment.

    Short timeout on the hot path: a slow control plane (cold Neon/RDS) must
    never stall a developer's tool call; records that miss the window land in
    the spool and ride along with the next upload, so nothing is lost.
    """
    import urllib.request
    import urllib.error

    from prismor.runtime.enterprise import identity as _identity
    from prismor.runtime.enterprise import telemetry_spool as _spool

    ident = _identity.load_identity()
    if not ident or _identity.revoked_backoff_active():
        return

    # Server caps batches at 500 events.
    batch = _spool.drain(limit=max(0, 500 - len(records))) + records
    if not batch:
        return

    base = str(url_base or ident.get("api_base") or _identity.api_base()).rstrip("/")
    url = base if base.endswith("/ingest") else f"{base}/api/telemetry/ingest"
    body = json.dumps({
        "org_id": ident.get("org_id"),
        "device_id": ident.get("device_id"),
        "events": batch,
    }).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {ident.get('device_key')}",
    }
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    req.add_header("User-Agent", _http_user_agent())
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp.read(16)  # drain
        _identity.clear_revoked()
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            # The control plane rejected our device key: revoked (or deleted).
            # Local protection continues with the last good policy.
            _identity.mark_revoked(f"telemetry upload rejected ({exc.code})")
            sys.stderr.write(
                "[prismor] control plane rejected this device's key "
                f"({exc.code}) — telemetry paused. Re-enroll with: prismor enroll <token>\n"
            )
            return
        _spool.append(batch)
        raise
    except (urllib.error.URLError, OSError):
        _spool.append(batch)
        raise


_DISPATCHERS = {
    "webhook": _dispatch_webhook,
    "syslog": _dispatch_syslog,
    "file": _dispatch_file,
    "splunk": _dispatch_splunk_hec,
    "datadog": _dispatch_datadog,
    "otel": _dispatch_otel,
}


def dispatch(
    findings: List[Dict[str, Any]],
    sinks: List[Dict[str, Any]],
    extra: Optional[Dict[str, Any]] = None,
    raw_event: Optional[Dict[str, Any]] = None,
) -> None:
    """Send each finding to each configured sink. Errors are swallowed with
    a warning on stderr so telemetry never blocks the user.

    The ``prismor`` control-plane sink is batched and privacy-bounded — it
    receives the raw event (to build a redacted record) rather than the generic
    SIEM event the other sinks consume.
    """
    if not findings or not sinks:
        return
    extra = extra or {}

    # First-party control-plane sinks are batched separately.
    prismor_sinks = [s for s in sinks if str((s or {}).get("type", "")).lower() == "prismor"]
    generic_sinks = [s for s in sinks if str((s or {}).get("type", "")).lower() != "prismor"]

    for sink_cfg in prismor_sinks:
        sink = _expand_env(sink_cfg)
        try:
            _dispatch_prismor(sink, findings, raw_event or {}, extra)
        except Exception as exc:
            sys.stderr.write(f"[prismor] sink 'prismor' failed: {exc}\n")

    for finding in findings:
        event = _build_event(finding, extra=extra)
        for sink_cfg in generic_sinks:
            sink = _expand_env(sink_cfg)
            kind = str(sink.get("type", "")).lower()
            disp = _DISPATCHERS.get(kind)
            if not disp:
                continue
            try:
                disp(sink, event)
            except Exception as exc:
                sys.stderr.write(f"[prismor] sink {kind!r} failed: {exc}\n")
