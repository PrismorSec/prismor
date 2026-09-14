"""Device identity for Prismor — enterprise control plane link.

A Prismor install can be *enrolled* against an organization in the Prismor
control plane (prismor-web). Enrollment exchanges a short-lived enrollment
token for a long-lived, revocable **device key** and records the
``{org_id, user_id, device_id}`` this machine reports as.

The identity lives at ``$PRISMOR_HOME/identity.json`` (default
``~/.prismor/identity.json``) with ``0600`` permissions — it contains the
device key, which is a bearer credential for telemetry upload and policy
pull. It is intentionally separate from the scan API key and from cloaked
secrets so that revoking a lost laptop never breaks CI scans.

This module is import-safe with no third-party dependencies: enrollment and
control-plane I/O use ``urllib`` from the stdlib, mirroring ``sinks.py``.
"""
from __future__ import annotations

from prismor.runtime.http_ua import user_agent as _http_user_agent

import json
import os
import stat
from pathlib import Path
from typing import Any, Dict, Optional

# Default control-plane base URL. Overridable via $PRISMOR_API_BASE so
# self-hosted / staging deployments can repoint without a rebuild.
# www is canonical: the apex is subject to host-level redirects that urllib
# will not follow for POSTs (a domain-level 308 once broke enrollment).
DEFAULT_API_BASE = "https://www.prismor.dev"

_SCHEMA = "prismor.runtime.identity.v1"


def prismor_home() -> Path:
    """Return the Prismor home dir, honoring $PRISMOR_HOME (default ~/.prismor)."""
    return Path(os.environ.get("PRISMOR_HOME", str(Path.home() / ".prismor")))


def identity_path() -> Path:
    return prismor_home() / "identity.json"


def api_base() -> str:
    return os.environ.get("PRISMOR_API_BASE", DEFAULT_API_BASE).rstrip("/")


def _env_identity() -> Optional[Dict[str, Any]]:
    """Deviceless identity from ``$PRISMOR_AGENT_KEY``, or None.

    A deployed SDK agent (container, serverless worker) has no machine to
    enroll. Instead an org admin mints an **agent key** in the console and
    wires it into the deployment; the runtime presents it as the same Bearer
    credential a device key would be. The control plane attributes org/user/
    device server-side from the key, so no ids are needed locally. Env
    identity is read-only: it is never saved to identity.json and takes
    precedence over an enrolled file so container images with a baked-in
    enrollment can be overridden per-deployment.
    """
    key = (os.environ.get("PRISMOR_AGENT_KEY") or "").strip()
    if not key:
        return None
    return {
        "schema": _SCHEMA,
        "device_key": key,
        "source": "env",
        "api_base": api_base(),
        "label": os.environ.get("PRISMOR_AGENT_LABEL") or None,
    }


def load_identity() -> Optional[Dict[str, Any]]:
    """Load the enrolled device identity, or None if this machine is not enrolled.

    Returns a dict with at least ``device_key`` when enrolled (file identities
    also carry ``device_id``, ``org_id`` and ``user_id``; the control plane
    treats those as advisory and binds server-side from the key). A
    ``$PRISMOR_AGENT_KEY`` env identity — the deviceless SDK path — takes
    precedence over the file. Never raises — a malformed or missing file reads
    as "not enrolled" so the runtime degrades to local-only mode.
    """
    env = _env_identity()
    if env is not None:
        return env
    path = identity_path()
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or not data.get("device_key"):
        return None
    return data


def is_enrolled() -> bool:
    return load_identity() is not None and revoked_info() is None


def save_identity(identity: Dict[str, Any]) -> Path:
    """Persist the device identity with 0600 perms. Returns the path written."""
    home = prismor_home()
    home.mkdir(parents=True, exist_ok=True)
    try:
        home.chmod(0o700)
    except (PermissionError, OSError):
        pass
    record = {"schema": _SCHEMA, **identity}
    path = identity_path()
    path.write_text(json.dumps(record, indent=2), encoding="utf-8")
    try:
        path.chmod(0o600)
    except (PermissionError, OSError):
        pass
    return path


def clear_identity() -> bool:
    """Remove the device identity (un-enroll). Returns True if one existed."""
    path = identity_path()
    if path.exists():
        path.unlink()
        return True
    return False


# ---------------------------------------------------------------------------
# Revocation marker
#
# When the control plane answers 401/403 to a device-key call, the key has
# been revoked (or the device deleted). We record that locally so the runtime
# (a) stops hammering the control plane with doomed requests, and (b) can
# surface "this device was revoked" in `prismor enroll-status`. Local
# protection is unaffected — the last good policy keeps applying.

# After this many seconds we try the control plane again, in case the device
# was un-revoked server-side or the 401 was a transient misconfiguration.
REVOKED_RETRY_SECONDS = 3600.0


def _revoked_marker_path() -> Path:
    return prismor_home() / "device-revoked.json"


def mark_revoked(reason: str = "") -> None:
    """Record that the control plane rejected this device's key. Never raises."""
    import time
    try:
        prismor_home().mkdir(parents=True, exist_ok=True)
        _revoked_marker_path().write_text(
            json.dumps({"at": time.time(), "reason": reason[:300]}), encoding="utf-8"
        )
    except OSError:
        pass


def revoked_info() -> Optional[Dict[str, Any]]:
    """The revocation marker ({at, reason}) if this device has been rejected
    by the control plane, else None. Never raises."""
    try:
        data = json.loads(_revoked_marker_path().read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def verify_remote(timeout: float = 6.0) -> Dict[str, Any]:
    """Ask the control plane who this key actually is. One authenticated call.

    ``prismor enroll-status`` and ``doctor`` historically reported "Enrolled"
    from the *local* identity alone, so a typo'd, revoked, or wrong-org key
    still read as healthy - and an env key (``PRISMOR_AGENT_KEY``) carries no
    org/device fields at all, printing ``org: None``. A deployed agent then
    looks fine and reports nothing. This round-trips ``/api/policy/version``
    (device-authenticated, also bumps ``lastSeenAt``) and returns what the
    SERVER resolved.

    Returns ``{ok: True, org, device_id, kind, version, full_capture}`` or
    ``{ok: False, error: <short reason>}``. Never raises: verification failing
    must not break the command reporting it.
    """
    ident = load_identity()
    if not ident:
        return {"ok": False, "error": "not enrolled"}
    key = str(ident.get("device_key") or "")
    if not key:
        return {"ok": False, "error": "no device key in identity"}

    import urllib.error
    import urllib.request

    base = str(ident.get("api_base") or api_base()).rstrip("/")
    url = f"{base}/api/policy/version"
    req = urllib.request.Request(
        url, headers={"Authorization": f"Bearer {key}"}, method="GET"
    )
    try:
        from prismor.runtime.http_ua import user_agent as _ua
        req.add_header("User-Agent", _ua())
    except Exception:
        pass
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            return {"ok": False, "error": f"control plane rejected this key (HTTP {exc.code}) - revoked or wrong key"}
        return {"ok": False, "error": f"HTTP {exc.code} from {base}"}
    except (urllib.error.URLError, OSError) as exc:
        return {"ok": False, "error": f"unreachable ({exc.__class__.__name__})"}
    except ValueError:
        return {"ok": False, "error": "malformed response from the control plane"}

    return {
        "ok": True,
        "org": data.get("org"),
        "device_id": data.get("deviceId"),
        "kind": data.get("deviceKind"),
        "version": data.get("version"),
        "full_capture": data.get("fullCapture"),
    }


def revoked_backoff_active() -> bool:
    """True while we should skip control-plane calls after a revocation."""
    import time
    info = revoked_info()
    if not info:
        return False
    try:
        return (time.time() - float(info.get("at", 0))) < REVOKED_RETRY_SECONDS
    except (TypeError, ValueError):
        return False


def clear_revoked() -> None:
    """Drop the revocation marker (successful auth or fresh enrollment)."""
    try:
        _revoked_marker_path().unlink()
    except OSError:
        pass


def _hostname_label() -> str:
    import socket
    try:
        return socket.gethostname()
    except OSError:
        return "unknown-host"


def _receipt_pubkey() -> Optional[str]:
    # Register this device's Ed25519 receipt-signing public key so the control
    # plane can verify signed telemetry receipts and pin the key to the device.
    # Best-effort: None when `cryptography` isn't installed; the server treats it
    # as optional and can still pin trusted-on-first-use from the first receipt.
    try:
        from prismor.runtime.enterprise import receipt_signing as _signing
        return _signing.public_key_b64()
    except Exception:
        return None


def _enroll_request(path: str, payload: Dict[str, Any], base: str, label: str,
                    timeout: float, extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """POST an enrollment payload, validate the response, persist the identity."""
    import urllib.request
    import urllib.error
    from prismor.runtime import __version__ as _ver

    payload = {
        **payload,
        "label": label,
        "platform": _platform(),
        "prismor_version": _ver,
        "receipt_pubkey": _receipt_pubkey(),
    }
    req = urllib.request.Request(
        f"{base}{path}",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    req.add_header("User-Agent", _http_user_agent())
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:200] if exc.fp else ""
        raise RuntimeError(f"enrollment rejected ({exc.code}): {detail or exc.reason}")
    except (urllib.error.URLError, ValueError, OSError) as exc:
        raise RuntimeError(f"enrollment failed: {exc}")

    for field in ("device_id", "org_id", "user_id", "device_key"):
        if not body.get(field):
            raise RuntimeError(f"enrollment response missing {field!r}")

    identity = {
        "device_id": body["device_id"],
        "org_id": body["org_id"],
        "user_id": body["user_id"],
        "device_key": body["device_key"],
        "org_name": body.get("org_name"),
        "label": label,
        "api_base": base,
        **(extra or {}),
    }
    save_identity(identity)
    clear_revoked()  # a fresh enrollment supersedes any prior revocation
    return identity


def enroll(token: str, base: Optional[str] = None, label: Optional[str] = None,
           timeout: float = 20.0) -> Dict[str, Any]:
    """Exchange a one-time enrollment token for a device identity and persist it.

    Calls ``POST {base}/api/devices/enroll`` with the enrollment token and a
    human-readable label (defaults to the hostname). On success the response
    carries ``device_id``, ``org_id``, ``user_id`` and ``device_key``; we store
    them and return the saved record. Raises RuntimeError with a readable
    message on any failure (network, non-2xx, malformed response).
    """
    base = (base or api_base()).rstrip("/")
    return _enroll_request("/api/devices/enroll", {"token": token}, base,
                           label or _hostname_label(), timeout)


def enroll_aws(org_id: str, base: Optional[str] = None, label: Optional[str] = None,
               region: Optional[str] = None, timeout: float = 20.0) -> Dict[str, Any]:
    """Enroll using this workload's AWS IAM role instead of a token.

    Signs ``sts:GetCallerIdentity`` with whatever role credentials the host
    has (env, container endpoint, IMDSv2, ``~/.aws/credentials``) and posts the
    *signed request* to ``POST {base}/api/devices/enroll/aws``. The control
    plane replays it to STS and, if an admin bound that role to ``org_id``,
    mints a service identity. Credentials never leave the workload.
    """
    from urllib.parse import urlparse
    from prismor.runtime.enterprise import aws_identity as _aws

    base = (base or api_base()).rstrip("/")
    creds = _aws.resolve_credentials()
    if not creds:
        raise RuntimeError(
            "no AWS credentials found (checked env, container endpoint, IMDSv2, ~/.aws/credentials)"
        )
    server_id = urlparse(base).netloc
    signed = _aws.sign_get_caller_identity(
        creds, region or os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION"),
        server_id, org_id,
    )
    return _enroll_request("/api/devices/enroll/aws", {"aws": signed}, base,
                           label or _hostname_label(), timeout, extra={"source": "aws"})


def _platform() -> str:
    import platform
    return platform.system().lower() or "unknown"
