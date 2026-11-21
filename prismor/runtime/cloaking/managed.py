"""Org vault: secrets the console holds, delivered sealed to this device.

An org admin adds a secret in the console and picks who gets it. The console
seals it to this device's X25519 key and signs the whole list with the policy
key. This module fetches that list, checks the signature and the binding,
opens each secret, and writes it into the local cloak vault, so agents use it
as ``@@SECRET:<name>@@`` like any other vaulted secret. A name that leaves the
list was deleted or un-granted, and its local copy is deleted too.

Seal format v1 (lib/managed-secrets.ts in the console is the other half)::

    shared = X25519(device_private, epk)
    key    = HKDF-SHA256(shared, salt = epk || device_public,
                         info = "prismor-managed-secret-v1", 32 bytes)
    value  = AES-256-GCM-open(key, nonce, ct||tag, aad = "<device_id>|<name>|<version>")

Files under ``$PRISMOR_HOME``:
    seal_key.pem          X25519 private key, 0600, made on first sync
    managed-vault.json    last synced change signal + issued_at high-water mark
Each delivered secret is recorded in secret-sources.json as
``prismor://<name>`` so ``cloak list`` shows where it came from.

Values are never printed or logged; errors name the secret, never its value.
"""
from __future__ import annotations

import base64
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

PREFIX = "prismor://"
_INFO = b"prismor-managed-secret-v1"
_SKEW_SECONDS = 300


class ManagedError(Exception):
    """A vault sync that could not complete. The message never holds a value."""


def _home() -> Path:
    from prismor.runtime.enterprise import identity
    return identity.prismor_home()


def key_path() -> Path:
    return _home() / "seal_key.pem"


def _state_path() -> Path:
    return _home() / "managed-vault.json"


def _write_private(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    os.replace(tmp, path)


def _load_key():
    """This device's X25519 key, made on first use."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    path = key_path()
    try:
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        if isinstance(key, X25519PrivateKey):
            return key
    except (OSError, ValueError):
        pass
    key = X25519PrivateKey.generate()
    _write_private(path, key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return key


def _public_raw(key) -> bytes:
    from cryptography.hazmat.primitives import serialization
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def open_box(box: Dict[str, Any], key, aad: bytes) -> str:
    """Open one sealed secret. Raises ManagedError if it does not open."""
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    try:
        epk = base64.b64decode(box["epk"], validate=True)
        nonce = base64.b64decode(box["nonce"], validate=True)
        ct = base64.b64decode(box["ct"], validate=True)
        shared = key.exchange(X25519PublicKey.from_public_bytes(epk))
        k = HKDF(algorithm=hashes.SHA256(), length=32, salt=epk + _public_raw(key), info=_INFO).derive(shared)
        return AESGCM(k).decrypt(nonce, ct, aad).decode("utf-8")
    except (KeyError, TypeError, ValueError, InvalidTag, UnicodeDecodeError) as exc:
        raise ManagedError("a sealed secret did not open (wrong device key, or it was altered)") from exc


def _load_state() -> Dict[str, Any]:
    try:
        data = json.loads(_state_path().read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def last_sig() -> str:
    return str(_load_state().get("sig") or "")


def _request(ident: Dict[str, Any], method: str, path: str, body: Optional[dict] = None,
             timeout: float = 8) -> Tuple[int, Dict[str, Any]]:
    from prismor.runtime.enterprise import identity
    from prismor.runtime.http_ua import user_agent

    base = str(ident.get("api_base") or identity.api_base()).rstrip("/")
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(f"{base}{path}", data=data, method=method, headers={
        "Authorization": f"Bearer {ident.get('device_key')}",
        "User-Agent": user_agent(),
        **({"Content-Type": "application/json"} if data is not None else {}),
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # operator-configured console URL  # nosec B310
            return resp.status, json.loads(resp.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as exc:
        try:
            payload = json.loads(exc.read().decode("utf-8") or "{}")
        except ValueError:
            payload = {}
        return exc.code, payload if isinstance(payload, dict) else {}
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise ManagedError(f"could not reach the console: {getattr(exc, 'reason', exc)}") from exc


def _error_code(payload: Dict[str, Any]) -> str:
    err = payload.get("error")
    return str(err.get("code") if isinstance(err, dict) else payload.get("code") or err or "")


def _fetch(ident: Dict[str, Any], key, timeout: float) -> Dict[str, Any]:
    """GET the sealed list, registering the seal key first when the console asks."""
    status, body = _request(ident, "GET", "/api/secrets/sealed", timeout=timeout)
    if status == 409 and _error_code(body) == "no_seal_key":
        pub = base64.b64encode(_public_raw(key)).decode("ascii")
        st, reply = _request(ident, "POST", "/api/devices/seal-key", {"public_key": pub}, timeout=timeout)
        if st != 200:
            raise ManagedError(f"the console refused this device's seal key (HTTP {st})")
        status, body = _request(ident, "GET", "/api/secrets/sealed", timeout=timeout)
    if status in (401, 403):
        raise ManagedError(f"the console rejected this device (HTTP {status}); re-enroll with `prismor enroll`")
    if status != 200:
        raise ManagedError(f"the console returned HTTP {status} for the org vault")
    return body


def _verify(body: Dict[str, Any], ident: Dict[str, Any]) -> Dict[str, Any]:
    """Signature, device/org binding and freshness. Returns the parsed payload."""
    from prismor.runtime.enterprise.remote_policy import _verify_signature

    payload, signature = body.get("payload"), body.get("signature")
    if not isinstance(payload, str) or not isinstance(signature, str):
        raise ManagedError("the org vault reply is not signed")
    if not _verify_signature(payload.encode("utf-8"), signature):
        raise ManagedError("the org vault signature did not verify; nothing was changed")
    try:
        parsed = json.loads(payload)
    except ValueError as exc:
        raise ManagedError("the org vault payload is not JSON") from exc
    if not isinstance(parsed, dict) or not isinstance(parsed.get("secrets"), list):
        raise ManagedError("the org vault payload has no secret list")
    for field in ("device_id", "org_id"):
        have = ident.get(field)
        if have is not None and str(parsed.get(field)) != str(have):
            raise ManagedError(f"the org vault payload is for another {field}; nothing was changed")
    from prismor.runtime.enterprise.remote_policy import _as_epoch
    issued = _as_epoch(parsed.get("issued_at"))
    if issued is None:
        raise ManagedError("the org vault payload has no issued_at")
    if issued < float(_load_state().get("issued_at") or 0) - _SKEW_SECONDS:
        raise ManagedError("the org vault payload is older than one already applied; nothing was changed")
    parsed["_issued"] = issued
    return parsed


def sync(timeout: float = 8) -> List[Dict[str, Any]]:
    """Fetch, verify and apply the org vault. Returns one result per name:
    ``{"name", "version"?, "status": stored|unchanged|conflict|removed}``.
    Raises ManagedError (nothing changed) when the device is not enrolled, the
    console can not be reached, or the reply does not verify."""
    from prismor.runtime.cloaking.secrets_store import add_secret, remove_secret, secrets_dir
    from prismor.runtime.cloaking.sources import _save_sources, load_sources
    from prismor.runtime.enterprise import identity

    ident = identity.load_identity()
    if not ident or not ident.get("device_key"):
        raise ManagedError("this machine is not enrolled with an org console")
    key = _load_key()
    parsed = _verify(_fetch(ident, key, timeout), ident)
    device_id = str(parsed.get("device_id"))

    from prismor.runtime.cloaking import bindings
    # Hosts an admin bound each secret to (signed with the rest). Checked for
    # every entry before any is applied: a bad list changes nothing.
    wanted_hosts: Dict[str, List[str]] = {}
    for box in parsed["secrets"]:
        raw = box.get("hosts") or []
        if not isinstance(raw, list):
            raise ManagedError(f"the org vault entry for {box.get('name')} has a bad hosts list")
        try:
            wanted_hosts[str(box.get("name", ""))] = [bindings.normalize_host(str(h)) for h in raw]
        except ValueError as exc:
            raise ManagedError(f"the org vault entry for {box.get('name')}: {exc}") from exc
    try:
        bound = bindings.load(secrets_dir())
    except (OSError, ValueError) as exc:
        raise ManagedError(f"can't read secret bindings: {exc}") from exc

    sources = load_sources()
    managed = {n for n, e in sources.items() if str(e.get("ref", "")).startswith(PREFIX)}
    out: List[Dict[str, Any]] = []
    seen = set()
    for box in parsed["secrets"]:
        name, version = str(box.get("name", "")), box.get("version")
        if not isinstance(version, int):
            raise ManagedError(f"the org vault entry for {name} has no version")
        seen.add(name)
        path = secrets_dir() / name
        if name not in managed and path.exists():
            # The person on this machine already vaulted a secret with this
            # name. Theirs wins; the console shows the conflict.
            out.append({"name": name, "version": version, "status": "conflict"})
            continue
        value = open_box(box, key, f"{device_id}|{name}|{version}".encode("utf-8"))
        try:
            current = path.read_text(encoding="utf-8")
        except OSError:
            current = None
        hosts = wanted_hosts.get(name) or []
        if sorted(set(hosts)) != sorted(bound.get(name) or []):
            # Before the value lands, so a newly bound secret is never on
            # disk unbound.
            bindings.save(secrets_dir(), name, hosts)
        if current == value and sources.get(name, {}).get("version") == str(version):
            out.append({"name": name, "version": version, "status": "unchanged"})
        else:
            add_secret(name, value)
            out.append({"name": name, "version": version, "status": "stored"})
        sources[name] = {"ref": f"{PREFIX}{name}", "version": str(version)}
    for name in sorted(managed - seen):
        remove_secret(name)
        sources.pop(name, None)
        if name in bound:
            bindings.save(secrets_dir(), name, None)
        out.append({"name": name, "status": "removed"})
    _save_sources(sources)
    _write_private(_state_path(), json.dumps({
        "sig": parsed.get("sig") or "", "issued_at": max(parsed["_issued"], float(_load_state().get("issued_at") or 0)),
        "synced_at": time.time(),
    }).encode("utf-8"))

    report = [{"name": r["name"], "version": r["version"], "status": "conflict" if r["status"] == "conflict" else "stored"}
              for r in out if r["status"] != "removed"]
    if report:
        try:
            _request(ident, "POST", "/api/secrets/sealed", {"results": report}, timeout=timeout)
        except ManagedError:
            pass  # the vault is applied; the console's delivery column catches up next sync
    return out


_RETRY_SECONDS = 300


def _failed_path() -> Path:
    return _home() / "managed-vault.failed"


def maybe_sync(sig: Any, timeout: float = 4) -> None:
    """Hot-path hook from the policy version check: sync when the console's
    change signal differs from the last one applied. A failed sync waits
    ``_RETRY_SECONDS`` before the hot path tries again, so a console that can
    not serve the vault does not slow every check. Never raises."""
    if sig is None or str(sig) == last_sig():
        return
    try:
        if time.time() - _failed_path().stat().st_mtime < _RETRY_SECONDS:
            return
    except OSError:
        pass
    try:
        sync(timeout=timeout)
        _failed_path().unlink(missing_ok=True)
    except Exception as exc:  # best-effort on the hot path; `prismor cloak sync` shows the reason
        import sys
        try:
            _failed_path().write_text(str(exc)[:200], encoding="utf-8")
        except OSError:
            pass
        sys.stderr.write(f"[prismor] org vault not synced: {exc}\n")
