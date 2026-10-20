"""Ed25519 signing for telemetry receipts — non-repudiation + identity binding.

The per-device hash chain (``chain.py``) makes receipts tamper-*evident*: a
retroactively edited or deleted record breaks the recomputed linkage. But the
chain is keyless (plain SHA-256), so anyone who can write the local chain file
can recompute a fully valid chain, and it hashes none of the identity fields.
That gives ordering integrity but neither **non-repudiation** nor **identity
binding**.

This module closes both. Each device holds an Ed25519 keypair; every receipt is
signed over a canonical payload that binds the immutable chain ``hash`` to the
receipt's identity claims and timestamp:

    signed_payload = {
        "hash":     <chain hash>,          # covers all hashed event fields + seq + prev_hash
        "ts":       <ISO timestamp>,       # ts is NOT in the chain hash; the signature covers it
        "identity": {device_id, agent, agent_name, subagent_id,
                     user_id, team_id, org_id},   # service + agent + human principal
    }
    signature = Ed25519(private_key).sign(canonical_json(signed_payload))

The record then carries ``signature`` (base64), ``signing_pubkey`` (base64 raw
32-byte key), ``signing_key_id`` (sha256(pubkey)[:16], hex) and
``signing_alg: "ed25519"``. The control plane verifies the signature against the
device's pinned public key (registered at enrollment / trusted-on-first-use),
which is what gives the signature teeth: a forged receipt would need the
device's private key, and the identity fields cannot be altered without
invalidating the signature.

Canonicalization contract (MUST byte-match the server verifier):
  JSON, ``sort_keys=True``, ``separators=(",", ":")``, ``ensure_ascii=False``,
  UTF-8. Null-valued fields are kept (present with value ``null``) so the field
  set is fixed regardless of which identifiers a given call carries.

Dependency posture: signing needs ``cryptography`` (an optional extra —
``pip install "prismor[signing]"``). Without it, or on any error, signing is a
silent no-op and telemetry falls back to the hash chain — signing must never
block or break telemetry. The private key lives at
``$PRISMOR_HOME/receipt_signing_key.pem`` with ``0600`` perms.
"""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Optional

from prismor.runtime.enterprise import identity as _identity

try:  # optional dependency — degrade to hash-chain-only when absent
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )

    _HAVE_CRYPTO = True
except Exception:  # pragma: no cover - import guard
    _HAVE_CRYPTO = False

SIGNING_ALG = "ed25519"

# Process-level cache so we load/parse the key once, not per receipt.
_CACHED_KEY: Any = None
_CACHED_PUBKEY_B64: Optional[str] = None
_LOAD_ATTEMPTED = False


def key_path() -> Path:
    return _identity.prismor_home() / "receipt_signing_key.pem"


def available() -> bool:
    """True when receipt signing can run (``cryptography`` importable)."""
    return _HAVE_CRYPTO


def _load_or_create_key() -> Any:
    """Return this device's Ed25519 private key, generating + persisting one on
    first use. Returns None when ``cryptography`` is unavailable or on any I/O
    error (caller then skips signing). Cached after the first call."""
    global _CACHED_KEY, _LOAD_ATTEMPTED
    if _CACHED_KEY is not None:
        return _CACHED_KEY
    if _LOAD_ATTEMPTED:
        return _CACHED_KEY  # a prior attempt failed; don't thrash the filesystem
    _LOAD_ATTEMPTED = True
    if not _HAVE_CRYPTO:
        return None

    path = key_path()
    try:
        if path.exists():
            key = serialization.load_pem_private_key(
                path.read_bytes(), password=None
            )
            if isinstance(key, Ed25519PrivateKey):
                _CACHED_KEY = key
                return key
            # Wrong key type on disk — regenerate below.
        home = _identity.prismor_home()
        home.mkdir(parents=True, exist_ok=True)
        try:
            home.chmod(0o700)
        except (PermissionError, OSError):
            pass
        key = Ed25519PrivateKey.generate()
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        tmp = path.with_suffix(".tmp")
        tmp.write_bytes(pem)
        try:
            tmp.chmod(0o600)
        except (PermissionError, OSError):
            pass
        tmp.replace(path)
        _CACHED_KEY = key
        return key
    except Exception:
        return None


def _raw_pubkey_b64(key: Any) -> Optional[str]:
    try:
        raw = key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return base64.b64encode(raw).decode("ascii")
    except Exception:
        return None


def public_key_b64() -> Optional[str]:
    """Base64 raw (32-byte) Ed25519 public key for this device, or None.

    Used at enrollment to register the key with the control plane and inline on
    each receipt for trusted-on-first-use pinning. Never raises."""
    global _CACHED_PUBKEY_B64
    if _CACHED_PUBKEY_B64 is not None:
        return _CACHED_PUBKEY_B64
    key = _load_or_create_key()
    if key is None:
        return None
    _CACHED_PUBKEY_B64 = _raw_pubkey_b64(key)
    return _CACHED_PUBKEY_B64


def key_id(pubkey_b64: Optional[str] = None) -> Optional[str]:
    """Short fingerprint of the public key: ``sha256(raw_pubkey)[:16]`` hex."""
    pk = pubkey_b64 if pubkey_b64 is not None else public_key_b64()
    if not pk:
        return None
    try:
        raw = base64.b64decode(pk)
        return hashlib.sha256(raw).hexdigest()[:16]
    except Exception:
        return None


def signed_identity(record: Dict[str, Any]) -> Dict[str, Any]:
    """The fixed identity view bound into the signature: service (device),
    agent, and human principal. Field set is stable; missing values are null."""
    subject = record.get("subject")
    subject = subject if isinstance(subject, dict) else {}
    return {
        "device_id": record.get("device_id"),
        "agent": record.get("agent"),
        "agent_name": record.get("agent_name"),
        "subagent_id": record.get("subagent_id"),
        "user_id": subject.get("user_id"),
        "team_id": subject.get("team_id"),
        "org_id": subject.get("org_id"),
    }


def signing_payload(record: Dict[str, Any]) -> Dict[str, Any]:
    """The exact object that gets signed. The server rebuilds it from the raw
    upload at ingest (its stored columns lose ``ts`` precision and cap the
    identity strings), verifies it against the pinned pubkey, and keeps the
    canonical bytes so the signature can be re-checked later."""
    return {
        "hash": record.get("hash"),
        "ts": record.get("ts"),
        "identity": signed_identity(record),
    }


def canonical(payload: Dict[str, Any]) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sign_record(record: Dict[str, Any]) -> Dict[str, Any]:
    """Attach an Ed25519 signature + public key to ``record`` in place.

    Best-effort: requires ``cryptography`` and a chain ``hash`` on the record.
    A no-op (record unchanged) when signing is unavailable or on any error —
    telemetry then rides on the hash chain alone. Returns the same record."""
    if not _HAVE_CRYPTO:
        return record
    if not record.get("hash"):
        return record  # nothing immutable to bind to; skip
    key = _load_or_create_key()
    if key is None:
        return record
    try:
        sig = key.sign(canonical(signing_payload(record)))
        pub = public_key_b64()
        record["signature"] = base64.b64encode(sig).decode("ascii")
        record["signing_alg"] = SIGNING_ALG
        record["signing_pubkey"] = pub
        record["signing_key_id"] = key_id(pub)
    except Exception:
        pass
    return record


def verify_record(record: Dict[str, Any], pubkey_b64: Optional[str] = None) -> bool:
    """Verify a record's signature. Uses the inline ``signing_pubkey`` unless an
    explicit (pinned) key is given. Returns False on any problem. Kept here so
    the runtime (`prismor doctor`) and tests can self-check without the server."""
    if not _HAVE_CRYPTO:
        return False
    sig_b64 = record.get("signature")
    pk_b64 = pubkey_b64 or record.get("signing_pubkey")
    if not sig_b64 or not pk_b64:
        return False
    try:
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(pk_b64))
        pub.verify(base64.b64decode(sig_b64), canonical(signing_payload(record)))
        return True
    except Exception:
        return False
