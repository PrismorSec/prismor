"""Per-device tamper-evident telemetry chain.

Every telemetry record this device emits is linked to the previous one:

    hash = sha256(canonical_json(normalized_fields + {"seq", "prev_hash"}))

The chain state (monotonic sequence + last hash) lives at
``~/.prismor/telemetry_chain.json`` and is advanced under an ``fcntl`` lock so
concurrent agent processes on one machine serialize correctly. The control
plane re-walks the chain (prismor-web ``lib/telemetry-chain.ts``) — a
retroactively edited or deleted record breaks the recomputed linkage.

Canonicalization contract (MUST byte-match the server-side verifier):

* Fields hashed: ``event_id, verdict, severity, rule_id, tool_name,
  evidence_hash, session_id`` + ``seq`` (int) and ``prev_hash``.
* Values are normalized EXACTLY like the ingest endpoint stores them
  (length caps, empty-string → null, enum whitelists), so the server can
  recompute the hash from its stored columns byte-for-byte.
* ``ts`` is deliberately NOT hashed: the client emits microsecond ISO strings
  while the database stores millisecond precision, so no byte-stable
  round-trip exists. Ordering integrity comes from ``seq`` + the
  ``prev_hash`` linkage instead; a timestamp-only edit is the one mutation
  this chain does not catch.
* Serialization: JSON with sorted keys, ``(",", ":")`` separators, raw
  (non-escaped) unicode, UTF-8 encoded; sha256 hex digest.

Failure posture: chain trouble must never block telemetry. Callers wrap
:func:`next_link` in try/except; a skipped link shows up server-side as a
sequence gap on an otherwise-valid chain, which the verifier reports (with
the seq range) rather than fails — an admin can distinguish "process
crashed" from "row deleted" by whether the records around the gap verify.
"""
from __future__ import annotations

import hashlib
import json
import os
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, Optional, Tuple

from prismor.runtime.enterprise import identity as _identity

GENESIS = "0" * 64

_VERDICTS = {"blocked", "warned", "observed", "allowed"}
_SEVERITIES = {"critical", "high", "medium", "low"}


def chain_path() -> Path:
    return _identity.prismor_home() / "telemetry_chain.json"


@contextmanager
def _locked(path: Path) -> Iterator[Any]:
    # Delegates to the one guarded implementation. A bare `import fcntl`
    # here raised ImportError on every tool call on Windows.
    from prismor.runtime.store import file_lock
    with file_lock(path):
        yield


def _read_state(path: Path) -> Dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and isinstance(data.get("seq"), int):
            return data
    except (OSError, ValueError):
        pass
    return {"seq": -1, "last_hash": GENESIS}


def _norm_str(value: Any, cap: int) -> Optional[str]:
    """Mirror the ingest endpoint's `str()` helper: non-empty strings are
    truncated to ``cap``; everything else stores as null."""
    if isinstance(value, str) and value:
        return value[:cap]
    return None


def _norm_enum(value: Any, allowed: set) -> Optional[str]:
    """Mirror ingest verdict/severity handling: lowercase + whitelist."""
    v = _norm_str(value, 16)
    if v is None:
        return None
    v = v.lower()
    return v if v in allowed else None


def normalized_fields(record: Dict[str, Any]) -> Dict[str, Any]:
    """The exact hashed view of a record, as the server will store it."""
    return {
        "event_id": _norm_str(record.get("event_id"), 60),
        "verdict": _norm_enum(record.get("verdict"), _VERDICTS),
        "severity": _norm_enum(record.get("severity"), _SEVERITIES),
        "rule_id": _norm_str(record.get("rule_id"), 80),
        "tool_name": _norm_str(record.get("tool_name"), 80),
        "evidence_hash": _norm_str(record.get("evidence_hash"), 64),
        "session_id": _norm_str(record.get("session_id"), 80),
    }


def compute_hash(record: Dict[str, Any], seq: int, prev_hash: str) -> str:
    payload = normalized_fields(record)
    payload["seq"] = seq
    payload["prev_hash"] = prev_hash
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def next_link(record: Dict[str, Any]) -> Tuple[int, str, str]:
    """Advance the device chain and return ``(seq, prev_hash, hash)`` for
    ``record``. Atomic under the state-file lock."""
    path = chain_path()
    with _locked(path):
        state = _read_state(path)
        seq = int(state["seq"]) + 1
        prev_hash = str(state.get("last_hash") or GENESIS)
        digest = compute_hash(record, seq, prev_hash)
        tmp = path.with_suffix(f".{os.getpid()}.tmp")
        tmp.write_text(
            json.dumps({"seq": seq, "last_hash": digest}), encoding="utf-8"
        )
        from prismor.runtime.winutil import replace_retry
        replace_retry(tmp, path)
        return seq, prev_hash, digest


def current_state() -> Dict[str, Any]:
    """Read-only view of the chain state (for `prismor doctor`)."""
    return _read_state(chain_path())
