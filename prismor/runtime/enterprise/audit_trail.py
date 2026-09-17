"""Tamper-evident, Ed25519-signed audit trail of agent actions.

The session store (``store.py``) records every tool call, but as ordinary
mutable SQLite rows + JSONL — anyone with the user's uid can edit or delete
history undetectably. The telemetry chain (``chain.py``) + receipt signing
(``receipt_signing.py``) close that gap, but only for policy findings, only
at cloud-upload time, and only when enrolled. This module applies the same
two primitives to **every evaluated action, locally**:

    ~/.prismor/audit/trail.jsonl   append-only log, one JSON record per line
    ~/.prismor/audit/chain.json    chain head {seq, last_hash}, fcntl-locked

Each record is hash-chained and signed:

    hash      = sha256(canonical_json(record - signature fields))
    signature = Ed25519(device key) over {hash, ts, identity}   (receipt_signing)

Unlike the telemetry chain, ``ts`` and every other field IS in the hash —
this chain is verified locally (``prismor trail verify``) from the very
bytes on disk, so there is no server-storage round-trip to stay byte-stable
with. Records capture the who/what/why of one action: timestamp, agent
identity + versions, the (secret-scrubbed) inputs, the policy engine's
human-readable decision rationale, and human approval outcomes. "Reasoning"
here means the policy rationale plus the agent's *stated* intent (e.g. the
Bash ``description`` param) — model chain-of-thought is not visible at the
hook boundary.

Threat model (v1, software-only): with the agent running as the user's uid
this is tamper-EVIDENT, not tamper-proof — the signing key lives on the same
machine. Byte edits, reordering, and mid-log deletion break the recomputed
linkage; whole-log rewrites require re-signing, which swaps the key id
(caught when verifying against the pinned device key or an anchored
checkpoint). ``prismor trail checkpoint`` exports a signed head for
anchoring outside the machine, which is what makes truncation provable.
The ``audit-trail-tampering`` policy rule blocks casual interference.

Failure posture: appending must never break the tool path. Errors degrade to
a skipped record — visible later as a seq gap on an otherwise-valid chain
(crash and deletion are distinguishable by whether neighbors verify).
``PRISMOR_AUDIT_STRICT=1`` inverts this: the caller fails the action closed
when a record cannot be written. ``PRISMOR_AUDIT_TRAIL=0`` disables the
trail entirely. Without the ``cryptography`` extra records are chained but
unsigned (install ``prismor[signing]``).
"""
from __future__ import annotations

import hashlib
import json
import os
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from prismor.runtime.enterprise import identity as _identity
from prismor.runtime.enterprise import receipt_signing as _signing

GENESIS = "0" * 64

# Fields attached by signing, never part of the chained hash.
_SIGNATURE_FIELDS = frozenset(
    {"signature", "signing_alg", "signing_pubkey", "signing_key_id"}
)

_SUMMARY_CAP = 400
CHECKPOINT_SCHEMA = "prismor.audit.checkpoint.v1"


def enabled() -> bool:
    return os.environ.get("PRISMOR_AUDIT_TRAIL", "1").lower() not in (
        "0", "false", "no", "off",
    )


def strict() -> bool:
    return os.environ.get("PRISMOR_AUDIT_STRICT", "").lower() in (
        "1", "true", "yes", "on",
    )


def audit_dir() -> Path:
    return _identity.prismor_home() / "audit"


def trail_path() -> Path:
    return audit_dir() / "trail.jsonl"


def state_path() -> Path:
    return audit_dir() / "chain.json"


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


def _canonical(payload: Dict[str, Any]) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def compute_hash(record: Dict[str, Any]) -> str:
    """Chained hash over the WHOLE record (incl. ts/seq/prev_hash), minus the
    signature fields and the hash itself."""
    payload = {
        k: v for k, v in record.items()
        if k not in _SIGNATURE_FIELDS and k != "hash"
    }
    return hashlib.sha256(_canonical(payload)).hexdigest()


def _append(record: Dict[str, Any]) -> Dict[str, Any]:
    """Advance the chain and append ``record`` (chained + signed) to the trail.

    State advances before the line is written — mirroring ``chain.next_link`` —
    so a crash between the two produces a verifiable seq gap rather than a
    forked seq. Raises on I/O failure; the caller decides best-effort vs strict.
    """
    state_file = state_path()
    with _locked(state_file):
        state = _read_state(state_file)
        record["seq"] = int(state["seq"]) + 1
        record["prev_hash"] = str(state.get("last_hash") or GENESIS)
        record["hash"] = compute_hash(record)
        tmp = state_file.with_suffix(".tmp")
        tmp.write_text(
            json.dumps({"seq": record["seq"], "last_hash": record["hash"]}),
            encoding="utf-8",
        )
        tmp.replace(state_file)
        _signing.sign_record(record)  # no-op without `cryptography`
        line = json.dumps(
            record, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )
        with open(trail_path(), "a", encoding="utf-8") as f:
            f.write(line + "\n")
            f.flush()
            os.fsync(f.fileno())
    return record


def _device_id() -> Optional[str]:
    try:
        ident = _identity.load_identity()
        return ident.get("device_id") if ident else None
    except Exception:
        return None


def _prismor_version() -> Optional[str]:
    try:
        from prismor.runtime import __version__
        return __version__
    except Exception:
        return None


def _phase(agent_event: str) -> str:
    try:
        from prismor.runtime.hooks import _is_pre_action
        return "pre" if _is_pre_action(agent_event) else "post"
    except Exception:
        return "pre" if "pre" in agent_event.lower() else "post"


def _tool_name(event: Dict[str, Any]) -> Optional[str]:
    try:
        from prismor.runtime.scoped_agent import _resolve_tool_name
        return _resolve_tool_name(event)
    except Exception:
        meta = event.get("metadata") or {}
        return meta.get("tool_name") or event.get("type")


def _scrubbed_view(event: Dict[str, Any]) -> Dict[str, Any]:
    """Secret-scrubbed copy of the event minus ``metadata`` (whose ``raw``
    duplicates the entire hook payload)."""
    view = {k: v for k, v in event.items() if k != "metadata"}
    try:
        from prismor.runtime.store import _recloak_event
        view = _recloak_event(view)
    except Exception:
        pass
    return view


def _input_summary(view: Dict[str, Any]) -> Optional[str]:
    for field in ("command", "path", "url", "prompt", "content"):
        value = view.get(field)
        if isinstance(value, str) and value.strip():
            return value[:_SUMMARY_CAP]
    return None


def _stated_intent(event: Dict[str, Any]) -> Optional[str]:
    """The agent's own description of what it is doing, when the payload
    carries one (e.g. the Bash tool's ``description`` param)."""
    raw = (event.get("metadata") or {}).get("raw")
    if isinstance(raw, dict):
        tool_input = raw.get("tool_input")
        if isinstance(tool_input, dict):
            desc = tool_input.get("description")
            if isinstance(desc, str) and desc.strip():
                return desc[:_SUMMARY_CAP]
    return None


def _verdict(findings: List[Dict[str, Any]], blocking: Optional[Dict[str, Any]]) -> str:
    if blocking is not None:
        action = str(blocking.get("action") or "").lower()
        return "step_up" if action == "step_up" else "blocked"
    return "warned" if findings else "allowed"


def _reason(findings: List[Dict[str, Any]], blocking: Optional[Dict[str, Any]]) -> str:
    """Human-readable rationale for the decision, mirroring
    ``runtime._block_reason`` for blocks."""
    if blocking is not None:
        parts = [f"[{blocking.get('severity', 'high')}] {blocking.get('title', 'blocked')}"]
        if blocking.get("evidence"):
            parts.append(str(blocking["evidence"]))
        if blocking.get("remediation"):
            parts.append(f"Recommended fix: {blocking['remediation']}")
        return "\n".join(parts)
    if findings:
        titles = [str(f.get("title") or f.get("ruleId") or "finding") for f in findings]
        return "non-blocking findings: " + "; ".join(titles)
    return "no policy findings"


def append_action_record(
    *,
    event: Dict[str, Any],
    findings: List[Dict[str, Any]],
    blocking: Optional[Dict[str, Any]],
    workspace: Path,
    agent: str,
    agent_name: str = "",
    session_id: str = "",
    subject: Optional[Dict[str, Any]] = None,
    mode: str = "",
    eval_ms: Optional[int] = None,
) -> Dict[str, Any]:
    """Append one signed record for an evaluated tool call (any verdict).

    Raises on I/O/lock failure so the caller can honor ``strict()``; callers
    on the tool path wrap this in try/except for the default best-effort
    posture.
    """
    meta = event.get("metadata") or {}
    view = _scrubbed_view(event)
    record: Dict[str, Any] = {
        "record_type": "action",
        "ts": datetime.now(timezone.utc).isoformat(),
        # Identity — field names match receipt_signing.signed_identity().
        "device_id": _device_id(),
        "agent": agent,
        "agent_name": agent_name or agent,
        "subagent_id": meta.get("subagent_id"),
        "subject": subject or {},
        "agent_version": meta.get("agent_version"),
        "prismor_version": _prismor_version(),
        "session_id": session_id,
        # Action.
        "phase": _phase(str(event.get("agent_event") or "")),
        "event_type": event.get("type"),
        "tool_name": _tool_name(event),
        "workspace": str(workspace),
        "input_summary": _input_summary(view),
        "evidence_hash": hashlib.sha256(_canonical(view)).hexdigest(),
        "agent_stated_intent": _stated_intent(event),
        # What told the agent to do this, when an extension did (extensions.py).
        "extension_id": ((meta.get("extension") or {}).get("id") if isinstance(meta, dict) else None),
        # Decision.
        "verdict": _verdict(findings, blocking),
        "mode": mode,
        "eval_ms": eval_ms,
        "rules": sorted(
            {str(f.get("ruleId") or f.get("rule_id")) for f in findings
             if f.get("ruleId") or f.get("rule_id")}
        ),
        "reason": _reason(findings, blocking),
    }
    return _append(record)


def append_approval_record(
    *,
    status: str,
    approval_id: Optional[str] = None,
    tool: str = "",
    rule_id: Optional[str] = None,
    severity: Optional[str] = None,
    reason: str = "",
    fingerprint: str = "",
    agent: str = "",
    session_id: str = "",
) -> Dict[str, Any]:
    """Append one signed record for a human-approval outcome
    (``approved | denied | expired | timeout | request_failed``)."""
    record: Dict[str, Any] = {
        "record_type": "approval",
        "ts": datetime.now(timezone.utc).isoformat(),
        "device_id": _device_id(),
        "agent": agent,
        "agent_name": agent,
        "subagent_id": None,
        "subject": {},
        "prismor_version": _prismor_version(),
        "session_id": session_id,
        "tool_name": tool or None,
        "approval_id": approval_id,
        "status": status,
        "fingerprint": fingerprint or None,
        "rules": [rule_id] if rule_id else [],
        "severity": severity,
        "reason": reason or f"human approval {status}",
    }
    return _append(record)


def append_extension_record(
    *,
    event: str,
    extension: Dict[str, Any],
    session_id: str = "",
    **detail: Any,
) -> Dict[str, Any]:
    """Append one signed record for an extension lifecycle event:
    ``extension_installed | extension_changed | extension_invoked |
    remote_ref_drift | remote_ref_flagged | hook_executed``. The install path is
    the one part of an agent's supply chain no tool call passes through, so it
    gets its own record type rather than riding on an action."""
    record: Dict[str, Any] = {
        "record_type": "extension",
        "ts": datetime.now(timezone.utc).isoformat(),
        "device_id": _device_id(),
        "prismor_version": _prismor_version(),
        "session_id": session_id,
        "event": event,
        "extension_id": extension.get("id"),
        "kind": extension.get("kind"),
        "name": extension.get("name"),
        "path": extension.get("path"),
        "origin": extension.get("origin"),
        "sha256": extension.get("sha256"),
        "installed_by": extension.get("installed_by"),
        "capabilities": extension.get("capabilities") or [],
        "detail": {k: v for k, v in detail.items() if v is not None},
    }
    return _append(record)


# ── Verification ─────────────────────────────────────────────────────────────

def verify_trail(
    path: Optional[Path] = None,
    pubkey_b64: Optional[str] = None,
) -> Dict[str, Any]:
    """Re-walk the trail: recompute every hash, check prev-hash linkage + seq
    monotonicity, and verify signatures.

    Signatures verify against ``pubkey_b64`` when given, else this device's
    key; records signed by any *other* key are counted in ``foreign_keys`` —
    a rewritten-and-re-signed history shows up there, not as a sig failure.
    Returns a report dict; ``status`` is ``ok`` | ``gaps`` | ``tampered`` |
    ``empty``. Gaps mean skipped/missing records (crash and deletion look the
    same locally — an anchored checkpoint disambiguates).
    """
    trail = path or trail_path()
    pinned = pubkey_b64 or (_signing.public_key_b64() if _signing.available() else None)
    pinned_key_id = _signing.key_id(pinned) if pinned else None

    report: Dict[str, Any] = {
        "path": str(trail),
        "records": 0,
        "signed": 0,
        "unsigned": 0,
        "sig_failures": [],
        "foreign_keys": {},
        "gaps": [],
        "errors": [],
        "head": None,
        "state": _read_state(state_path()),
        "pinned_key_id": pinned_key_id,
    }

    if not trail.exists():
        report["status"] = "empty"
        report["ok"] = True
        return report

    # The chain starts at seq 0 / GENESIS, so a deleted head is a gap too.
    expected_seq: Optional[int] = 0
    expected_prev: Optional[str] = GENESIS
    last: Optional[Dict[str, Any]] = None

    with open(trail, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            report["records"] += 1
            try:
                record = json.loads(line)
                if not isinstance(record, dict):
                    raise ValueError("record is not an object")
            except ValueError as exc:
                report["errors"].append(
                    {"line": line_no, "seq": None, "kind": "parse_error", "detail": str(exc)}
                )
                expected_seq, expected_prev = None, None
                continue

            seq = record.get("seq")
            if not isinstance(seq, int):
                report["errors"].append(
                    {"line": line_no, "seq": None, "kind": "missing_seq", "detail": "no integer seq"}
                )
                expected_seq, expected_prev = None, None
                continue

            if expected_seq is not None:
                if seq < expected_seq:
                    report["errors"].append({
                        "line": line_no, "seq": seq, "kind": "seq_regress",
                        "detail": f"seq {seq} after {expected_seq - 1}",
                    })
                elif seq > expected_seq:
                    # Skipped records: linkage across the hole is unverifiable,
                    # but the chain re-anchors on this record's own hash.
                    report["gaps"].append([expected_seq, seq - 1])
                    expected_prev = None

            if compute_hash(record) != record.get("hash"):
                report["errors"].append({
                    "line": line_no, "seq": seq, "kind": "hash_mismatch",
                    "detail": "recomputed hash differs — record bytes were altered",
                })
            elif expected_prev is not None and record.get("prev_hash") != expected_prev:
                report["errors"].append({
                    "line": line_no, "seq": seq, "kind": "link_break",
                    "detail": "prev_hash does not match the preceding record",
                })

            if record.get("signature"):
                key_id = record.get("signing_key_id")
                if pinned and key_id != pinned_key_id:
                    report["foreign_keys"][key_id] = report["foreign_keys"].get(key_id, 0) + 1
                elif _signing.verify_record(record, pinned):
                    report["signed"] += 1
                else:
                    report["sig_failures"].append(seq)
            else:
                report["unsigned"] += 1

            expected_seq = seq + 1
            expected_prev = record.get("hash")
            last = record

    if last is not None:
        report["head"] = {"seq": last.get("seq"), "hash": last.get("hash")}
        state = report["state"]
        if state["seq"] > last["seq"]:
            report["gaps"].append([last["seq"] + 1, state["seq"]])
        elif state["seq"] < last["seq"] or state.get("last_hash") != last.get("hash"):
            report["errors"].append({
                "line": None, "seq": last.get("seq"), "kind": "state_mismatch",
                "detail": "chain state file is behind the trail — state was reset or replaced",
            })

    tampered = bool(report["errors"] or report["sig_failures"] or report["foreign_keys"])
    report["status"] = "tampered" if tampered else ("gaps" if report["gaps"] else "ok")
    report["ok"] = report["status"] in ("ok", "empty")
    return report


def checkpoint() -> Dict[str, Any]:
    """A signed snapshot of the current chain head, for anchoring outside this
    machine (git remote, another host, a ticket). Verifiable with
    ``receipt_signing.verify_record``; ``hash``/``ts``/identity are what the
    signature binds."""
    state = _read_state(state_path())
    record: Dict[str, Any] = {
        "type": CHECKPOINT_SCHEMA,
        "ts": datetime.now(timezone.utc).isoformat(),
        "device_id": _device_id(),
        "agent": "prismor",
        "agent_name": "trail-checkpoint",
        "subagent_id": None,
        "subject": {},
        "seq": state["seq"],
        "hash": state.get("last_hash") or GENESIS,
    }
    _signing.sign_record(record)
    return record
