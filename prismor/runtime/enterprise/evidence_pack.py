"""`prismor trail export`: a per-decision evidence pack an auditor can take away (#943).

    pack/
      decisions.jsonl     one object per decision (schema: docs/schemas/decisions.schema.json)
      records.jsonl       the signed trail records those decisions came from
      authority/<h>.json  each authority snapshot a decision references
      verify.json         `trail verify` on the device + the chain head
      timeline.md         the session, in order
      manifest.json       sha256 of every file, JCS + Ed25519 signed (as `prismor attest`)

`verify_pack` checks it offline: manifest signature, each file's hash, each
record's own hash and signature, and that each snapshot matches its name.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from prismor.runtime.enterprise import attestation as _att
from prismor.runtime.enterprise import audit_trail as _audit
from prismor.runtime.enterprise import authority as _authority
from prismor.runtime.enterprise import receipt_signing as _signing

SCHEMA = "prismor.evidence_pack.v1"
_DECISION_TYPES = ("action", "approval")


def _records(session: Optional[str], since: Optional[str], until: Optional[str]) -> List[Dict[str, Any]]:
    out = []
    try:
        lines = _audit.trail_path().read_text(encoding="utf-8").splitlines()
    except OSError:
        return out
    for line in lines:
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if rec.get("record_type") not in _DECISION_TYPES:
            continue
        if session and rec.get("session_id") != session:
            continue
        ts = str(rec.get("ts") or "")
        if (since and ts < since) or (until and ts > until):
            continue
        out.append(rec)
    return out


def _decision(rec: Dict[str, Any]) -> Dict[str, Any]:
    approval = rec.get("record_type") == "approval"
    outcome = rec.get("status") if approval else (
        "refused" if rec.get("verdict") == "blocked" else
        "held" if rec.get("verdict") == "step_up" else
        "observed" if rec.get("mode") == "observe" and rec.get("rules") else "allowed")
    rules = rec.get("rules") or []
    return {
        "seq": rec.get("seq"),
        "record_hash": rec.get("hash"),
        "ts": rec.get("ts"),
        "kind": "approval_outcome" if approval else "decision",
        "identity": {"device_id": rec.get("device_id"), "signing_key_id": rec.get("signing_key_id")},
        "subject": rec.get("subject") or {},
        "agent": {"framework": rec.get("agent"), "name": rec.get("agent_name"),
                  "subagent_id": rec.get("subagent_id")},
        "session_id": rec.get("session_id"),
        "action": {"tool": rec.get("tool_name"), "event_type": rec.get("event_type"),
                   "input_summary": rec.get("input_summary")},
        "resource": rec.get("resource"),
        "policy": {"version": rec.get("policy_version"), "profile_id": rec.get("policy_profile_id")},
        "authority_hash": rec.get("authority_hash"),
        "decision": rec.get("status") if approval else rec.get("verdict"),
        "mode": rec.get("mode"),
        "enforcement_outcome": outcome,
        "rules": rules,
        "refusing_rule": (rules[0] if rules else None) if outcome in (
            "refused", "revoked_after_approval", "revoked_before_commit", "cancelled_in_flight",
            "denied") else None,
        "reason": rec.get("reason"),
        "approval": {"id": rec.get("approval_id"), "approver": rec.get("approver")} if approval else None,
    }


def _timeline(decisions: List[Dict[str, Any]], session: Optional[str]) -> str:
    lines = [f"# Session {session or '(all)'}", ""]
    for d in decisions:
        who = d["agent"]["name"] or d["agent"]["framework"] or "agent"
        res = d["resource"] or {}
        on = f" on {res.get('kind')} {res.get('id')}" if res.get("id") else ""
        rule = f" ({', '.join(d['rules'])})" if d["rules"] else ""
        by = ""
        if d["approval"] and (d["approval"].get("approver") or {}).get("email"):
            by = f" by {d['approval']['approver']['email']}"
        lines.append(f"- {d['ts']} · {who} · {d['action']['tool']}{on} → "
                     f"**{d['enforcement_outcome']}**{by}{rule}")
    return "\n".join(lines) + "\n"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def export(out: Path, *, session: Optional[str] = None, since: Optional[str] = None,
           until: Optional[str] = None) -> Dict[str, Any]:
    out.mkdir(parents=True, exist_ok=True)
    recs = _records(session, since, until)
    decisions = [_decision(r) for r in recs]
    (out / "records.jsonl").write_text(
        "".join(json.dumps(r, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
                for r in recs), encoding="utf-8")
    (out / "decisions.jsonl").write_text(
        "".join(json.dumps(d, sort_keys=True, ensure_ascii=False) + "\n" for d in decisions),
        encoding="utf-8")
    missing = []
    for h in sorted({d["authority_hash"] for d in decisions if d["authority_hash"]}):
        snap = _authority.load(h)
        if snap is None:
            missing.append(h)
            continue
        (out / "authority").mkdir(exist_ok=True)
        (out / "authority" / f"{h}.json").write_text(json.dumps(snap, sort_keys=True, indent=2),
                                                      encoding="utf-8")
    verify = {"trail": _audit.verify_trail(), "checkpoint": _audit.checkpoint()}
    (out / "verify.json").write_text(json.dumps(verify, indent=2, default=str), encoding="utf-8")
    (out / "timeline.md").write_text(_timeline(decisions, session), encoding="utf-8")

    files = {p.relative_to(out).as_posix(): _sha(p) for p in sorted(out.rglob("*"))
             if p.is_file() and p.name != "manifest.json"}
    manifest: Dict[str, Any] = {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "session_id": session, "from": since, "to": until,
        "decisions": len(decisions),
        "missing_authority": missing,
        "files": files,
    }
    manifest["content_hash"] = _att._content_hash(manifest)
    signable = {**manifest, "hash": manifest["content_hash"]}
    _signing.sign_record(signable)
    for k in ("signature", "signing_alg", "signing_pubkey", "signing_key_id"):
        if k in signable:
            manifest[k] = signable[k]
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def verify_pack(pack: Path, pubkey_b64: Optional[str] = None) -> Dict[str, Any]:
    errors: List[str] = []
    try:
        from prismor.runtime.winutil import read_text_file
        manifest = json.loads(read_text_file(pack / "manifest.json"))
    except (OSError, ValueError) as exc:
        return {"ok": False, "unreadable": True, "errors": [f"manifest.json unreadable: {exc}"]}
    sig = _att.verify_bundle(manifest, pubkey_b64)
    errors += sig["errors"]
    listed = manifest.get("files") or {}
    present = {p.relative_to(pack).as_posix() for p in pack.rglob("*")
               if p.is_file() and p.name != "manifest.json"}
    for name in sorted(present - set(listed)):
        errors.append(f"{name}: not in the manifest")
    for name, want in listed.items():
        p = pack / name
        if not p.is_file():
            errors.append(f"{name}: missing")
        elif _sha(p) != want:
            errors.append(f"{name}: altered (sha256 does not match the manifest)")
    for p in sorted((pack / "authority").glob("*.json")) if (pack / "authority").is_dir() else []:
        if _authority.digest(json.loads(p.read_text(encoding="utf-8"))) != p.stem:
            errors.append(f"authority/{p.name}: content does not match its hash")
    try:
        refs = {json.loads(l).get("authority_hash") for l in
                (pack / "decisions.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()}
    except (OSError, ValueError):
        refs = set()
    for h in sorted(r for r in refs if r):
        if not (pack / "authority" / f"{h}.json").is_file():
            errors.append(f"authority {h[:12]}: referenced by a decision but not in the pack")
    records = 0
    try:
        lines = (pack / "records.jsonl").read_text(encoding="utf-8").splitlines()
    except OSError:
        lines = []
    for line in lines:
        rec = json.loads(line)
        records += 1
        if _audit.compute_hash(rec) != rec.get("hash"):
            errors.append(f"record seq {rec.get('seq')}: hash mismatch")
        elif rec.get("signature") and _signing.available() and not _signing.verify_record(rec, pubkey_b64):
            errors.append(f"record seq {rec.get('seq')}: signature does not verify")
    return {"ok": not errors, "signed": sig["signed"], "records": records,
            "decisions": manifest.get("decisions"), "errors": errors}
