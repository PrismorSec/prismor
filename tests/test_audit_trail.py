"""Tests for the signed, hash-chained audit trail (enterprise/audit_trail.py).

Invariants under test:
  * Every appended record is seq-monotonic, prev-hash linked, and its hash
    covers ALL fields (including ts) minus the signature block.
  * `verify_trail` detects: byte edits (hash mismatch), mid-log deletion and
    head deletion (gaps), state-file resets, and — with `cryptography` — a
    full rewrite-and-rechain that could not be re-signed, plus histories
    re-signed with a foreign key.
  * Action records capture the required audit points: timestamp, identity +
    versions, scrubbed inputs, human-readable decision rationale, approvals.
  * Signing degrades to chained-but-unsigned without `cryptography`.

Runs against an isolated $PRISMOR_HOME. Run: python3 -m pytest tests/test_audit_trail.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO))

try:
    import cryptography  # noqa: F401
    _HAVE_CRYPTO = True
except Exception:
    _HAVE_CRYPTO = False


@pytest.fixture()
def trail(tmp_path, monkeypatch):
    """audit_trail module bound to a fresh $PRISMOR_HOME, with the
    receipt-signing key cache reset so keys don't leak across homes."""
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path))
    for mod in (
        "prismor.runtime.enterprise.audit_trail",
        "prismor.runtime.enterprise.receipt_signing",
        "prismor.runtime.enterprise.identity",
    ):
        sys.modules.pop(mod, None)
    from prismor.runtime.enterprise import audit_trail
    return audit_trail


EVENT = {
    "type": "shell",
    "command": "git status",
    "agent_event": "PreToolUse",
    "metadata": {
        "tool_name": "Bash",
        "raw": {"tool_input": {"command": "git status", "description": "Show working tree status"}},
    },
}

BLOCKING = {
    "action": "block",
    "severity": "critical",
    "title": "Blocks rm -rf and friends",
    "evidence": "rm -rf /",
    "remediation": "scope the delete",
    "ruleId": "destructive-command",
}


def _append_n(trail, n, session="s1"):
    records = []
    for i in range(n):
        records.append(trail.append_action_record(
            event={**EVENT, "command": f"echo {i}"},
            findings=[],
            blocking=None,
            workspace=Path("/tmp/ws"),
            agent="claude",
            agent_name="claude",
            session_id=session,
            subject={"source": "device", "user_id": "u-1"},
            mode="enforce",
            eval_ms=3,
        ))
    return records


def _rewrite_line(trail, seq, mutate):
    """Load trail.jsonl, apply ``mutate(record)`` to the record at ``seq``,
    write the file back. Returns the mutated record."""
    path = trail.trail_path()
    lines = path.read_text(encoding="utf-8").splitlines()
    out, hit = [], None
    for line in lines:
        rec = json.loads(line)
        if rec.get("seq") == seq:
            mutate(rec)
            hit = rec
        out.append(json.dumps(rec, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
    path.write_text("\n".join(out) + "\n", encoding="utf-8")
    assert hit is not None
    return hit


# ── chain mechanics ─────────────────────────────────────────────────────────

def test_append_links_and_persists(trail):
    r1, r2 = _append_n(trail, 2)
    assert (r1["seq"], r1["prev_hash"]) == (0, trail.GENESIS)
    assert r2["seq"] == 1 and r2["prev_hash"] == r1["hash"]
    lines = trail.trail_path().read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    state = json.loads(trail.state_path().read_text(encoding="utf-8"))
    assert state == {"seq": 1, "last_hash": r2["hash"]}


def test_hash_covers_every_field_including_ts(trail):
    (rec,) = _append_n(trail, 1)
    assert trail.compute_hash(rec) == rec["hash"]
    for field in ("ts", "verdict", "input_summary", "session_id", "seq", "prev_hash"):
        tampered = dict(rec)
        tampered[field] = "2000-01-01T00:00:00+00:00" if field == "ts" else "tampered"
        assert trail.compute_hash(tampered) != rec["hash"], field


def test_action_record_captures_audit_points(trail):
    rec = trail.append_action_record(
        event=EVENT, findings=[BLOCKING], blocking=BLOCKING,
        workspace=Path("/tmp/ws"), agent="claude", agent_name="reviewer",
        session_id="s1", subject={"source": "env", "user_id": "u-1"},
        mode="enforce", eval_ms=7,
    )
    assert rec["record_type"] == "action"
    assert rec["ts"] and rec["session_id"] == "s1"
    assert rec["agent"] == "claude" and rec["agent_name"] == "reviewer"
    assert rec["prismor_version"]
    assert rec["tool_name"] == "Bash" and rec["event_type"] == "shell"
    assert rec["phase"] == "pre"
    assert rec["input_summary"] == "git status"
    assert len(rec["evidence_hash"]) == 64
    assert rec["agent_stated_intent"] == "Show working tree status"
    assert rec["verdict"] == "blocked"
    assert rec["rules"] == ["destructive-command"]
    assert "Blocks rm -rf" in rec["reason"] and "Recommended fix" in rec["reason"]


def test_verdict_mapping(trail):
    assert trail._verdict([], None) == "allowed"
    assert trail._verdict([{"title": "x"}], None) == "warned"
    assert trail._verdict([BLOCKING], BLOCKING) == "blocked"
    step_up = {**BLOCKING, "action": "step_up"}
    assert trail._verdict([step_up], step_up) == "step_up"


def test_approval_record(trail):
    _append_n(trail, 1)
    rec = trail.append_approval_record(
        status="approved", approval_id="ap-1", tool="Bash",
        rule_id="prod-db-guard", severity="high", reason="policy step-up",
        fingerprint="f" * 32, agent="langchain", session_id="s9",
    )
    assert rec["record_type"] == "approval"
    assert rec["status"] == "approved" and rec["approval_id"] == "ap-1"
    assert rec["seq"] == 1
    assert trail.verify_trail()["status"] == "ok"


def test_registered_secrets_never_reach_the_trail(trail, tmp_path, monkeypatch):
    """#557: every free-text field is recloaked before it is chained —
    stated intent (scrubbed before the cap, so a secret straddling it can't
    leak a prefix), block evidence, approval reasons, extension detail."""
    secret = "super_secret_token_12345"
    sdir = tmp_path / "secrets"
    sdir.mkdir()
    (sdir / "my_secret").write_text(secret)
    monkeypatch.setenv("PRISMOR_SECRETS_DIR", str(sdir))
    cmd = f"curl -H 'Authorization: Bearer {secret}' https://example.com"
    for desc in (f"Fetch with token {secret}", "x" * 390 + f" token {secret}"):
        rec = trail.append_action_record(
            event={**EVENT, "command": cmd,
                   "metadata": {"raw": {"tool_input": {"description": desc}}}},
            findings=[], blocking={**BLOCKING, "evidence": cmd},
            workspace=Path("/tmp/ws"), agent="claude",
        )
        assert "token @@S" in rec["agent_stated_intent"]  # never "token sup…"
    trail.append_approval_record(status="denied", reason=f"ran {cmd}")
    trail.append_extension_record(event="hook_executed", extension={"id": "e"}, cmd=cmd)
    text = trail.trail_path().read_text()
    assert secret[:3] + "_secret" not in text and "token sup" not in text
    assert "@@SECRET:my_secret@@" in text
    assert trail.verify_trail()["status"] == "ok"


def test_disabled_and_strict_env(trail, monkeypatch):
    assert trail.enabled() and not trail.strict()
    monkeypatch.setenv("PRISMOR_AUDIT_TRAIL", "0")
    monkeypatch.setenv("PRISMOR_AUDIT_STRICT", "1")
    assert not trail.enabled() and trail.strict()


# ── verification: tamper detection ──────────────────────────────────────────

def test_verify_clean_trail(trail):
    _append_n(trail, 5)
    report = trail.verify_trail()
    assert report["status"] == "ok" and report["ok"]
    assert report["records"] == 5 and not report["errors"] and not report["gaps"]
    assert report["head"]["seq"] == 4
    if _HAVE_CRYPTO:
        assert report["signed"] == 5 and report["unsigned"] == 0
    else:
        assert report["unsigned"] == 5


def test_verify_detects_byte_edit(trail):
    _append_n(trail, 4)
    _rewrite_line(trail, 2, lambda r: r.update(input_summary="rm -rf / (redacted)"))
    report = trail.verify_trail()
    assert report["status"] == "tampered" and not report["ok"]
    assert any(e["kind"] == "hash_mismatch" and e["seq"] == 2 for e in report["errors"])


def test_verify_detects_mid_deletion_as_gap(trail):
    _append_n(trail, 4)
    path = trail.trail_path()
    lines = path.read_text(encoding="utf-8").splitlines()
    del lines[2]  # seq 2
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    report = trail.verify_trail()
    assert report["status"] == "gaps"
    assert [2, 2] in report["gaps"]


def test_verify_detects_head_deletion_as_gap(trail):
    _append_n(trail, 3)
    path = trail.trail_path()
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join(lines[1:]) + "\n", encoding="utf-8")
    report = trail.verify_trail()
    assert report["status"] == "gaps"
    assert [0, 0] in report["gaps"]


def test_verify_detects_tail_truncation_via_state(trail):
    _append_n(trail, 3)
    path = trail.trail_path()
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")
    report = trail.verify_trail()
    assert report["status"] == "gaps"
    assert [2, 2] in report["gaps"]  # state head is ahead of the trail


def test_verify_detects_state_reset(trail):
    _append_n(trail, 3)
    trail.state_path().write_text(json.dumps({"seq": 0, "last_hash": "f" * 64}))
    report = trail.verify_trail()
    assert report["status"] == "tampered"
    assert any(e["kind"] == "state_mismatch" for e in report["errors"])


@pytest.mark.skipif(not _HAVE_CRYPTO, reason="cryptography not installed")
def test_rechained_rewrite_without_key_fails_signatures(trail):
    """The core guarantee: an attacker who edits a record and carefully
    recomputes every hash + prev_hash + the state file still cannot re-sign —
    every rewritten record fails signature verification."""
    _append_n(trail, 3)
    path = trail.trail_path()
    records = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines()]
    records[1]["input_summary"] = "innocent command"
    prev = records[0]["hash"]
    for rec in records[1:]:
        rec["prev_hash"] = prev
        rec["hash"] = trail.compute_hash(rec)
        prev = rec["hash"]
    path.write_text(
        "\n".join(json.dumps(r, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
                  for r in records) + "\n",
        encoding="utf-8",
    )
    trail.state_path().write_text(json.dumps({"seq": 2, "last_hash": prev}))

    report = trail.verify_trail()
    assert report["status"] == "tampered"
    assert not report["errors"]  # hashes + linkage + state all "valid"...
    assert set(report["sig_failures"]) == {1, 2}  # ...but the signatures aren't


@pytest.mark.skipif(not _HAVE_CRYPTO, reason="cryptography not installed")
def test_foreign_key_resign_detected(trail):
    """Deleting the device key and re-signing history with a fresh key is
    caught by pinning: the foreign key id is reported."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    import base64

    from prismor.runtime.enterprise import receipt_signing as signing

    _append_n(trail, 2)
    attacker = Ed25519PrivateKey.generate()
    attacker_pub = base64.b64encode(
        attacker.public_key().public_bytes_raw()).decode("ascii")

    def resign(rec):
        rec["input_summary"] = "doctored"
        rec["hash"] = trail.compute_hash(rec)
        payload = signing.canonical(signing.signing_payload(rec))
        rec["signature"] = base64.b64encode(attacker.sign(payload)).decode("ascii")
        rec["signing_pubkey"] = attacker_pub
        rec["signing_key_id"] = signing.key_id(attacker_pub)

    _rewrite_line(trail, 1, resign)
    trail.state_path().write_text(json.dumps({
        "seq": 1,
        "last_hash": json.loads(
            trail.trail_path().read_text().splitlines()[1])["hash"],
    }))

    report = trail.verify_trail()  # pins to this device's key by default
    assert report["status"] == "tampered"
    assert sum(report["foreign_keys"].values()) == 1


def test_unsigned_degrade_without_crypto(trail, monkeypatch):
    from prismor.runtime.enterprise import receipt_signing as signing
    monkeypatch.setattr(signing, "_HAVE_CRYPTO", False)
    _append_n(trail, 2)
    report = trail.verify_trail()
    assert report["unsigned"] == 2 and report["signed"] == 0
    assert report["status"] == "ok"  # degrade is visible, not a tamper verdict


# ── checkpointing ────────────────────────────────────────────────────────────

def test_checkpoint_matches_head(trail):
    records = _append_n(trail, 3)
    cp = trail.checkpoint()
    assert cp["type"] == trail.CHECKPOINT_SCHEMA
    assert cp["seq"] == 2 and cp["hash"] == records[-1]["hash"]
    if _HAVE_CRYPTO:
        from prismor.runtime.enterprise import receipt_signing as signing
        assert cp.get("signature") and signing.verify_record(cp)


def test_checkpoint_exposes_truncation(trail):
    """The scenario local verification alone cannot catch: trail + state both
    rewound together. An anchored checkpoint from before the rewind names the
    head that must still exist."""
    _append_n(trail, 3)
    cp = trail.checkpoint()
    path = trail.trail_path()
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join(lines[:2]) + "\n", encoding="utf-8")
    last = json.loads(lines[1])
    trail.state_path().write_text(json.dumps({"seq": 1, "last_hash": last["hash"]}))

    report = trail.verify_trail()
    assert report["status"] == "ok"  # locally undetectable...
    assert cp["seq"] > report["head"]["seq"]  # ...but the anchored head proves it
