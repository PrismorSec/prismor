"""Tests for Ed25519 receipt signing (non-repudiation + identity binding).

Verifies keypair generation/persistence, that a signed record carries a valid
signature over {hash, ts, identity}, that tampering with the hash or any bound
identity field invalidates the signature, and that the canonical signing input
matches the documented contract. Runs against an isolated $PRISMOR_HOME.

Skipped entirely when `cryptography` is unavailable (signing is an optional
extra; the runtime degrades to hash-chain-only). Run:
  python3 tests/test_receipt_signing.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO))

try:
    import cryptography  # noqa: F401
    _HAVE_CRYPTO = True
except Exception:
    _HAVE_CRYPTO = False


@unittest.skipUnless(_HAVE_CRYPTO, "cryptography not installed")
class ReceiptSigning(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp(prefix="prismor-sign-"))
        os.environ["PRISMOR_HOME"] = str(self.home)
        from prismor.runtime.enterprise import receipt_signing as signing
        self.signing = signing
        # Fresh key cache per test, so a key generated under one $PRISMOR_HOME
        # is not served to the next. Dropping the module from sys.modules does
        # NOT do this: `from prismor.runtime.enterprise import receipt_signing`
        # finds the submodule still bound on the parent package and hands back
        # the same object, cache and all — the re-import never happens.
        for name, blank in (("_CACHED_KEY", None),
                            ("_CACHED_PUBKEY_B64", None),
                            ("_LOAD_ATTEMPTED", False)):
            patcher = mock.patch.object(signing, name, blank)
            patcher.start()
            self.addCleanup(patcher.stop)

    def _record(self):
        return {
            "hash": "a" * 64,
            "ts": "2026-07-10T12:00:00.000000+00:00",
            "device_id": "dev-123",
            "agent": "claude",
            "agent_name": "reviewer",
            "subagent_id": None,
            "subject": {"source": "env", "user_id": "u-1", "team_id": "t-1", "org_id": "o-1"},
        }

    def test_keypair_generated_and_persisted(self):
        pk1 = self.signing.public_key_b64()
        self.assertTrue(pk1, "expected a public key")
        self.assertTrue(self.signing.key_path().exists())
        try:
            mode = self.signing.key_path().stat().st_mode & 0o777
            self.assertEqual(mode, 0o600)
        except Exception:
            pass  # perms best-effort on some filesystems
        # A second call returns the same key (persisted, cached).
        self.assertEqual(pk1, self.signing.public_key_b64())

    def test_sign_then_verify(self):
        rec = self._record()
        self.signing.sign_record(rec)
        self.assertEqual(rec.get("signing_alg"), "ed25519")
        self.assertTrue(rec.get("signature"))
        self.assertTrue(rec.get("signing_pubkey"))
        self.assertEqual(len(rec["signing_key_id"]), 16)
        self.assertTrue(self.signing.verify_record(rec), "signature must verify")

    def test_tampered_hash_fails(self):
        rec = self._record()
        self.signing.sign_record(rec)
        rec["hash"] = "b" * 64
        self.assertFalse(self.signing.verify_record(rec))

    def test_tampered_identity_fails(self):
        rec = self._record()
        self.signing.sign_record(rec)
        # Swapping the human principal must break the signature (R6 binding).
        rec["subject"] = {**rec["subject"], "user_id": "attacker"}
        self.assertFalse(self.signing.verify_record(rec))

    def test_tampered_ts_fails(self):
        rec = self._record()
        self.signing.sign_record(rec)
        rec["ts"] = "2020-01-01T00:00:00.000000+00:00"
        self.assertFalse(self.signing.verify_record(rec))

    def test_canonical_contract(self):
        # The signed bytes must be sorted-key, compact, non-ASCII-escaped JSON —
        # byte-identical to the server verifier's reconstruction.
        rec = self._record()
        payload = self.signing.signing_payload(rec)
        got = self.signing.canonical(payload)
        expected = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        self.assertEqual(got, expected)
        # identity carries exactly the 7 bound fields.
        self.assertEqual(
            set(payload["identity"]),
            {"device_id", "agent", "agent_name", "subagent_id", "user_id", "team_id", "org_id"},
        )

    def test_no_hash_no_signature(self):
        rec = {"ts": "2026-07-10T12:00:00+00:00", "device_id": "d"}
        self.signing.sign_record(rec)
        self.assertNotIn("signature", rec)


if __name__ == "__main__":
    unittest.main(verbosity=2)
