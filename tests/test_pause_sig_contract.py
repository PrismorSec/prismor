"""The device half of the pause propagation contract.

``/api/policy/version`` sends ``pauseSig``; this machine recomputes it from the
``settings.device_pause`` block in its cached signed policy and re-pulls when
they differ. If the two hashers ever disagree, the device re-pulls on EVERY
heartbeat forever — a silent, uncapped request loop that neither side's own
tests would catch.

The fixture and expected digest below are the SAME ones pinned server-side in
prismor-web/__tests__/api/policy-pause-propagation.test.ts. Change one, change
both — that is the point of pinning rather than recomputing.
"""

import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prismor.runtime.enterprise import remote_policy

# Exactly what composeBundle serves for a paused device, and the 16 hex chars
# blockSig() produces for it.
SERVED_PAUSE = {
    "state": "paused",
    "at": "2026-07-30T12:00:00.000Z",
    "until": "2099-01-01T00:00:00.000Z",
    "reason": "incident 412",
    "by": "user_1",
}
EXPECTED_SIG = "57c0ab6b692feadf"


def policy(pause_block):
    settings = {} if pause_block is None else {"device_pause": pause_block}
    return {"version": "1.0", "rules": [], "settings": settings}


class TestPauseSigContract(unittest.TestCase):
    def sig_for(self, pause_block):
        with patch.object(remote_policy, "verify_and_load", return_value=policy(pause_block)):
            return remote_policy._current_pause_sig()

    def test_matches_the_server_digest_byte_for_byte(self):
        self.assertEqual(self.sig_for(SERVED_PAUSE), EXPECTED_SIG)

    def test_key_order_on_the_wire_does_not_change_the_digest(self):
        # JSON object order is not meaningful, and the server's key order is an
        # implementation detail of how the record is built. Canonicalisation has
        # to absorb that or the digests drift for no reason at all.
        reordered = {k: SERVED_PAUSE[k] for k in reversed(list(SERVED_PAUSE))}
        self.assertEqual(self.sig_for(reordered), EXPECTED_SIG)

    def test_no_pause_signs_empty(self):
        # Must be "" and not the hash of {}, to match the server's empty-string
        # sentinel — otherwise every unpaused device re-pulls forever.
        self.assertEqual(self.sig_for(None), "")
        self.assertEqual(self.sig_for({}), "")

    def test_every_distinct_pause_gets_a_distinct_digest(self):
        variants = [
            SERVED_PAUSE,
            {**SERVED_PAUSE, "state": "resumed"},
            {**SERVED_PAUSE, "at": "2026-07-30T12:00:01.000Z"},
            {**SERVED_PAUSE, "reason": "something else"},
            {k: v for k, v in SERVED_PAUSE.items() if k != "until"},
        ]
        sigs = [self.sig_for(v) for v in variants]
        self.assertEqual(len(set(sigs)), len(variants))

    def test_unreadable_policy_signs_empty_rather_than_raising(self):
        # This runs on the hot path of every tool call; it must never throw.
        with patch.object(remote_policy, "verify_and_load", side_effect=RuntimeError("bad signature")):
            self.assertEqual(remote_policy._current_pause_sig(), "")

    def test_a_non_dict_block_is_ignored(self):
        for junk in ("paused", 1, [], None):
            self.assertEqual(self.sig_for(junk), "")


class TestRemotePauseRead(unittest.TestCase):
    """remote_pause() is what actually turns enforcement off, so it rejects
    anything it can't fully understand rather than guessing."""

    def read(self, pause_block):
        with patch.object(remote_policy, "verify_and_load", return_value=policy(pause_block)):
            return remote_policy.remote_pause()

    def test_reads_a_well_formed_pause(self):
        self.assertEqual(self.read(SERVED_PAUSE), SERVED_PAUSE)

    def test_reads_a_resume(self):
        rec = {"state": "resumed", "at": "2026-07-30T12:00:00.000Z"}
        self.assertEqual(self.read(rec), rec)

    def test_rejects_a_record_with_no_timestamp(self):
        # Precedence against a local pause is decided by time; without one there
        # is no safe answer, so refuse to act on it.
        self.assertIsNone(self.read({"state": "paused"}))

    def test_rejects_an_unknown_state(self):
        self.assertIsNone(self.read({"state": "halted", "at": "2026-07-30T12:00:00.000Z"}))

    def test_unverified_policy_yields_no_pause(self):
        # verify_and_load raising is how a tampered or unsigned policy presents.
        # Failing toward "keep enforcing" is the only safe direction here.
        with patch.object(remote_policy, "verify_and_load", side_effect=RuntimeError("bad signature")):
            self.assertIsNone(remote_policy.remote_pause())

    def test_no_policy_at_all_yields_no_pause(self):
        with patch.object(remote_policy, "verify_and_load", return_value=None):
            self.assertIsNone(remote_policy.remote_pause())


class TestServedYamlRoundTrip(unittest.TestCase):
    """The server writes the pause into YAML with UNQUOTED ISO times. The tests
    above hand verify_and_load's output in as strings, so they never saw that
    stock yaml.safe_load turns ``at`` into a datetime — which made every org
    pause a silent no-op and the sig a permanent re-pull."""

    SERVED_YAML = (
        "version: '1.0'\nrules: []\nsettings:\n  device_pause:\n"
        "    state: paused\n    at: 2026-07-30T12:00:00.000Z\n"
        "    until: 2099-01-01T00:00:00.000Z\n    reason: incident 412\n    by: user_1\n"
    )

    def test_pause_survives_the_real_loader(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as d:
            pol, sig = Path(d) / "p.yaml", Path(d) / "p.yaml.sig"
            pol.write_text(self.SERVED_YAML)
            sig.write_text("x")
            remote_policy._VERIFIED.clear()
            with patch.object(remote_policy, "cached_policy_path", return_value=pol), \
                 patch.object(remote_policy, "_cached_sig_path", return_value=sig), \
                 patch.object(remote_policy, "_verify_signature", return_value=True), \
                 patch.object(remote_policy, "_meta_path", return_value=Path(d) / "meta.json"), \
                 patch.object(remote_policy._identity, "revoked_info", return_value=None):
                self.assertEqual(remote_policy.remote_pause(), SERVED_PAUSE)
                self.assertEqual(remote_policy._current_pause_sig(), EXPECTED_SIG)
                from prismor.runtime import pause
                state = pause.org_state()
                self.assertTrue(state and state["paused"])
            remote_policy._VERIFIED.clear()


if __name__ == "__main__":
    unittest.main()
