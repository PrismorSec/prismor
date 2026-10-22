"""A changed pauseSig must actually trigger the signed re-pull.

The sig-compare block in check_and_refresh is a long chain of near-identical
clauses, and a new one that is computed but left out of the final `if` is both
easy to write and invisible — it just means the feature silently never
propagates (exactly the bug the toolTagsSig comment in that function records).
This pins the wiring, not the hashing.
"""

import io
import json
import os
import sys
import tempfile
import unittest
import urllib.request
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prismor.runtime.enterprise import identity, remote_policy

# What the server sends when nothing at all has changed for this device.
STEADY_STATE = {
    "version": 3,
    "profileId": "prof_1",
    "fullCapture": False,
    "deviceMode": "",
    "managedReposSig": "",
    "agentControlsSig": "",
    "ruleExemptionsSig": "",
    "toolDeniesSig": "",
    "subjectControlsSig": "",
    "toolTagsSig": "",
    "egressSig": "",
    "pauseSig": "",
}


class PauseRefreshTrigger(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self._env = patch.dict(os.environ, {"PRISMOR_HOME": self._tmp})
        self._env.start()
        identity.save_identity({
            "device_id": "d1", "org_id": "o1", "user_id": "u1",
            "device_key": "prism_dev_x", "api_base": "http://127.0.0.1:1",
        })
        # Pin EVERY channel the refresh check compares, not just the pause one,
        # so STEADY_STATE is a genuine no-op and any re-pull below is
        # attributable to pauseSig alone. Leaving the other nine to fall through
        # to real reads makes this test depend on the cached-policy state, which
        # other suites in this repo are known to leak into.
        self._patches = [
            patch.object(remote_policy, "current_version", return_value=3),
            patch.object(remote_policy, "current_profile_id", return_value="prof_1"),
            patch.object(remote_policy, "current_full_capture", return_value=False),
            patch.object(remote_policy, "_current_managed_repos_sig", return_value=""),
            patch.object(remote_policy, "_current_agent_controls_sig", return_value=""),
            patch.object(remote_policy, "_current_rule_exemptions_sig", return_value=""),
            patch.object(remote_policy, "_current_tool_denies_sig", return_value=""),
            patch.object(remote_policy, "_current_subject_controls_sig", return_value=""),
            patch.object(remote_policy, "_current_tool_tags_sig", return_value=""),
            patch.object(remote_policy, "_current_egress_sig", return_value=""),
            patch.object(remote_policy, "_current_device_mode", return_value=""),
        ]
        self._pause_sig = patch.object(remote_policy, "_current_pause_sig", return_value="")
        self._patches.append(self._pause_sig)
        for p in self._patches:
            p.start()
        # Other suites here monkeypatch identity module-wide without always
        # undoing it; assert our own enrolled, non-revoked state explicitly.
        self._ident = patch.object(remote_policy._identity, "revoked_backoff_active", return_value=False)
        self._ident.start()
        self._fetch = patch.object(remote_policy, "fetch", return_value=True)
        self.fetch = self._fetch.start()

    def tearDown(self):
        self._fetch.stop()
        self._ident.stop()
        for p in self._patches:
            p.stop()
        self._env.stop()

    def _respond(self, body):
        class _Resp(io.BytesIO):
            def __enter__(self_inner): return self_inner
            def __exit__(self_inner, *a): return False
        return patch.object(urllib.request, "urlopen",
                            return_value=_Resp(json.dumps(body).encode("utf-8")))

    def test_no_repull_when_nothing_changed(self):
        with self._respond(STEADY_STATE):
            self.assertFalse(remote_policy.check_and_refresh(interval=0))
        self.fetch.assert_not_called()

    def test_a_new_pause_triggers_a_signed_repull(self):
        with self._respond({**STEADY_STATE, "pauseSig": "57c0ab6b692feadf"}):
            self.assertTrue(remote_policy.check_and_refresh(interval=0))
        self.fetch.assert_called_once_with(force=True)

    def test_a_lifted_pause_triggers_a_repull_too(self):
        # Resuming has to reach the device as reliably as pausing it, or a
        # machine stays unprotected until something unrelated churns.
        # Nested patch: overrides the setUp one and restores back to it, so a
        # failure here can't leave the class-wide patch torn down.
        with patch.object(remote_policy, "_current_pause_sig", return_value="57c0ab6b692feadf"):
            with self._respond({**STEADY_STATE, "pauseSig": ""}):
                self.assertTrue(remote_policy.check_and_refresh(interval=0))
        self.fetch.assert_called_once_with(force=True)

    def test_an_older_server_omitting_pausesig_is_not_a_change(self):
        # Absent field != changed field. A control plane that predates this
        # feature must not put every device into a permanent re-pull loop.
        body = {k: v for k, v in STEADY_STATE.items() if k != "pauseSig"}
        with self._respond(body):
            self.assertFalse(remote_policy.check_and_refresh(interval=0))
        self.fetch.assert_not_called()


if __name__ == "__main__":
    unittest.main()


class CopilotStudioRefreshTrigger(PauseRefreshTrigger):
    """Same wiring check for settings.copilot_studio (the console's tenant +
    app allowlist for the Copilot Studio eval-server)."""

    def test_a_registered_tenant_triggers_a_signed_repull(self):
        with patch.object(remote_policy, "_settings_block_sig", return_value=""):
            with self._respond({**STEADY_STATE, "copilotStudioSig": "0123456789abcdef"}):
                self.assertTrue(remote_policy.check_and_refresh(interval=0))
        self.fetch.assert_called_once_with(force=True)

    def test_same_copilot_studio_sig_is_not_a_change(self):
        with patch.object(remote_policy, "_settings_block_sig", return_value="0123456789abcdef"):
            with self._respond({**STEADY_STATE, "copilotStudioSig": "0123456789abcdef"}):
                self.assertFalse(remote_policy.check_and_refresh(interval=0))
        self.fetch.assert_not_called()
