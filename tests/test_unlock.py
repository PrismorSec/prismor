"""The password-gated self-edit window.

The window is the one thing that lets an agent past Prismor's self-protection,
so these tests care mostly about the ways it must *not* open: no password, wrong
password, forged marker, lapsed expiry, another workspace, or an org that turned
the whole feature off.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prismor.runtime import unlock

PASSWORD = "correct horse battery"


class UnlockTestCase(unittest.TestCase):
    """Each test gets its own PRISMOR_HOME so nothing touches the real one."""

    def setUp(self):
        self.home = Path(tempfile.mkdtemp())
        self._prev = os.environ.get("PRISMOR_HOME")
        os.environ["PRISMOR_HOME"] = str(self.home)
        self.workspace = Path(tempfile.mkdtemp())
        # No org opinion unless a test says otherwise.
        self._patch = mock.patch.object(unlock, "_org_self_edit", return_value={})
        self._patch.start()

    def tearDown(self):
        self._patch.stop()
        if self._prev is None:
            os.environ.pop("PRISMOR_HOME", None)
        else:
            os.environ["PRISMOR_HOME"] = self._prev


class TestCredential(UnlockTestCase):
    def test_not_configured_until_a_password_is_set(self):
        self.assertFalse(unlock.is_configured())
        ok, msg = unlock.verify(PASSWORD)
        self.assertFalse(ok)
        self.assertIn("--set-password", msg)

    def test_correct_password_verifies_and_wrong_one_does_not(self):
        unlock.set_password(PASSWORD)
        self.assertTrue(unlock.verify(PASSWORD)[0])
        self.assertFalse(unlock.verify("something else")[0])

    def test_password_is_not_recoverable_from_the_file(self):
        unlock.set_password(PASSWORD)
        text = unlock.credential_path().read_text()
        self.assertNotIn(PASSWORD, text)
        self.assertIn("scrypt", text)

    def test_credential_file_is_private(self):
        unlock.set_password(PASSWORD)
        self.assertEqual(unlock.credential_path().stat().st_mode & 0o777, 0o600)

    def test_system_method_stores_no_hash(self):
        unlock.set_password("", system=True)
        self.assertEqual(unlock.method(), "system")
        record = unlock.credential_path().read_text()
        self.assertNotIn("hash", record)

    def test_guessing_backs_off_after_repeated_failures(self):
        unlock.set_password(PASSWORD)
        for _ in range(6):
            unlock.verify("wrong")
        self.assertGreater(unlock.lockout_remaining(), 0)
        ok, msg = unlock.verify(PASSWORD)
        self.assertFalse(ok, "lockout must hold even for the right password")
        self.assertIn("try again", msg)

    def test_a_success_clears_the_failure_count(self):
        unlock.set_password(PASSWORD)
        for _ in range(3):
            unlock.verify("wrong")
        self.assertTrue(unlock.verify(PASSWORD)[0])
        for _ in range(3):
            unlock.verify("wrong")
        self.assertEqual(unlock.lockout_remaining(), 0)

    def test_first_password_needs_no_current(self):
        # Nothing to impersonate yet, so the first credential sets freely.
        self.assertFalse(unlock.is_configured())
        unlock.set_password(PASSWORD)
        self.assertTrue(unlock.verify(PASSWORD)[0])

    def test_changing_the_password_requires_the_current_one(self):
        unlock.set_password(PASSWORD)
        with self.assertRaises(PermissionError):
            unlock.set_password("new", current="wrong")
        with self.assertRaises(PermissionError):
            unlock.set_password("new")  # no proof at all
        self.assertTrue(unlock.verify(PASSWORD)[0], "the old password must still work")
        unlock.set_password("a new password", current=PASSWORD)
        self.assertTrue(unlock.verify("a new password")[0])

    def test_forgetting_the_password_closes_any_open_window(self):
        unlock.set_password(PASSWORD)
        unlock.open_window(workspace=self.workspace)
        self.assertTrue(unlock.is_open(self.workspace))
        unlock.clear_password()
        self.assertFalse(unlock.is_open(self.workspace))
        self.assertFalse(unlock.is_configured())


class TestWindow(UnlockTestCase):
    def setUp(self):
        super().setUp()
        unlock.set_password(PASSWORD)

    def test_closed_until_opened(self):
        self.assertFalse(unlock.is_open(self.workspace))

    def test_opens_and_closes(self):
        unlock.open_window(workspace=self.workspace)
        self.assertTrue(unlock.is_open(self.workspace))
        self.assertTrue(unlock.close_window())
        self.assertFalse(unlock.is_open(self.workspace))

    def test_default_window_is_three_minutes(self):
        unlock.open_window(workspace=self.workspace)
        self.assertLessEqual(unlock.remaining_seconds(self.workspace), 180)
        self.assertGreater(unlock.remaining_seconds(self.workspace), 170)

    def test_expiry_heals_itself(self):
        unlock.open_window(duration_seconds=60, workspace=self.workspace)
        with mock.patch.object(unlock, "_now", return_value=unlock.time.time() + 3600):
            self.assertFalse(unlock.is_open(self.workspace))
        self.assertFalse(
            unlock.grant_path().exists(),
            "a lapsed window should delete its marker, not linger",
        )

    def test_window_is_scoped_to_its_workspace(self):
        unlock.open_window(workspace=self.workspace)
        self.assertFalse(unlock.is_open(Path(tempfile.mkdtemp())))

    def test_forged_marker_is_rejected(self):
        # The whole point of the MAC: a grant nothing verified a password for.
        unlock.grant_path().write_text(
            '{"schema": "prismor.unlock-grant.v1", "at": "2020-01-01T00:00:00Z",'
            ' "until": "2999-01-01T00:00:00Z", "by": "x", "workspace": ""}'
        )
        self.assertFalse(unlock.is_open(self.workspace))

    def test_tampering_with_the_expiry_is_rejected(self):
        import json
        unlock.open_window(duration_seconds=60, workspace=self.workspace)
        record = json.loads(unlock.grant_path().read_text())
        record["until"] = "2999-01-01T00:00:00Z"  # keep the old MAC
        unlock.grant_path().write_text(json.dumps(record))
        self.assertFalse(unlock.is_open(self.workspace))

    def test_grant_does_not_survive_a_password_change(self):
        unlock.open_window(workspace=self.workspace)
        unlock.set_password("a different password", current=PASSWORD)
        self.assertFalse(
            unlock.is_open(self.workspace),
            "changing the password should invalidate windows it did not authorize",
        )

    def test_window_cannot_exceed_the_maximum(self):
        unlock.open_window(duration_seconds=99999, workspace=self.workspace)
        self.assertLessEqual(unlock.remaining_seconds(self.workspace), unlock.MAX_WINDOW_SECONDS)

    def test_a_correctly_signed_but_over_long_window_is_rejected(self):
        # The forge in the advisory: a grant whose MAC checks out (the key is
        # derived from a file the attacker can read) but whose window reaches
        # ten years. The cap is re-checked on read, so it never opens.
        import json
        key = unlock._grant_key()
        now = unlock._now()
        rec = {
            "schema": unlock._GRANT_SCHEMA,
            "at": unlock._iso(now),
            "until": unlock._iso(now + 10 * 365 * 86400),
            "by": "agent", "workspace": "",
        }
        rec["mac"] = unlock._mac(rec, key)
        unlock.grant_path().write_text(json.dumps(rec))
        self.assertFalse(
            unlock.is_open(self.workspace),
            "a window longer than the cap must be rejected even with a valid MAC",
        )


class TestOrgControls(UnlockTestCase):
    def setUp(self):
        super().setUp()
        unlock.set_password(PASSWORD)

    def _org(self, record):
        self._patch.stop()
        self._patch = mock.patch.object(unlock, "_org_self_edit", return_value=record)
        self._patch.start()

    def test_org_can_disable_self_edit_entirely(self):
        unlock.open_window(workspace=self.workspace)
        self._org({"enabled": False})
        self.assertTrue(unlock.org_self_edit_disabled())
        self.assertFalse(
            unlock.is_open(self.workspace),
            "an org disable must close a window that is already open",
        )

    def test_org_caps_the_window(self):
        self._org({"enabled": True, "window_seconds": 60})
        unlock.open_window(duration_seconds=600, workspace=self.workspace)
        self.assertLessEqual(unlock.remaining_seconds(self.workspace), 60)

    def test_org_silence_leaves_local_settings_alone(self):
        self._org({})
        self.assertFalse(unlock.org_self_edit_disabled())
        self.assertIsNone(unlock.org_max_window_seconds())


class TestSelfEditGate(UnlockTestCase):
    """What the window is for: `prismor allow` refuses self-protection rules
    whether or not it is open — the window lets the agent edit *policy*, never
    the mechanism that guards policy."""

    def setUp(self):
        super().setUp()
        unlock.set_password(PASSWORD)
        unlock.open_window(workspace=self.workspace)

    def test_self_protection_rules_stay_refused_inside_an_open_window(self):
        from prismor.runtime import allow
        from prismor.runtime.policy_engine import _SELF_PROTECTION_RULE_IDS
        with mock.patch(
            "prismor.runtime.enterprise.workspace_scope.is_managed", return_value=False
        ):
            for rule_id in _SELF_PROTECTION_RULE_IDS:
                self.assertIsNotNone(
                    allow.check_allowed(rule_id, scope="observe",
                                        workspace=self.workspace, confirmed=True),
                    f"{rule_id} must stay refused even while unlocked",
                )

    def test_ordinary_rules_are_editable(self):
        from prismor.runtime import allow
        with mock.patch(
            "prismor.runtime.enterprise.workspace_scope.is_managed", return_value=False
        ):
            self.assertIsNone(
                allow.check_allowed("risky-write", scope="pattern", workspace=self.workspace)
            )


class TestImportRouteIsBlocked(unittest.TestCase):
    """Opening the window by importing unlock, not running the CLI. The CLI is
    already blocked and gated; the import route must be a self-edit too."""

    def _blocks(self, command: str) -> bool:
        from prismor.runtime.hooks import should_block
        from prismor.runtime.policy_engine import PolicyEngine
        with tempfile.TemporaryDirectory() as tmp:
            eng = PolicyEngine(workspace=Path(tmp))
            findings = eng.evaluate({"type": "shell", "command": command}, index=0)
            return should_block(
                findings,
                {"type": "shell", "command": command, "agent_event": "PreToolUse"},
            ) is not None

    def test_from_module_import_open_window_blocks(self):
        self.assertTrue(self._blocks(
            'python3 -c "from prismor.runtime.unlock import open_window; open_window()"'))

    def test_module_alias_open_window_blocks(self):
        self.assertTrue(self._blocks(
            'python3 -c "from prismor.runtime import unlock; unlock.open_window()"'))

    def test_set_password_import_blocks(self):
        self.assertTrue(self._blocks(
            "python3 -c \"from prismor.runtime.unlock import set_password; set_password('x')\""))

    def test_dynamic_import_blocks(self):
        self.assertTrue(self._blocks(
            'python3 -c "m = __import__(\'prismor.runtime.unlock\'); ..."'))

    def test_ordinary_python_does_not_block(self):
        self.assertFalse(self._blocks('python3 -c "import json; print(json.dumps({}))"'))


if __name__ == "__main__":
    unittest.main()
