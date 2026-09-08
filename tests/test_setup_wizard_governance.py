"""`prismor setup` wiring for the governance modes.

Choosing "enforce" now offers a mode (dev-safe / trusted-workspace /
regulated-airgap) as well as the existing rule-by-rule "custom" picker.
Picking a named mode skips the rule-selection step and compiles that mode's
policy at install time instead of writing the manual selection.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prismor.runtime import setup_wizard
from prismor.runtime.modes import load_modes


class TestWizardSteps(unittest.TestCase):
    def test_observe_has_no_governance_step(self):
        steps = setup_wizard._wizard_steps("observe", None, offer_unlock=False)
        self.assertNotIn("governance", steps)
        self.assertNotIn("policy_select", steps)
        self.assertEqual(steps, ["mode", "agents", "cloak", "scope", "confirm"])

    def test_enforce_undecided_assumes_custom(self):
        steps = setup_wizard._wizard_steps("enforce", None, offer_unlock=False)
        self.assertEqual(
            steps, ["mode", "governance", "policy_select", "agents", "cloak", "scope", "confirm"]
        )

    def test_enforce_custom_keeps_rule_picker(self):
        steps = setup_wizard._wizard_steps("enforce", "custom", offer_unlock=False)
        self.assertIn("policy_select", steps)

    def test_enforce_named_mode_skips_rule_picker(self):
        mode_id = next(iter(load_modes()))
        steps = setup_wizard._wizard_steps("enforce", mode_id, offer_unlock=True)
        self.assertNotIn("policy_select", steps)
        self.assertEqual(
            steps, ["mode", "governance", "agents", "cloak", "scope", "unlock", "confirm"]
        )


class TestInstallCompilesMode(unittest.TestCase):
    def setUp(self):
        self.target = Path(tempfile.mkdtemp())

    def test_named_mode_writes_a_compiled_policy(self):
        mode_id = next(iter(load_modes()))
        with mock.patch("prismor.runtime.setup_wizard._REPO_ROOT", Path("/nonexistent")):
            setup_wizard._do_install(
                self.target, "enforce", rules=[], agents=[], cloak=False,
                scope="project", gov_mode=mode_id,
            )
        policy = (self.target / ".prismor" / "policy.yaml").read_text(encoding="utf-8")
        self.assertIn(f"mode: {mode_id}", policy)

    def test_install_on_a_host_with_no_docker_keeps_the_posture(self):
        """The wizard used to pass force=True, which ALSO skipped the runtime
        check, so setup wrote an enforcing sandbox onto a host with no Docker —
        strictly more dangerous than the `mode apply` it wraps. Now the sandbox
        axis degrades and everything else still lands."""
        with mock.patch("prismor.runtime.setup_wizard._REPO_ROOT", Path("/nonexistent")), \
             mock.patch("prismor.runtime.sandbox.docker_status",
                        new=lambda: {"cli_found": False, "server_reachable": False,
                                     "error": "docker CLI not found"}), \
             mock.patch("prismor.runtime.enterprise.workspace_scope.is_managed",
                        return_value=False):
            setup_wizard._do_install(
                self.target, "enforce", rules=[], agents=[], cloak=False,
                scope="project", gov_mode="dev-safe",
            )
        written = yaml.safe_load(
            (self.target / ".prismor" / "policy.yaml").read_text(encoding="utf-8")
        )
        settings = written.get("settings") or {}
        self.assertEqual(settings.get("mode_id"), "dev-safe")
        self.assertEqual((settings.get("sandbox") or {}).get("mode"), "observe")
        # Not the blunt observe build: the rules and egress must still enforce.
        self.assertNotIn("mode_observe", settings)
        self.assertEqual((settings.get("egress") or {}).get("default"), "deny")
        self.assertTrue([r for r in written.get("rules") or []
                         if r.get("mode") == "enforce"])


if __name__ == "__main__":
    unittest.main()
