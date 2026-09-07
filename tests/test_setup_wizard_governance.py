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

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prismor.runtime import setup_wizard
from prismor.runtime.modes import ModeError, load_modes


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

    def test_docker_unavailable_falls_back_to_observe_build(self):
        mode_id = next(iter(load_modes()))

        def _refuse_enforce(workspace, mid, force=False, observe=False):
            if not observe:
                raise ModeError("Docker is not reachable")
            path = workspace / ".prismor" / "policy.yaml"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"# observe build of {mid}\n", encoding="utf-8")
            return path, []

        with mock.patch("prismor.runtime.setup_wizard._REPO_ROOT", Path("/nonexistent")), \
             mock.patch("prismor.runtime.modes.apply_mode", side_effect=_refuse_enforce):
            setup_wizard._do_install(
                self.target, "enforce", rules=[], agents=[], cloak=False,
                scope="project", gov_mode=mode_id,
            )
        policy = (self.target / ".prismor" / "policy.yaml").read_text(encoding="utf-8")
        self.assertIn("observe build", policy)


if __name__ == "__main__":
    unittest.main()
