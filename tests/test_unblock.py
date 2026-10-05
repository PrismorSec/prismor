"""Tests for the human-facing unblock steps printed alongside a block."""

import os
import sys
import unittest
from pathlib import Path

import yaml

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prismor.runtime import unblock
from prismor.runtime.policy_engine import PolicyEngine


def _finding(**over):
    base = {
        "ruleId": "secret-access",
        "severity": "HIGH",
        "category": "secret_access",
        "title": "Flags reads/writes to .env",
        "evidence": "/home/u/.ssh/id_rsa",
        "pattern": r"\.ssh/id_rsa",
    }
    base.update(over)
    return base


class TestFloorDetection(unittest.TestCase):
    def test_core_rule_id_is_floor(self):
        self.assertTrue(unblock.is_floor(_finding(ruleId="destructive-command")))

    def test_core_category_is_floor(self):
        self.assertTrue(
            unblock.is_floor(_finding(ruleId="curl-pipe-sh", category="remote_execution"))
        )

    def test_ordinary_rule_is_not_floor(self):
        self.assertFalse(unblock.is_floor(_finding()))

    def test_floor_set_is_read_from_the_engine_not_copied(self):
        """Guards drift: a rule added to the engine's floor must not need an edit here."""
        from prismor.runtime.policy_engine import _NON_OVERRIDABLE_RULE_IDS

        for rule_id in _NON_OVERRIDABLE_RULE_IDS:
            self.assertTrue(unblock.is_floor(_finding(ruleId=rule_id, category="x")), rule_id)


class TestOrdinaryRuleSteps(unittest.TestCase):
    def setUp(self):
        self.steps = unblock.unblock_steps(_finding(), workspace=Path("/w"))

    def test_narrowest_option_comes_first(self):
        joined = "\n".join(self.steps)
        self.assertLess(joined.index("Allow only this case"), joined.index("--observe"))
        self.assertLess(joined.index("--observe"), joined.index("--off"))

    def test_each_rung_is_a_command_the_user_can_run(self):
        # The ladder is only useful if the narrow rung is the easy one; a step
        # that says "paste this YAML" loses to "turn Prismor off".
        joined = "\n".join(self.steps)
        self.assertIn("prismor allow secret-access --pattern", joined)
        self.assertIn("prismor allow secret-access --observe", joined)

    def test_pattern_is_prefilled_from_the_evidence(self):
        joined = "\n".join(unblock.unblock_steps(
            _finding(evidence="/home/u/.ssh/id_rsa"), workspace=Path("/w")))
        self.assertIn(r"/home/u/\.ssh/id_rsa", joined)

    def test_names_the_policy_file(self):
        self.assertIn("/w/.prismor/policy.yaml", "\n".join(self.steps))


class TestSuggestedYamlIsValid(unittest.TestCase):
    """The snippet is meant to be pasted verbatim — it must parse and work."""

    def _doc(self, finding):
        return "version: '1.0'\n" + "\n".join(
            unblock._allowlist_yaml(finding["ruleId"], finding)
        ) + "\n"

    def test_allowlist_snippet_parses(self):
        parsed = yaml.safe_load(self._doc(_finding()))
        entry = parsed["allowlists"][0]
        self.assertEqual(entry["rule_ids"], ["secret-access"])

    def test_backslashes_survive_yaml_roundtrip(self):
        """Regex patterns are backslash-heavy; double-quoted YAML would reject them."""
        parsed = yaml.safe_load(self._doc(_finding(evidence="/home/u/.ssh/id_rsa")))
        self.assertEqual(parsed["allowlists"][0]["patterns"], [r"/home/u/\.ssh/id_rsa"])

    def test_quote_in_evidence_does_not_break_yaml(self):
        parsed = yaml.safe_load(self._doc(_finding(evidence="echo 'hi'")))
        self.assertIn("patterns", parsed["allowlists"][0])

    def test_multi_field_evidence_does_not_fold_into_a_dead_pattern(self):
        """Evidence joins matched fields with newlines; YAML folds those to spaces."""
        finding = _finding(evidence="/home/u/.ssh/id_rsa\n/Volumes/Data/home/u/.ssh/id_rsa")
        pattern = yaml.safe_load(self._doc(finding))["allowlists"][0]["patterns"][0]
        self.assertNotIn(" ", pattern)
        # Must still match the full multi-field blob it was derived from.
        import re

        self.assertTrue(re.search(pattern, finding["evidence"]))

    def test_suggested_allowlist_actually_suppresses_the_finding(self):
        """End-to-end: the snippet we print must clear the block it was printed for."""
        engine = PolicyEngine()
        before = engine.check_path("/home/u/.ssh/id_rsa", "file_read")
        rule_ids = [f["ruleId"] for f in before]
        self.assertIn("secret-access", rule_ids)

        finding = next(f for f in before if f["ruleId"] == "secret-access")
        snippet = yaml.safe_load(self._doc(finding))
        engine.allowlists.append(
            __import__(
                "prismor.runtime.policy_engine", fromlist=["AllowlistEntry"]
            ).AllowlistEntry(snippet["allowlists"][0])
        )

        after = [f["ruleId"] for f in engine.check_path("/home/u/.ssh/id_rsa", "file_read")]
        self.assertNotIn("secret-access", after)

        # ...and stays narrow: a different secret path still fires.
        other = [f["ruleId"] for f in engine.check_path("/home/u/.aws/credentials", "file_read")]
        self.assertIn("secret-access", other)


class TestFloorSteps(unittest.TestCase):
    def test_does_not_offer_an_override_that_would_be_ignored(self):
        joined = "\n".join(unblock.unblock_steps(_finding(ruleId="destructive-command")))
        self.assertIn("floor rule", joined)
        # It may *mention* the knobs to say they are ignored, but must never
        # hand over a snippet that looks like it would work.
        self.assertIn("will not clear this block", joined)
        self.assertNotIn("allowlists:", joined)
        self.assertNotIn("prismor policy edit", joined)

    def test_unreadable_pattern_is_not_dumped_verbatim(self):
        joined = "\n".join(
            unblock.unblock_steps(_finding(ruleId="destructive-command", pattern="x" * 300))
        )
        self.assertNotIn("x" * 300, joined)
        self.assertIn("prismor policy show", joined)

    def test_exemption_offered_only_when_enrolled(self):
        f = _finding(ruleId="destructive-command")
        self.assertNotIn("exempt request", "\n".join(unblock.unblock_steps(f)))
        self.assertIn("exempt request", "\n".join(unblock.unblock_steps(f, enrolled=True)))


class TestSubsystemSteps(unittest.TestCase):
    def test_scoped_agent_names_the_session(self):
        joined = "\n".join(
            unblock.unblock_steps(_finding(ruleId="scoped-agent"), session_id="sess-9")
        )
        self.assertIn("prismor scope clear sess-9", joined)

    def test_iam_points_at_identity_not_policy(self):
        joined = "\n".join(unblock.unblock_steps(_finding(ruleId="iam"), workspace=Path("/w")))
        self.assertIn("iam.yaml", joined)
        self.assertNotIn("allowlists:", joined)

    def test_trifecta_relaxes_tags_not_the_finding(self):
        joined = "\n".join(
            unblock.unblock_steps(
                _finding(ruleId="tool-category-crossover", category="lethal_trifecta")
            )
        )
        self.assertIn("tool_tags", joined)

    def test_agent_disabled_defers_to_the_layer_that_paused_it(self):
        """A paused agent is a kill switch, not a rule — an allowlist does nothing."""
        joined = "\n".join(
            unblock.unblock_steps(
                _finding(
                    ruleId="agent-disabled",
                    category="agent-control",
                    title="Agent is paused",
                    evidence="agent 'ci' is paused by your org's control plane",
                    remediation="Ask an org admin to re-enable 'ci' in the dashboard's fleet view.",
                )
            )
        )
        self.assertIn("org admin", joined)
        self.assertNotIn("allowlists:", joined)
        self.assertNotIn("mode: observe", joined)

    def test_cloaking_steers_to_cloak_run_not_a_policy_edit(self):
        joined = "\n".join(unblock.unblock_steps(_finding(ruleId="codex-cloak-read-guard")))
        self.assertIn("prismor cloak run", joined)
        self.assertNotIn("allowlists:", joined)


class TestOrgManaged(unittest.TestCase):
    def test_warns_that_a_local_override_may_be_overwritten(self):
        joined = "\n".join(unblock.unblock_steps(_finding(), org_managed=True))
        self.assertIn("exempt request", joined)

    def test_personal_workspace_gets_no_admin_noise(self):
        self.assertNotIn("exempt request", "\n".join(unblock.unblock_steps(_finding())))


class TestFormatting(unittest.TestCase):
    def test_addressed_to_the_human(self):
        text = unblock.format_unblock(_finding())
        self.assertIn("for the human", text)

    def test_unknown_rule_yields_nothing_rather_than_guesswork(self):
        self.assertEqual(unblock.format_unblock(_finding(ruleId="")), "")
        self.assertEqual(unblock.format_unblock(_finding(ruleId="unknown")), "")


class EgressStepsTest(unittest.TestCase):
    """Egress verdicts live in settings.egress, so `prismor allow <rule>` cannot clear them."""

    def _steps(self, rule_id):
        return "\n".join(unblock.unblock_steps(
            _finding(ruleId=rule_id, category="network_isolation", egressHost="api.example.dev"),
            workspace=Path("/w"),
        ))

    def test_off_allowlist_points_at_egress_allow_with_the_host(self):
        joined = self._steps("egress-allowlist")
        self.assertIn("prismor egress allow api.example.dev", joined)
        self.assertNotIn("prismor allow egress-allowlist", joined)

    def test_explicit_deny_points_at_egress_rm(self):
        joined = self._steps("egress-deny")
        self.assertIn("prismor egress rm", joined)
        self.assertNotIn("prismor allow egress-deny", joined)


if __name__ == "__main__":
    unittest.main()
