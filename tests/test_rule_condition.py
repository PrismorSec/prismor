"""Tests for the optional per-rule `condition:` expression.

A rule may name groups of patterns and combine them with a boolean expression
instead of the default "any pattern wins" alternation:

    pattern_groups:
      benign: ['localhost']
    condition: "patterns and not benign"

Two properties matter more than the feature itself and are pinned hardest here:

  1. Opt-in. A rule with no `condition:` behaves exactly as before.
  2. It can only narrow, never widen — so it is refused outright on the
     non-overridable floor, where narrowing would be a bypass.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prismor.runtime.policy_engine import (
    _CORE_BLOCK_CATEGORIES,
    _NON_OVERRIDABLE_RULE_IDS,
    CompiledRule,
    ConditionError,
    PolicyEngine,
    RuleCondition,
)

_BASE = dict(id="t", severity="HIGH", category="reconnaissance", title="T",
             event_types=["shell"], fields=["command"])


def mk(**kw):
    return CompiledRule({**_BASE, **kw})


class TestBackwardCompatibility(unittest.TestCase):
    def test_rule_without_condition_is_untouched(self):
        rule = mk(patterns=["curl"])
        self.assertIsNone(rule.condition)
        self.assertEqual(rule.pattern_groups, {})

    def test_only_known_shipped_rules_use_a_condition(self):
        # The bundled policy must not have *quietly* grown conditions. A rule
        # added here is an explicit, reviewed decision; anything else showing up
        # is the drift this canary exists to catch.
        #
        # memory-directive-on-write needs one structurally: it fires on
        # file_write, where `combined_text` carries the written content, so
        # without `condition: "patterns and instruction_file"` it would flag any
        # document that merely discusses directive phrasing — including the
        # policy file that defines the patterns.
        #
        # skill-self-persist needs one for the same reason: it fires on
        # tool_result / file_write content, and "install this skill" is normal
        # skill prose — only the remote-fetch AND overwrite AND auto-load
        # combination is the remote-controlled-instructions shape it targets.
        #
        # ci-workflow-remote-exec: `curl | sh` is ordinary in install scripts and
        # docs; only inside a CI workflow file does it run with the repo's secrets.
        expected = {"memory-directive-on-write", "skill-self-persist", "ci-workflow-remote-exec"}
        engine = PolicyEngine()
        actual = {r.id for r in engine.rules if r.condition is not None}
        self.assertEqual(actual, expected)

    def test_pattern_groups_alone_do_nothing_without_a_condition(self):
        rule = mk(patterns=["curl"], pattern_groups={"x": ["nope"]})
        self.assertIsNone(rule.condition)


class TestConditionSemantics(unittest.TestCase):
    def test_false_positive_suppression(self):
        rule = mk(patterns=[r"curl\s+http"],
                  pattern_groups={"benign": [r"localhost|127\.0\.0\.1"]},
                  condition="patterns and not benign")
        self.assertIsNotNone(rule.evaluate_condition(["curl http://evil.example"]))
        self.assertIsNone(rule.evaluate_condition(["curl http://localhost:3000/health"]))

    def test_conjunction_across_two_groups(self):
        rule = mk(patterns=["x"], pattern_groups={"verb": ["curl"], "target": [r"\.env"]},
                  condition="verb and target")
        self.assertIsNotNone(rule.evaluate_condition(["curl .env"]))
        self.assertIsNone(rule.evaluate_condition(["curl example.com"]))
        self.assertIsNone(rule.evaluate_condition(["cat .env"]))

    def test_disjunction(self):
        rule = mk(patterns=["x"], pattern_groups={"a": ["aws"], "b": ["gcp"]},
                  condition="any of (a, b)")
        self.assertIsNotNone(rule.evaluate_condition(["aws configure"]))
        self.assertIsNotNone(rule.evaluate_condition(["gcp auth"]))
        self.assertIsNone(rule.evaluate_condition(["echo hi"]))

    def test_all_of_quantifier(self):
        rule = mk(patterns=["x"], pattern_groups={"a": ["aws"], "b": ["gcp"]},
                  condition="all of (a, b)")
        self.assertIsNotNone(rule.evaluate_condition(["aws and gcp"]))
        self.assertIsNone(rule.evaluate_condition(["aws only"]))

    def test_n_of_quantifier(self):
        rule = mk(patterns=["x"],
                  pattern_groups={"a": ["curl"], "b": [r"\.env"], "c": ["base64"]},
                  condition="2 of (a, b, c)")
        self.assertIsNone(rule.evaluate_condition(["curl example.com"]))
        self.assertIsNotNone(rule.evaluate_condition(["curl .env"]))
        self.assertIsNotNone(rule.evaluate_condition(["curl .env | base64"]))

    def test_condition_may_be_satisfied_across_different_fields(self):
        rule = mk(fields=["command", "path"], patterns=["x"],
                  pattern_groups={"verb": ["curl"], "target": [r"\.env"]},
                  condition="verb and target")
        self.assertIsNotNone(rule.evaluate_condition(["curl example.com", "/app/.env"]))

    def test_evidence_is_a_matching_field_value(self):
        rule = mk(patterns=[r"curl\s+http"], pattern_groups={"benign": ["localhost"]},
                  condition="patterns and not benign")
        self.assertEqual(rule.evaluate_condition(["curl http://evil.example"]),
                         "curl http://evil.example")


class TestFloorCannotBeNarrowed(unittest.TestCase):
    """A condition only ever narrows, so the floor must refuse it outright."""

    _NARROW = dict(severity="CRITICAL", title="T", event_types=["shell"],
                   fields=["command"], patterns=[r"rm\s+-rf"],
                   pattern_groups={"never": ["ZZZ_NEVER_MATCHES"]},
                   condition="patterns and never")

    def test_protected_rule_ids_refuse_a_condition(self):
        for rule_id in _NON_OVERRIDABLE_RULE_IDS:
            rule = CompiledRule({**self._NARROW, "id": rule_id, "category": "reconnaissance"})
            self.assertIsNone(rule.condition, f"{rule_id} accepted a narrowing condition")

    def test_protected_categories_refuse_a_condition(self):
        for category in _CORE_BLOCK_CATEGORIES:
            rule = CompiledRule({**self._NARROW, "id": "x-rule", "category": category})
            self.assertIsNone(rule.condition, f"{category} accepted a narrowing condition")

    def test_a_refused_condition_leaves_detection_fully_intact(self):
        rule = CompiledRule({**self._NARROW, "id": "destructive-command",
                             "category": "destructive_command"})
        self.assertIsNone(rule.condition)
        self.assertTrue(rule.patterns.search("rm -rf /"))

    def test_ordinary_rules_still_accept_a_condition(self):
        rule = CompiledRule({**self._NARROW, "id": "ordinary", "category": "reconnaissance"})
        self.assertIsNotNone(rule.condition)


class TestConditionIsNotCodeExecution(unittest.TestCase):
    """The expression parser must reject everything that is not boolean logic."""

    HOSTILE = [
        '__import__("os").system("id")',
        'open("/etc/passwd").read()',
        "a.__class__",
        "a if b else c",
        "a == 1",
        "lambda: 1",
        "a + b",
        "[x for x in y]",
        'a and eval("1")',
        "a.attr",
        "f'{a}'",
    ]

    def test_hostile_expressions_are_rejected(self):
        for expr in self.HOSTILE:
            with self.assertRaises(ConditionError, msg=f"accepted: {expr}"):
                RuleCondition(expr, {"a", "b", "c"})

    def test_unknown_group_is_rejected(self):
        with self.assertRaises(ConditionError):
            RuleCondition("a and typo", {"a"})

    def test_condition_with_no_groups_is_rejected(self):
        with self.assertRaises(ConditionError):
            RuleCondition("not (1 and 2)", {"a"})


class TestMalformedConditionFailsTowardDetection(unittest.TestCase):
    """A broken condition must never silently disable a rule."""

    def test_syntax_error_drops_the_condition_and_keeps_patterns(self):
        rule = mk(patterns=["curl"], condition="patterns and and")
        self.assertIsNone(rule.condition)
        self.assertTrue(rule.patterns.search("curl example.com"))

    def test_unknown_group_drops_the_condition_and_keeps_patterns(self):
        rule = mk(patterns=["curl"], condition="patterns and nonexistent")
        self.assertIsNone(rule.condition)
        self.assertTrue(rule.patterns.search("curl example.com"))

    def test_invalid_group_regex_is_skipped_not_fatal(self):
        rule = mk(patterns=["curl"], pattern_groups={"bad": ["([unclosed"]},
                  condition="patterns")
        self.assertIsNotNone(rule.condition)
        self.assertNotIn("bad", rule.pattern_groups)


class TestConditionRulesStillGetEvasionRescan(unittest.TestCase):
    """The homoglyph fallback must cover condition rules too."""

    def test_folded_text_satisfies_a_condition(self):
        rule = mk(patterns=[r"curl\s+http"], pattern_groups={"benign": ["localhost"]},
                  condition="patterns and not benign")
        # Cyrillic 'с' in "сurl" — the raw text cannot match.
        self.assertIsNone(rule.evaluate_condition(["сurl http://evil.example"]))
        from prismor.runtime.policy_engine import _fold_confusables
        folded = _fold_confusables("сurl http://evil.example")
        self.assertIsNotNone(rule.evaluate_condition([folded]))


if __name__ == "__main__":
    unittest.main()
