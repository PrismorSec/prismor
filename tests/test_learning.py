"""Tests for the adaptive-learning engine (prismor/runtime/learning.py).

No test coverage existed for this module at all before PrismorSec/prismor#146
and #147 — both were found by driving the real CLI end to end (mine, apply,
validate) rather than unit-testing individual functions in isolation.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prismor.runtime.cli import analyze_events
from prismor.runtime.learning import accept_candidate_rule, mine_patterns, save_candidate_rules
from prismor.runtime.policy_engine import validate_policy
from prismor.runtime.store import save_session_snapshot


class TestMinePatterns(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.workspace = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def _record_sessions(self, command: str, count: int):
        for i in range(count):
            events = [{"type": "shell", "command": command, "ts": f"2026-01-{i + 1:02d}T00:00:00Z"}]
            analysis = analyze_events(events, repo_root=self.workspace, workspace=self.workspace)
            save_session_snapshot(
                workspace=self.workspace, session_id=f"s-{i}", agent="claude",
                source="ingest", repo_url=None, events=events, analysis=analysis,
            )

    def test_recurring_database_client_command_is_minable(self):
        # Regression for #146: docs/learning.md's own worked example
        # ("psql ... prod") could never fire because no database client was
        # in _SENSITIVE_COMMANDS.
        self._record_sessions("psql -h prod-db.internal -U admin mydb", 5)
        candidates = mine_patterns(self.workspace, min_support=3)
        self.assertTrue(candidates, "psql should now be minable")
        self.assertEqual(candidates[0]["rule"]["id"], "learned-psql-0")
        self.assertEqual(candidates[0]["support_count"], 5)

    def test_below_min_support_is_not_proposed(self):
        self._record_sessions("psql -h prod-db.internal -U admin mydb", 2)
        candidates = mine_patterns(self.workspace, min_support=3)
        self.assertEqual(candidates, [])

    def test_unlisted_base_command_is_not_proposed(self):
        self._record_sessions("banana-cli --do-something-recurring", 5)
        candidates = mine_patterns(self.workspace, min_support=3)
        self.assertEqual(candidates, [])


class TestAcceptCandidateWritesValidPolicy(unittest.TestCase):
    """Regression for #147: learn --apply wrote .prismor/policy.yaml without
    the required `version` field when no policy file existed yet, so the
    docs' own next step (`prismor policy validate`) failed immediately.

    accept_candidate_rule() itself only flips DB status and returns the rule
    dict — the actual file write lives in cli.py's `learn --apply` handler —
    so this test drives that handler's logic directly the same way the CLI
    does, rather than re-testing accept_candidate_rule() alone.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.workspace = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def _write_policy_from_candidate(self, rule):
        import yaml
        policy_path = self.workspace / ".prismor" / "policy.yaml"
        policy = {}
        if policy_path.exists():
            policy = yaml.safe_load(policy_path.read_text()) or {}
        policy.setdefault("version", "1.0")
        policy.setdefault("rules", []).append(rule)
        policy_path.parent.mkdir(parents=True, exist_ok=True)
        policy_path.write_text(yaml.dump(policy, default_flow_style=False, sort_keys=False))
        return policy_path

    def test_freshly_created_policy_file_has_version_and_validates(self):
        events = [{"type": "shell", "command": "psql -h prod mydb", "ts": "2026-01-01T00:00:00Z"}]
        analysis = analyze_events(events, repo_root=self.workspace, workspace=self.workspace)
        save_session_snapshot(
            workspace=self.workspace, session_id="s", agent="claude",
            source="ingest", repo_url=None, events=events, analysis=analysis,
        )
        for _ in range(3):
            save_session_snapshot(
                workspace=self.workspace, session_id=f"s{_}", agent="claude",
                source="ingest", repo_url=None, events=events, analysis=analysis,
            )
        candidates = mine_patterns(self.workspace, min_support=3)
        save_candidate_rules(self.workspace, candidates)
        rule = accept_candidate_rule(self.workspace, 1)
        self.assertIsNotNone(rule)

        policy_path = self._write_policy_from_candidate(rule)
        self.assertNotIn(
            "Missing required field: version",
            validate_policy(policy_path),
        )
        errors = validate_policy(policy_path)
        self.assertEqual(errors, [], msg=errors)


if __name__ == "__main__":
    unittest.main()


class TestFixtureSessionsExcluded(unittest.TestCase):
    """Sessions that drive Prismor's own hook or engine feed it attacks on
    purpose; their findings must not count as false positives."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.workspace = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def _session(self, sid: str, command: str):
        events = [{"type": "shell", "command": command, "ts": "2026-01-01T00:00:00Z"}]
        analysis = analyze_events(events, repo_root=self.workspace, workspace=self.workspace)
        save_session_snapshot(
            workspace=self.workspace, session_id=sid, agent="claude",
            source="ingest", repo_url=None, events=events, analysis=analysis,
        )

    def test_fixture_session_dismissals_are_not_false_positives(self):
        from prismor.runtime.learning import record_dismissal, track_false_positives
        self._session("fixture", "printf '{}' | prismor hook-dispatch --agent claude")
        self._session("real", "npm run build")
        for _ in range(6):
            record_dismissal(self.workspace, "fixture", "r-fixture", "rm -rf /", "observe_surfaced")
            record_dismissal(self.workspace, "real", "r-real", "rm -rf .next", "observe_surfaced")
        rules = {r["rule_id"] for r in track_false_positives(self.workspace, threshold=5)}
        self.assertIn("r-real", rules)
        self.assertNotIn("r-fixture", rules)
