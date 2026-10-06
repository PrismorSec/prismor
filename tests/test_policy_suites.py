"""`prismor policy test` suites: fixtures, principal matrices, skip, filter,
--policy with embedded tests, --json — run through the real CLI."""

import json
import subprocess
import sys

import yaml

from prismor.runtime.policy_test import expand_cases, run_cases

POLICY = {
    "version": "1.0",
    "settings": {"conditions": {"is_finance": "'finance' in principal.roles"}},
    "rules": [{
        "id": "refund-cap", "severity": "HIGH", "category": "custom-authz",
        "title": "Large refunds need finance", "event_types": ["shell"], "fields": ["tool_name"],
        "patterns": ["^refund_order$"], "action": "block", "mode": "enforce",
        "when": "args.amount >= 500 and not is_finance",
    }],
}
FIXTURES = {
    "principals": {"bob": {"id": "bob", "roles": ["support"], "verified": True},
                   "carol": {"id": "carol", "roles": ["finance"], "verified": True},
                   "anon": {}},
    "resources": {"o1": {"kind": "order", "id": "o-1", "attr": {"owner": "alice"}}},
}
TESTS = [
    {"name": "big refund", "tool": "refund_order", "args": {"amount": 900}, "resource": "o1",
     "expect": {"bob": "block", "carol": "pass", "anon": "block"}, "expect_rule": "refund-cap"},
    {"name": "small refund", "tool": "refund_order", "args": {"amount": 5}, "principal": "bob", "expect": "pass"},
    {"name": "todo", "skip": True, "skip_reason": "later"},
]


def test_matrix_expands_one_case_per_principal():
    names = [c["name"] for c in expand_cases(TESTS, FIXTURES)]
    assert names[:3] == ["big refund [bob]", "big refund [carol]", "big refund [anon]"]


def test_unknown_fixture_is_a_failure_not_a_crash():
    out = expand_cases([{"name": "x", "tool": "t", "principal": "ghost"}], FIXTURES)
    assert "unknown principal fixture 'ghost'" in out[0]["_error"]


def test_run_suite(tmp_path):
    pol = tmp_path / "policy.yaml"
    pol.write_text(yaml.safe_dump(POLICY))
    r = run_cases(TESTS, workspace=tmp_path, fixtures=FIXTURES, policy_path=pol)
    assert (r["total"], r["passed"], r["failed"], r["skipped"]) == (5, 4, 0, 1), r
    r = run_cases(TESTS, workspace=tmp_path, fixtures=FIXTURES, policy_path=pol, name_filter="*[carol]")
    assert r["total"] == 1 and r["passed"] == 1


def _cli(tmp_path, *args):
    return subprocess.run([sys.executable, "-m", "prismor.runtime.cli", "policy", "test",
                           "--workspace", str(tmp_path), *args],
                          capture_output=True, text=True, env={"PRISMOR_HOME": str(tmp_path / "home"),
                                                               "PATH": "/usr/bin:/bin"})


def test_cli_policy_with_embedded_tests_and_sibling_fixtures(tmp_path):
    (tmp_path / "policies").mkdir()
    pol = tmp_path / "policies" / "support-bot.yaml"
    pol.write_text(yaml.safe_dump({**POLICY, "tests": TESTS}))
    (tmp_path / "policies" / "policy-fixtures.yaml").write_text(yaml.safe_dump(FIXTURES))
    p = _cli(tmp_path, "--policy", str(pol), "--json")
    assert p.returncode == 0, p.stdout + p.stderr
    assert json.loads(p.stdout)["passed"] == 4


def test_cli_fails_ci_on_a_wrong_expectation(tmp_path):
    pol = tmp_path / "p.yaml"
    bad = [{**TESTS[0], "expect": {"carol": "block"}}]
    pol.write_text(yaml.safe_dump({**POLICY, "tests": bad, "fixtures": FIXTURES}))
    p = _cli(tmp_path, "--policy", str(pol))
    assert p.returncode == 1
    assert "FAIL" in p.stdout and "big refund [carol]" in p.stdout


def test_engine_ignores_tests_and_fixtures_keys(tmp_path):
    from prismor.runtime.policy_engine import PolicyEngine, validate_policy
    pol = tmp_path / "p.yaml"
    pol.write_text(yaml.safe_dump({**POLICY, "tests": TESTS, "fixtures": FIXTURES}))
    assert "refund-cap" in {r.id for r in PolicyEngine(workspace=tmp_path, policy_path=pol).rules}
    assert validate_policy(pol) == []
