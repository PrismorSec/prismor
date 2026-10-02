"""Policy test harness — declarative test cases for Prismor rules.

Users author ``.prismor/policy-tests.yaml`` with a list of cases:

    tests:
      - name: rm -rf / must be blocked
        type: command
        input: "rm -rf /"
        expect: block                  # or: warn | pass
        expect_rule: destructive-command  # optional, stricter check
      - name: legitimate build cleanup should pass
        type: command
        input: "rm -rf ./node_modules"
        expect: pass
      - name: refunds over 500 need the finance role
        type: tool
        tool: refund_order
        args: {amount: 900}
        principal: {id: bob, roles: [support], verified: true}
        resource: {kind: order, id: o-1, attr: {owner: alice}}
        expect: block

``type: tool`` cases exercise ``when:`` rules: ``args``, ``principal`` and
``resource`` become the attributes the expression reads.

This is a lightweight pytest alternative that non-developer security
teams can run against a policy change in CI. Also used internally for
the starter test pack shipped as ``templates/policy-tests-owasp.yaml``.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from prismor.runtime.policy_engine import PolicyEngine

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore


def _verdict_from_findings(findings: List[Dict[str, Any]]) -> str:
    """Reduce a finding list to a single verdict string."""
    if not findings:
        return "pass"
    if any(f.get("action") == "block" for f in findings):
        return "block"
    if any(f.get("action") == "warn" for f in findings):
        return "warn"
    return "pass"


def _tool_case_event(case: Dict[str, Any]):
    """(event, subject) for a ``type: tool`` case."""
    from prismor.runtime.principal import Subject

    args = case.get("args") or {}
    p = case.get("principal") or {}
    subject = Subject(
        user_id=p.get("id"), team_id=p.get("team"), org_id=p.get("org"),
        source=str(p.get("source") or ("jwt" if p.get("verified") else "explicit")),
        roles=tuple(str(r) for r in p.get("roles") or ()),
        claims=dict(p.get("claims") or {}),
        verified=bool(p.get("verified")),
    )
    event = {
        "type": case.get("event_type", "shell"),
        "command": " ".join(str(v) for v in args.values() if v is not None),
        "metadata": {
            "tool_name": str(case.get("tool") or ""),
            "kwargs": args,
            "resource": case.get("resource") or {},
        },
    }
    return event, subject


def run_cases(
    cases: List[Dict[str, Any]],
    workspace: Optional[Path] = None,
) -> Dict[str, Any]:
    """Execute each test case against the current policy.

    Returns ``{total, passed, failed, results: [...]}``.
    Each result: ``{name, status: ok|fail, expected, got, matched_rules}``.
    """
    engine = PolicyEngine(workspace=workspace)
    results: List[Dict[str, Any]] = []
    passed = 0

    for i, case in enumerate(cases):
        name = str(case.get("name") or f"case-{i+1}")
        typ = case.get("type", "command")
        value = case.get("input", "")
        expected = str(case.get("expect", "pass")).lower()
        expected_rule = case.get("expect_rule")

        if typ == "command":
            findings = engine.check_command(value)
        elif typ in ("read", "write"):
            event_type = "file_read" if typ == "read" else "file_write"
            findings = engine.check_path(value, event_type=event_type)
        elif typ == "tool":
            event, subject = _tool_case_event(case)
            findings = engine.evaluate(event, 0, session_id="policy-test", subject=subject)
        else:
            results.append({
                "name": name, "status": "fail",
                "expected": expected, "got": f"unknown-type:{typ}",
                "matched_rules": [],
            })
            continue

        got = _verdict_from_findings(findings)
        matched = sorted({str(f.get("ruleId", "?")) for f in findings})
        ok = got == expected
        if ok and expected_rule:
            ok = expected_rule in matched
        if ok:
            passed += 1
        results.append({
            "name": name,
            "status": "ok" if ok else "fail",
            "expected": expected,
            "expected_rule": expected_rule,
            "got": got,
            "matched_rules": matched,
            "input": value,
            "type": typ,
        })

    return {
        "total": len(cases),
        "passed": passed,
        "failed": len(cases) - passed,
        "results": results,
    }


def load_cases(path: Path) -> List[Dict[str, Any]]:
    """Load policy-tests.yaml from ``path``."""
    if yaml is None:
        raise RuntimeError("PyYAML is required for policy tests")
    if not path.exists():
        raise FileNotFoundError(str(path))
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    tests = data.get("tests") or []
    if not isinstance(tests, list):
        raise ValueError(f"{path}: 'tests' must be a list")
    return tests
