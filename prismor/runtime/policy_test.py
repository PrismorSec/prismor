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

Suites can share fixtures and assert one call for several principals at once::

    fixtures:                      # or a sibling policy-fixtures.yaml
      principals:
        bob:   {id: bob, roles: [support], verified: true}
        carol: {id: carol, roles: [finance], verified: true}
        anon:  {}
      resources:
        alices_order: {kind: order, id: o-1, attr: {owner: alice}}
    tests:
      - name: refunds over 500
        tool: refund_order         # `tool:` implies type: tool
        args: {amount: 900}
        resource: alices_order     # fixture name, or an inline map
        expect: {bob: block, carol: pass, anon: block}   # one case per principal
        expect_rule: refund-cap    # checked on the block/warn rows
      - name: pending rule
        skip: true
        skip_reason: waiting on the finance roles claim

A case with ``steps:`` runs several calls in ONE session, so rules that depend
on what the session did earlier (tag rules, tool contracts) are testable::

    tests:
      - name: private repo content can't reach a public issue
        steps:
          - { tool: mcp__github__get_file_contents, args: { owner: acme, repo: billing } }
          - { tool: mcp__github__create_issue, args: { repo: acme/website }, expect: block }
          - { tool: mcp__linear__save_comment, args: { issueId: ENG-1 }, expect: pass }

Each step is one tool call (``tool``, ``args``, optional ``result`` text,
``expect`` — default ``pass`` — and ``expect_rule``). A step that is not
blocked is taken to have run: its result event follows, which is when a
contract's ``delta`` and ``effects`` reach the session label. A blocked step
never runs, exactly as in a live session.

A policy file may carry its own ``tests:`` / ``fixtures:`` (the console stores
them there); the engine ignores both keys.

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


def _step_events(step: Dict[str, Any], workspace: Optional[Path]):
    """(call event, result event) for one step of a multi-step case.

    Shaped the way a live surface would shape it: a built-in (``Read``,
    ``Bash``) becomes its native event type, anything else the generic tool
    payload. The arguments ride in ``metadata.kwargs`` either way.
    """
    import json

    tool = str(step.get("tool") or "")
    args = step.get("args") if isinstance(step.get("args"), dict) else {}
    shaped = None
    try:
        from prismor.runtime import mirror
        shaped = mirror.shape_call_event(tool, args)
    except Exception:
        shaped = None
    body = shaped or {"type": "tool_result", "response": json.dumps(args, default=str)}
    meta = {"tool_name": tool, "kwargs": args, "resource": step.get("resource") or {}}
    if workspace is not None:
        meta["cwd"] = str(workspace)
    call = {**body, "agent_event": "PreToolUse", "metadata": dict(meta)}
    result = {**body, "agent_event": "PostToolUse", "metadata": dict(meta),
              "response": str(step.get("result") or "")}
    if not shaped:
        result["type"] = "tool_result"
    return call, result


def _forget_session(workspace: Optional[Path], session_id: str) -> None:
    """Drop the per-session state a multi-step case left behind."""
    try:
        from prismor.runtime.contracts import label_path

        base = label_path(workspace or Path.cwd(), session_id)
        stem = base.name[: -len(".label.json")]
        for path in base.parent.glob(stem + "*"):
            if path.name.startswith(stem + "."):
                path.unlink()
    except Exception:
        pass


def _run_steps(engine: PolicyEngine, case: Dict[str, Any],
               workspace: Optional[Path]) -> Dict[str, Any]:
    """Run a ``steps:`` case in one fresh session."""
    import uuid
    from prismor.runtime.principal import Subject

    name = str(case.get("name"))
    steps = case.get("steps")
    if not isinstance(steps, list) or not steps or not all(
            isinstance(s, dict) and s.get("tool") for s in steps):
        return {"name": name, "status": "fail", "expected": "-",
                "got": "steps must be a non-empty list of {tool, args, expect}",
                "matched_rules": [], "input": "", "type": "steps"}
    p = case.get("principal") or {}
    subject = Subject(
        user_id=p.get("id"), team_id=p.get("team"), org_id=p.get("org"),
        source=str(p.get("source") or ("jwt" if p.get("verified") else "explicit")),
        roles=tuple(str(r) for r in p.get("roles") or ()),
        claims=dict(p.get("claims") or {}), verified=bool(p.get("verified")),
    )
    # `replay:` keeps the run out of the device-wide provenance store.
    session_id = f"replay:policy-test-{uuid.uuid4().hex}"
    rows: List[Dict[str, Any]] = []
    matched: set = set()
    ok = True
    try:
        for n, step in enumerate(steps):
            call, result = _step_events(step, workspace)
            findings = engine.evaluate(call, 2 * n, session_id=session_id, subject=subject)
            got = _verdict_from_findings(findings)
            rules = sorted({str(f.get("ruleId", "?")) for f in findings})
            matched.update(rules)
            expected = str(step.get("expect", "pass")).lower()
            step_ok = got == expected
            want_rule = step.get("expect_rule")
            if step_ok and want_rule and expected != "pass":
                step_ok = want_rule in rules
            ok = ok and step_ok
            rows.append({
                "step": n + 1, "tool": step.get("tool"), "expected": expected,
                "got": got, "status": "ok" if step_ok else "fail",
                "matched_rules": rules,
                "reason": next((str(f.get("title")) for f in findings
                                if f.get("action") == "block"), ""),
            })
            if got != "block":
                engine.evaluate(result, 2 * n + 1, session_id=session_id, subject=subject)
    finally:
        _forget_session(workspace, session_id)
    return {
        "name": name, "status": "ok" if ok else "fail",
        "expected": " -> ".join(r["expected"] for r in rows),
        "got": " -> ".join(r["got"] for r in rows),
        "matched_rules": sorted(matched),
        "input": " -> ".join(str(r["tool"]) for r in rows),
        "type": "steps", "steps": rows,
    }


def _fixture(kind: str, ref: Any, fixtures: Dict[str, Any]) -> Dict[str, Any]:
    if ref is None:
        return {}
    if isinstance(ref, dict):
        return ref
    table = (fixtures.get(kind) or {})
    if str(ref) not in table:
        raise ValueError(f"unknown {kind[:-1]} fixture '{ref}' (defined: {', '.join(sorted(table)) or 'none'})")
    return table[str(ref)] or {}


def expand_cases(cases: List[Dict[str, Any]], fixtures: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """Resolve fixture references and fan out `expect: {principal: verdict}`
    matrices into one plain case per principal."""
    fixtures = fixtures or {}
    out: List[Dict[str, Any]] = []
    for i, case in enumerate(cases):
        case = dict(case)
        name = str(case.get("name") or f"case-{i+1}")
        if case.get("tool") and "type" not in case:
            case["type"] = "tool"
        try:
            case["resource"] = _fixture("resources", case.get("resource"), fixtures)
            expect = case.get("expect", "pass")
            if isinstance(expect, dict):
                for who, verdict in expect.items():
                    out.append({**case, "name": f"{name} [{who}]", "expect": verdict,
                                "principal": _fixture("principals", who, fixtures)})
                continue
            case["principal"] = _fixture("principals", case.get("principal"), fixtures)
        except ValueError as exc:
            out.append({"name": name, "_error": str(exc)})
            continue
        out.append({**case, "name": name})
    return out


def run_cases(
    cases: List[Dict[str, Any]],
    workspace: Optional[Path] = None,
    fixtures: Optional[Dict[str, Any]] = None,
    policy_path: Optional[Path] = None,
    name_filter: Optional[str] = None,
) -> Dict[str, Any]:
    """Execute each test case against the current policy.

    Returns ``{total, passed, failed, skipped, results: [...]}``.
    Each result: ``{name, status: ok|fail|skip, expected, got, matched_rules}``.
    """
    from fnmatch import fnmatch

    engine = PolicyEngine(workspace=workspace, policy_path=policy_path)
    results: List[Dict[str, Any]] = []
    passed = 0
    skipped = 0
    cases = expand_cases(cases, fixtures)
    if name_filter:
        # `*` and `?` only: matrix rows are named "test [principal]", so a
        # bracket must match itself rather than open a character class.
        pattern = name_filter.replace("[", "[[]")
        cases = [c for c in cases if fnmatch(str(c.get("name")), pattern)]

    for i, case in enumerate(cases):
        if case.get("_error"):
            results.append({"name": case["name"], "status": "fail", "expected": "-",
                            "got": case["_error"], "matched_rules": [], "input": "", "type": "-"})
            continue
        if case.get("skip"):
            skipped += 1
            results.append({"name": str(case.get("name")), "status": "skip",
                            "reason": case.get("skip_reason") or "", "matched_rules": []})
            continue
        name = str(case.get("name") or f"case-{i+1}")
        if "steps" in case:
            row = _run_steps(engine, {**case, "name": name}, workspace)
            passed += row["status"] == "ok"
            results.append(row)
            continue
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
        if ok and expected_rule and expected != "pass":
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
            "input": value if typ != "tool" else case.get("tool"),
            "type": typ,
        })

    return {
        "total": len(cases),
        "passed": passed,
        "failed": len(cases) - passed - skipped,
        "skipped": skipped,
        "results": results,
    }


def load_cases(path: Path) -> List[Dict[str, Any]]:
    """Load policy-tests.yaml from ``path``."""
    return load_suite(path)[0]


def load_suite(path: Path) -> "tuple[List[Dict[str, Any]], Dict[str, Any]]":
    """(tests, fixtures) from ``path``. Fixtures come from the file's own
    ``fixtures:`` merged over a sibling ``policy-fixtures.yaml``, so several
    suites in one directory can share principals and resources."""
    if yaml is None:
        raise RuntimeError("PyYAML is required for policy tests")
    if not path.exists():
        raise FileNotFoundError(str(path))
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    tests = data.get("tests") or []
    if not isinstance(tests, list):
        raise ValueError(f"{path}: 'tests' must be a list")
    fixtures: Dict[str, Any] = {}
    shared = path.parent / "policy-fixtures.yaml"
    if shared.exists() and shared != path:
        fixtures = yaml.safe_load(shared.read_text(encoding="utf-8")) or {}
    for kind, table in (data.get("fixtures") or {}).items():
        fixtures[kind] = {**(fixtures.get(kind) or {}), **(table or {})}
    return tests, fixtures
