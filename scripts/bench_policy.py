#!/usr/bin/env python3
"""Detection and false-positive rates of the default policy on the in-repo corpus.

The attack side is harvested from cases that already live in the repo's tests
and templates (tests/fixtures/corpus/sources.yaml says where); the benign side
is ordinary dev traffic (tests/fixtures/corpus/benign.yaml). Every event goes
through ``PolicyEngine.evaluate`` -- the call the hook makes -- with the
default policy only, under a throwaway PRISMOR_HOME/HOME, and the semantic
guard held to its heuristic pass: no LLM judge, no network. Findings the hook
drops as inert text (``contextInert``) are dropped here too.

    python3 scripts/bench_policy.py                    # report
    python3 scripts/bench_policy.py --json out.json    # also write results
    python3 scripts/bench_policy.py --update-baseline  # rewrite the checked-in
        baseline (tests/fixtures/corpus/baseline.json) and docs/residual-risk.md

Payload text is never printed or written: misses are named by case id, which
points back at the test that owns the case.
"""
from __future__ import annotations

import argparse
import ast
import collections
import hashlib
import json
import os
import socket
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Tuple

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "tests" / "fixtures" / "corpus"
BASELINE = CORPUS / "baseline.json"
RESIDUAL = ROOT / "docs" / "residual-risk.md"

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import yaml  # noqa: E402


def _h(value: Any) -> str:
    blob = json.dumps(value, sort_keys=True, ensure_ascii=False)
    return hashlib.sha1(blob.encode("utf-8"), usedforsecurity=False).hexdigest()[:8]


def _event(kind: str, value: Any) -> Dict[str, Any]:
    if kind == "shell":
        return {"type": "shell", "command": value, "agent_event": "PreToolUse"}
    if kind in ("file_read", "file_write"):
        ev = value if isinstance(value, dict) else {"path": value}
        return {"type": kind, "agent_event": "PreToolUse", **ev}
    if kind == "network":
        return {"type": "network", "url": value, "agent_event": "PreToolUse"}
    if kind == "prompt":
        return {"type": "prompt", "prompt": value, "agent_event": "UserPromptSubmit"}
    if kind == "mcp":
        # A local stdio MCP pre-call, shaped as hooks._classify_mcp_event does.
        s, t = value["server"], value["tool"]
        return {"type": "tool_result", "agent_event": "PreToolUse", "mcp_server": s, "mcp_tool": t,
                "response": json.dumps(value.get("args") or {}), "metadata": {"tool_name": f"mcp__{s}__{t}"}}
    raise ValueError(f"unknown event kind {kind!r}")


# ── harvest ──────────────────────────────────────────────────────────────────

def _strings(node: ast.AST, module_lists: Dict[str, ast.AST]) -> Tuple[List[str], int]:
    if isinstance(node, ast.Name) and node.id in module_lists:
        node = module_lists[node.id]
    if not isinstance(node, (ast.List, ast.Tuple)):
        return [], 1
    out = [e.value for e in node.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)]
    return out, len(node.elts) - len(out)


def _harvest(src: Dict[str, Any], rule_meta: Dict[str, Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], int]:
    """(cases, skipped) for one sources.yaml entry."""
    path = ROOT / src["file"]
    kind = src["kind"]
    cases: List[Dict[str, Any]] = []
    if kind == "template":
        from prismor.runtime.policy_test import load_suite
        types = {"command": "shell", "read": "file_read", "write": "file_write"}
        for t in load_suite(path)[0]:
            expected = {"pass": "allow"}.get(str(t.get("expect")), str(t.get("expect")))
            rule = t.get("expect_rule")
            cat = (rule_meta.get(rule) or {}).get("category") if src.get("category_by_rule") else None
            event = _event(types[t.get("type", "command")], t["input"])
            cases.append({"id": f"{src['file']}::{t['name']}", "event": event, "expected": expected,
                          "side": "benign" if expected == "allow" else "attack",
                          "category": cat or src["category"], "note": t["name"], "source": src["file"]})
        return cases, 0

    text = path.read_text(encoding="utf-8")
    tree = ast.parse(text)
    module_lists = {t.id: n.value for n in tree.body if isinstance(n, ast.Assign)
                    for t in n.targets if isinstance(t, ast.Name)}
    side = src.get("side", "attack")
    expected = src.get("expected") or ("allow" if side == "benign"
                                       else (rule_meta.get(src.get("rule")) or {}).get("action", "block"))
    values: List[Tuple[str, Any, str]] = []  # (label, event, side)
    per_method = src.get("methods") or {}  # event_dicts: {method: {expected, category}}
    skipped = 0
    if kind == "module_list":
        vals, skipped = _strings(module_lists[src["name"]], {})
        values = [(src["name"], _event(src["event"], v), side) for v in vals]
    elif kind == "parametrize":
        for fn in ast.walk(tree):
            if isinstance(fn, ast.FunctionDef) and fn.name == src["test"]:
                for d in fn.decorator_list:
                    if (isinstance(d, ast.Call) and getattr(d.func, "attr", "") == "parametrize"
                            and isinstance(d.args[0], ast.Constant) and d.args[0].value == src["arg"]):
                        vals, skipped = _strings(d.args[1], module_lists)
                        values = [(src["test"], _event(src["event"], v), side) for v in vals]
    elif kind == "event_dicts":
        cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == src["class"])
        for fn in cls.body:
            if not isinstance(fn, ast.FunctionDef) or not fn.name.startswith("test"):
                continue
            fn_side = "benign" if "assertNotIn" in (ast.get_source_segment(text, fn) or "") else "attack"
            for n in ast.walk(fn):
                if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "event" for t in n.targets):
                    try:
                        values.append((fn.name, ast.literal_eval(n.value), fn_side))
                    except ValueError:
                        skipped += 1
    if not values:
        raise ValueError(f"{src['file']}: source {src.get('test') or src.get('name') or src.get('class')} "
                         f"yielded no cases (renamed or moved?)")
    for label, event, s in values:
        over = per_method.get(label) or {}
        if kind == "event_dicts":
            label = f"{src['class']}.{label}"
        cases.append({"id": f"{src['file']}::{label}[{_h(event)}]", "event": event,
                      "expected": "allow" if s == "benign" else over.get("expected", expected),
                      "side": s, "category": over.get("category", src["category"]),
                      "note": label, "source": src["file"]})
    return cases, skipped


def load_corpus() -> Tuple[List[Dict[str, Any]], int, Dict[str, str]]:
    """(cases, skipped harvest values, residual reasons)."""
    policy = yaml.safe_load((ROOT / "prismor/runtime/default_policy.yaml").read_text(encoding="utf-8"))
    rule_meta = {r["id"]: r for r in policy.get("rules", [])}
    sources = yaml.safe_load((CORPUS / "sources.yaml").read_text(encoding="utf-8"))
    cases: List[Dict[str, Any]] = []
    skipped = 0
    for src in sources["sources"]:
        got, n = _harvest(src, rule_meta)
        cases += got
        skipped += n
    benign = yaml.safe_load((CORPUS / "benign.yaml").read_text(encoding="utf-8"))
    for group in ("shell", "file_read", "file_write", "network", "prompt", "mcp"):
        for value in benign.get(group) or []:
            event = _event(group, value)
            cases.append({"id": f"benign/{group}/{_h(event)}", "event": event, "expected": "allow",
                          "side": "benign", "category": f"benign_{group}", "note": "",
                          "source": "tests/fixtures/corpus/benign.yaml"})
    ids = collections.Counter(c["id"] for c in cases)
    dupes = [i for i, n in ids.items() if n > 1]
    if dupes:  # the same literal twice in one source: keep one
        seen: set = set()
        cases = [c for c in cases if not (c["id"] in seen or seen.add(c["id"]))]
    return cases, skipped, dict(sources.get("residual") or {})


# ── evaluate ─────────────────────────────────────────────────────────────────

_real_connect = socket.socket.connect
NETWORK_ATTEMPTS = [0]


def _no_network(self, *a, **k):
    """The bench must not depend on the network: any layer that tries fails."""
    NETWORK_ATTEMPTS[0] += 1
    raise OSError("network disabled in bench_policy")


def run() -> Dict[str, Any]:
    """Evaluate the corpus and return the results document."""
    cases, skipped, _ = load_corpus()
    tmp = tempfile.mkdtemp(prefix="prismor-bench-")
    saved = {k: os.environ.get(k) for k in ("PRISMOR_HOME", "HOME", "PRISMOR_SEMANTIC_MODEL")}
    os.environ["HOME"] = tmp
    os.environ["PRISMOR_HOME"] = str(Path(tmp) / ".prismor")
    os.environ.pop("PRISMOR_SEMANTIC_MODEL", None)
    try:
        from prismor.runtime.policy_engine import PolicyEngine
        from prismor.runtime.policy_test import _verdict_from_findings

        overlay = Path(tmp) / "empty-policy.yaml"
        # The install check scores packages against live registry and OSV data.
        overlay.write_text('version: "1.0"\nrules: []\nsettings:\n  supply_chain_install_check: false\n',
                           encoding="utf-8")
        engine = PolicyEngine(workspace=Path(tmp), policy_path=overlay)
        engine.semantic_guard_config = {**engine.semantic_guard_config, "mode": "heuristic"}
        engine._semantic_guard = None
        results = []
        socket.socket.connect = _no_network  # type: ignore[method-assign]
        for c in cases:
            findings = [f for f in engine.evaluate(json.loads(json.dumps(c["event"])), 0)
                        if not f.get("contextInert")]
            got = {"pass": "allow"}.get(_verdict_from_findings(findings), _verdict_from_findings(findings))
            results.append({"id": c["id"], "side": c["side"], "category": c["category"],
                            "expected": c["expected"], "got": got, "source": c["source"],
                            "rules": sorted({str(f.get("ruleId")) for f in findings})})
    finally:
        socket.socket.connect = _real_connect  # type: ignore[method-assign]
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    return summarize(results, skipped)


def summarize(results: List[Dict[str, Any]], skipped: int) -> Dict[str, Any]:
    per_cat: Dict[str, Dict[str, int]] = collections.defaultdict(lambda: collections.Counter())
    for r in results:
        if r["side"] != "attack":
            continue
        c = per_cat[r["category"]]
        c["cases"] += 1
        c["detected"] += r["got"] != "allow"
        c["exact"] += r["got"] == r["expected"]
    attacks = [r for r in results if r["side"] == "attack"]
    benign = [r for r in results if r["side"] == "benign"]
    detected = sum(r["got"] != "allow" for r in attacks)
    blocked = sum(r["got"] == "block" for r in benign)
    warned = sum(r["got"] == "warn" for r in benign)
    return {
        "version": 1,
        "engine": "PolicyEngine.evaluate, default policy, semantic guard heuristic-only, no network",
        "totals": {
            "attack_cases": len(attacks), "attack_detected": detected,
            "detection_rate": round(detected / len(attacks), 4) if attacks else 0.0,
            "attack_exact_verdict": sum(r["got"] == r["expected"] for r in attacks),
            "benign_cases": len(benign), "benign_blocked": blocked, "benign_warned": warned,
            "false_positive_rate": round(blocked / len(benign), 4) if benign else 0.0,
            "benign_flag_rate": round((blocked + warned) / len(benign), 4) if benign else 0.0,
            "harvest_skipped_non_literal": skipped,
            "network_attempts_refused": NETWORK_ATTEMPTS[0],
        },
        "per_category": {k: dict(v, detection_rate=round(v["detected"] / v["cases"], 4))
                         for k, v in sorted(per_cat.items())},
        "cases": {r["id"]: {k: r[k] for k in ("side", "category", "expected", "got", "rules")}
                  for r in sorted(results, key=lambda r: r["id"])},
    }


def regressions(current: Dict[str, Any], baseline: Dict[str, Any]) -> List[str]:
    """Cases that got worse than the baseline. New or removed ids are ignored."""
    worse = []
    rank = {"allow": 0, "warn": 1, "block": 2}
    for cid, base in baseline["cases"].items():
        now = current["cases"].get(cid)
        if now is None:
            continue
        if base["side"] == "attack" and rank[now["got"]] < rank[base["got"]]:
            worse.append(f"attack {cid}: {base['got']} -> {now['got']}")
        if base["side"] == "benign" and rank[now["got"]] > rank[base["got"]]:
            worse.append(f"benign {cid}: {base['got']} -> {now['got']}")
    return worse


def residual_markdown(doc: Dict[str, Any], reasons: Dict[str, str]) -> str:
    t = doc["totals"]
    lines = [
        "# Residual risk",
        "",
        "Known gaps of the deterministic layers (rules plus the heuristic semantic",
        "pass, no LLM judge), measured by `python3 scripts/bench_policy.py` on the",
        "in-repo corpus. Generated with `--update-baseline`; edit the reasons in",
        "`tests/fixtures/corpus/sources.yaml` (`residual:`), not here.",
        "",
        f"Attack cases: {t['attack_cases']}, detected (warn or block): {t['attack_detected']} "
        f"({t['detection_rate']:.1%}). Benign cases: {t['benign_cases']}, blocked: "
        f"{t['benign_blocked']} ({t['false_positive_rate']:.1%}), warned: {t['benign_warned']}.",
        "",
        "Case ids name the test or template that holds the case.",
        "",
        "Scope of these numbers:",
        "",
        "- The attack half is harvested from the repo's own regression tests and",
        "  starter pack, which were written to pass. A full detection rate here",
        "  means no regression on known cases. It does not estimate how much of",
        "  an unseen technique the rules catch.",
        "- Only literal test values are harvested; computed ones (f-strings,",
        f"  encoded at test time) are skipped ({t['harvest_skipped_non_literal']} this run).",
        "- The LLM judge, the supply-chain install check (registry and OSV lookups),",
        "  and org, user or project policy layers are out of scope. Judge figures",
        "  quoted elsewhere in the docs were measured outside the repo.",
        "",
    ]
    groups = [
        ("Not detected", lambda c: c["side"] == "attack" and c["got"] == "allow"),
        ("Detected at a lower verdict than expected", lambda c: c["side"] == "attack"
         and c["got"] == "warn" and c["expected"] == "block"),
        ("Benign cases blocked", lambda c: c["side"] == "benign" and c["got"] == "block"),
    ]
    for title, pred in groups:
        rows = [(cid, c) for cid, c in doc["cases"].items() if pred(c)]
        lines += [f"## {title} ({len(rows)})", ""]
        if not rows:
            lines += ["None.", ""]
            continue
        lines += ["| Case | Category | Reason |", "| --- | --- | --- |"]
        for cid, c in rows:
            reason = reasons.get(cid, "Not yet triaged.")
            lines.append(f"| `{cid}` | {c['category']} | {reason} |")
        lines.append("")
    return "\n".join(lines)


def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--json", type=Path, help="write the results document here")
    ap.add_argument("--update-baseline", action="store_true",
                    help="rewrite tests/fixtures/corpus/baseline.json and docs/residual-risk.md")
    args = ap.parse_args(argv)

    doc = run()
    t = doc["totals"]
    print(f"Attack cases {t['attack_cases']}: detected {t['attack_detected']} ({t['detection_rate']:.1%}), "
          f"exact verdict {t['attack_exact_verdict']}")
    print(f"Benign cases {t['benign_cases']}: blocked {t['benign_blocked']} "
          f"(FP rate {t['false_positive_rate']:.1%}), warned {t['benign_warned']} "
          f"(flag rate {t['benign_flag_rate']:.1%})")
    print(f"Harvest: {t['harvest_skipped_non_literal']} non-literal test values skipped\n")
    print(f"{'category':<24}{'cases':>6}{'detected':>10}{'rate':>8}")
    for cat, c in doc["per_category"].items():
        print(f"{cat:<24}{c['cases']:>6}{c['detected']:>10}{c['detection_rate']:>8.0%}")
    misses = [cid for cid, c in doc["cases"].items() if c["side"] == "attack" and c["got"] == "allow"]
    fps = [cid for cid, c in doc["cases"].items() if c["side"] == "benign" and c["got"] != "allow"]
    print(f"\nMisses ({len(misses)}):")
    for cid in misses:
        print(f"  {cid}")
    print(f"\nBenign flagged ({len(fps)}):")
    for cid in fps:
        c = doc["cases"][cid]
        print(f"  {c['got']:<5} {cid}  {','.join(c['rules'])}")

    if args.json:
        args.json.write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    if args.update_baseline:
        BASELINE.write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n", encoding="utf-8")
        RESIDUAL.write_text(residual_markdown(doc, load_corpus()[2]) + "\n", encoding="utf-8")
        print(f"\nWrote {BASELINE.relative_to(ROOT)} and {RESIDUAL.relative_to(ROOT)}")
    elif BASELINE.exists():
        worse = regressions(doc, json.loads(BASELINE.read_text(encoding="utf-8")))
        if worse:
            print(f"\nRegressions against the baseline ({len(worse)}):")
            for w in worse:
                print(f"  {w}")
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
