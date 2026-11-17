"""Non-regression gate for the policy benchmark corpus (scripts/bench_policy.py).

Fails when an attack case gets a weaker verdict than the checked-in baseline
or a benign case a stronger one. After an intended change, refresh with:

    python3 scripts/bench_policy.py --update-baseline
"""
import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("bench_policy", ROOT / "scripts" / "bench_policy.py")
bench = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bench)

# Path resolution differs on Windows (drive letters, ~ expansion); the baseline
# is measured on POSIX.
pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="baseline is measured on POSIX")


def test_no_regression_against_baseline():
    baseline = json.loads(bench.BASELINE.read_text(encoding="utf-8"))
    current = bench.run()
    worse = bench.regressions(current, baseline)
    assert not worse, ("verdicts regressed; if intended, run "
                       "`python3 scripts/bench_policy.py --update-baseline`:\n" + "\n".join(worse))
    assert current["totals"]["network_attempts_refused"] == 0


def test_regressions_flags_both_directions():
    base = {"cases": {"a": {"side": "attack", "got": "block"}, "b": {"side": "benign", "got": "allow"}}}
    assert bench.regressions({"cases": {"a": {"side": "attack", "got": "warn"},
                                        "b": {"side": "benign", "got": "allow"}}}, base) == [
        "attack a: block -> warn"]
    assert bench.regressions({"cases": {"a": {"side": "attack", "got": "block"},
                                        "b": {"side": "benign", "got": "warn"}}}, base) == [
        "benign b: allow -> warn"]
    assert bench.regressions({"cases": {}}, base) == []


def test_corpus_shape():
    cases, _, _ = bench.load_corpus()
    attacks = [c for c in cases if c["side"] == "attack"]
    benign = [c for c in cases if c["side"] == "benign"]
    assert len({c["id"] for c in cases}) == len(cases)
    assert len(benign) >= 2 * len(attacks)
    assert {c["expected"] for c in cases} <= {"block", "warn", "allow"}
    assert {c["event"]["type"] for c in benign} >= {
        "shell", "file_read", "file_write", "network", "prompt", "tool_result"}
