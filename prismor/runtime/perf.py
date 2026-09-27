"""Per-stage and per-rule timings for one hook process (#494).

The hook is a short-lived process that screens one event, so module-level
state is per call. The dispatcher persists ``snapshot()`` next to the total in
hook_timings on exit. Everything here is monotonic timestamps into dicts: cheap
enough to leave on for every call.
"""
from __future__ import annotations

import time
from contextlib import contextmanager
from typing import Any, Dict, Iterable, Iterator, List

STAGES: Dict[str, float] = {}
# rule id -> [evaluations, matches, cumulative ms, errors]
RULES: Dict[str, List[float]] = {}
DEGRADED: List[str] = []
_last = time.perf_counter()


def reset() -> None:
    STAGES.clear()
    RULES.clear()
    DEGRADED.clear()
    lap()


def lap(name: str = "") -> None:
    """Charge the time since the previous lap to ``name`` (no name: restart).

    Sequential stages of one long function mark their ends with a lap instead of
    re-indenting each block under a ``with stage()``.
    """
    global _last
    now = time.perf_counter()
    if name:
        STAGES[name] = STAGES.get(name, 0.0) + (now - _last) * 1000
    _last = now


@contextmanager
def stage(name: str) -> Iterator[None]:
    t0 = time.perf_counter()
    try:
        yield
    finally:
        STAGES[name] = STAGES.get(name, 0.0) + (time.perf_counter() - t0) * 1000


def timed_rules(rules: Iterable[Any], findings: List[Any]) -> Iterator[Any]:
    """Yield each rule, timing the loop body that runs while it is out.

    A rule matched when ``findings`` grew during its turn. An exception in the
    body closes this generator at the yield, which counts as that rule's error
    and re-raises: a rule that throws shows up in rule health, it is not hidden.
    """
    for rule in rules:
        n, t0 = len(findings), time.perf_counter()
        error = True
        try:
            yield rule
            error = False
        finally:
            c = RULES.setdefault(str(getattr(rule, "id", rule)), [0, 0, 0.0, 0])
            c[0] += 1
            c[1] += len(findings) > n
            c[2] += (time.perf_counter() - t0) * 1000
            c[3] += error


def degraded(what: str) -> None:
    """A stage fell back to a cheaper path (judge over budget, judge failed)."""
    DEGRADED.append(what)


def snapshot() -> Dict[str, Any]:
    out: Dict[str, Any] = {"stages": {k: round(v, 2) for k, v in STAGES.items()}}
    # Only rules that cost something, matched or broke: ~100 rules per event
    # would otherwise bloat every row with zeros.
    rules = {k: [int(c[0]), int(c[1]), round(c[2], 3), int(c[3])]
             for k, c in RULES.items() if c[1] or c[3] or c[2] >= 0.05}
    if rules:
        out["rules"] = rules
    if DEGRADED:
        out["degraded"] = list(DEGRADED)
    return out
