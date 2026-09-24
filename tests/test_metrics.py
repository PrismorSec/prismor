"""Tests for the Prometheus exposition (prismor/runtime/metrics.py).

Invariants under test:
  * A metric name carries exactly one type. Registering it as both a gauge and
    a counter used to put two conflicting ``# TYPE`` lines in one exposition,
    which costs the whole scrape — the second registration is refused instead.
  * Every ``# TYPE`` line immediately precedes its own family's samples.
  * The store collector calls ``get_aggregate_stats`` with an *hours int* and
    reads the keys that function actually returns. Passing the workspace Path
    raised inside a bare ``except``, so every series silently vanished and
    ``/metrics`` answered a single newline.
  * Counters come from an unbounded window (monotonic, safe under ``rate()``);
    gauges come from the 24h window.

Run: python3 -m pytest tests/test_metrics.py
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO))

from prismor.runtime import metrics as M  # noqa: E402


@pytest.fixture()
def reg():
    return M.MetricsRegistry()


def families(text: str):
    """name -> declared type, from the # TYPE lines."""
    return {
        line.split()[2]: line.split()[3]
        for line in text.splitlines()
        if line.startswith("# TYPE")
    }


def type_lines(text: str, name: str):
    return [l for l in text.splitlines() if l.startswith(f"# TYPE {name} ")]


def samples(text: str, name: str):
    return [l for l in text.splitlines()
            if l.startswith(name) and not l.startswith("# ")]


# ── type claiming ───────────────────────────────────────────────────────────

def test_a_name_gets_exactly_one_type_line(reg):
    reg.set_gauge("prismor_blocked_total", 7)
    reg.inc_counter("prismor_blocked_total", 1, labels={"rule": "secret_leak"})
    out = reg.generate_prometheus_text()
    assert len(type_lines(out, "prismor_blocked_total")) == 1
    assert families(out)["prismor_blocked_total"] == "gauge"


def test_conflicting_registration_is_dropped_not_merged(reg):
    reg.inc_counter("m", 3)
    reg.set_gauge("m", 99)
    out = reg.generate_prometheus_text()
    assert families(out)["m"] == "counter"
    assert "m 3.0" in out and "99" not in out


def test_type_line_immediately_precedes_its_family(reg):
    reg.set_gauge("a_gauge", 1, labels={"k": "v"})
    reg.set_counter("z_counter", 2)
    lines = reg.generate_prometheus_text().splitlines()
    for i, line in enumerate(lines):
        if line.startswith("# TYPE "):
            name = line.split()[2]
            assert lines[i + 1].startswith(name), f"{name} samples do not follow its TYPE"


# ── values & formatting ─────────────────────────────────────────────────────

def test_counter_accumulates_and_gauge_replaces(reg):
    reg.inc_counter("c", 1.0, labels={"s": "ok"})
    reg.inc_counter("c", 2.0, labels={"s": "ok"})
    reg.set_gauge("g", 5)
    reg.set_gauge("g", 8)
    out = reg.generate_prometheus_text()
    assert 'c{s="ok"} 3.0' in out
    assert "g 8.0" in out


def test_quantiles_count_and_sum(reg):
    for i in range(100):
        reg.observe_latency("lat_seconds", float(i))
    out = reg.generate_prometheus_text()
    assert 'lat_seconds{quantile="0.5"} 49.000000' in out
    assert 'lat_seconds{quantile="0.99"} 98.000000' in out
    assert "lat_seconds_count 100" in out
    assert "lat_seconds_sum 4950.000000" in out


def test_label_values_are_escaped(reg):
    reg.set_counter("esc", 1, labels={"rule": 'foo"bar\\baz\nqux'})
    out = reg.generate_prometheus_text()
    assert r'rule="foo\"bar\\baz\nqux"' in out


def test_reset_drops_series_and_frees_the_name(reg):
    reg.set_gauge("x", 1)
    reg.reset()
    reg.inc_counter("x", 4)
    out = reg.generate_prometheus_text()
    assert families(out)["x"] == "counter"


# ── store collector ─────────────────────────────────────────────────────────

_STATS = {
    "kpis": {"activeSessions": 3, "toolCallsInspected24h": 120,
             "dangerousCommandsPrevented24h": 7, "deltas": {}},
    "threatsByCategory": {"prompt_injection": 11, "dangerous_command": 4},
    "agentBlockedCommands": [{"agent": "claude", "blocked": 9}],
    "toolCallBreakdown": [{"tool": "bash", "count": 88}, {"tool": "read", "count": 32}],
    "topPatterns": [{"pattern": "Outbound connection to raw IP", "category": "dangerous_command",
                     "severity": "high", "count": 5}],
    "severityBreakdown": {"critical": 1, "high": 2, "medium": 3, "low": 4},
}


@pytest.fixture()
def fake_store(monkeypatch):
    """Record every hours argument the collector passes."""
    calls = []

    def fake_stats(hours=24):
        calls.append(hours)
        return _STATS

    monkeypatch.setattr("prismor.runtime.store.get_aggregate_stats", fake_stats)
    monkeypatch.setattr("prismor.runtime.store.get_hook_latency_ms",
                        lambda limit=5000: [10, 20, 30, 40])
    return calls


def test_collector_passes_an_int_window_not_a_path(fake_store, reg):
    M.collect_from_store(reg)
    assert fake_store, "get_aggregate_stats was never called"
    assert all(isinstance(h, int) for h in fake_store), fake_store


def test_counters_use_an_unbounded_window_gauges_use_24h(fake_store, reg):
    M.collect_from_store(reg)
    assert M._ALL_TIME_HOURS in fake_store
    assert M._GAUGE_WINDOW_HOURS in fake_store


def test_collector_emits_the_documented_families(fake_store, reg):
    out = M.collect_from_store(reg).generate_prometheus_text()
    t = families(out)
    assert t["prismor_tool_calls_total"] == "counter"
    assert t["prismor_threats_total"] == "counter"
    assert t["prismor_blocked_total"] == "counter"
    assert t["prismor_pattern_hits_total"] == "counter"
    assert t["prismor_active_sessions"] == "gauge"
    assert t["prismor_findings_by_severity"] == "gauge"
    assert t["prismor_hook_latency_seconds"] == "summary"

    assert 'prismor_tool_calls_total{tool="bash"} 88.0' in out
    assert 'prismor_threats_total{category="prompt_injection"} 11.0' in out
    assert 'prismor_blocked_total{agent="claude"} 9.0' in out
    assert 'prismor_findings_by_severity{severity="critical"} 1.0' in out
    assert "prismor_active_sessions 3.0" in out
    assert "prismor_tool_calls_inspected_24h 120.0" in out
    assert "prismor_dangerous_commands_prevented_24h 7.0" in out


def test_hook_latency_is_seconds_not_milliseconds(fake_store, reg):
    out = M.collect_from_store(reg).generate_prometheus_text()
    # 10..40 ms → 0.010..0.040 s
    assert 'prismor_hook_latency_seconds{quantile="0.5"} 0.020000' in out
    assert "prismor_hook_latency_seconds_count 4" in out


def test_pattern_family_is_capped(fake_store, reg, monkeypatch):
    many = dict(_STATS)
    many["topPatterns"] = [{"pattern": f"p{i}", "category": "c", "severity": "low", "count": i}
                           for i in range(50)]
    monkeypatch.setattr("prismor.runtime.store.get_aggregate_stats",
                        lambda hours=24: many)
    out = M.collect_from_store(reg).generate_prometheus_text()
    assert len(samples(out, "prismor_pattern_hits_total")) == M._MAX_PATTERN_SERIES


def test_collect_is_idempotent_across_scrapes(fake_store, reg):
    first = M.collect_from_store(reg).generate_prometheus_text()
    second = M.collect_from_store(reg).generate_prometheus_text()
    assert first == second, "a second scrape double-counted or accumulated"


def test_render_is_not_an_empty_body(fake_store):
    """The shipped regression: /metrics answered exactly '\\n'."""
    body = M.render()
    assert body != "\n"
    assert "prismor_tool_calls_total" in body
