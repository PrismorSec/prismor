"""Prometheus exposition for the Prismor dashboard server.

Every number reported here is read back out of the session store rather than
counted in memory. That is deliberate: the hook dispatcher
(`prismor/runtime/cli.py`) runs as a short-lived process per tool call, so a
counter it incremented would die with the hook and never reach the long-lived
`serve` process that answers the scrape. The store is the only state the two
share.

Counters are queried over an effectively unbounded window so they stay
monotonic across scrapes — `rate()` on a windowed count would read as a sawtooth.
Gauges keep the dashboard's own 24h window.

No third-party dependency: the exposition is a few hundred bytes of text.
"""

import collections
import threading
from typing import Any, Dict, Iterable, List, Optional, Tuple

# Counter sources are queried over this window so their values only ever grow.
_ALL_TIME_HOURS = 24 * 365 * 20
_GAUGE_WINDOW_HOURS = 24

LabelKey = Tuple[Tuple[str, str], ...]


def _escape_label_value(val: str) -> str:
    return str(val).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _format_labels(labels: LabelKey) -> str:
    if not labels:
        return ""
    return "{" + ",".join(f'{k}="{_escape_label_value(v)}"' for k, v in labels) + "}"


class MetricsRegistry:
    """Counters, gauges and latency summaries, grouped by family on render.

    A metric name carries exactly one type. Registering the same name as both a
    gauge and a counter would put two conflicting `# TYPE` lines in one
    exposition, which costs you the whole scrape — so the second registration
    is refused at the point of the write instead.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._types: Dict[str, str] = {}
        self.counters: Dict[Tuple[str, LabelKey], float] = collections.defaultdict(float)
        self.gauges: Dict[Tuple[str, LabelKey], float] = {}
        # Sliding window of samples; _count/_sum stay lifetime totals.
        self.latencies: Dict[str, collections.deque] = collections.defaultdict(
            lambda: collections.deque(maxlen=10000)
        )
        self.latency_counts: Dict[str, int] = collections.defaultdict(int)
        self.latency_sums: Dict[str, float] = collections.defaultdict(float)

    # ── writes ──────────────────────────────────────────────────────────────
    def _claim(self, name: str, kind: str) -> bool:
        """Reserve `name` for `kind`; False if another type already holds it."""
        held = self._types.setdefault(name, kind)
        return held == kind

    @staticmethod
    def _key(labels: Optional[Dict[str, str]]) -> LabelKey:
        return tuple(sorted(labels.items())) if labels else ()

    def inc_counter(self, name: str, value: float = 1.0,
                    labels: Optional[Dict[str, str]] = None) -> None:
        with self._lock:
            if not self._claim(name, "counter"):
                return
            self.counters[(name, self._key(labels))] += value

    def set_counter(self, name: str, value: float,
                    labels: Optional[Dict[str, str]] = None) -> None:
        """Set a counter to an absolute total (store-derived, already cumulative)."""
        with self._lock:
            if not self._claim(name, "counter"):
                return
            self.counters[(name, self._key(labels))] = float(value)

    def set_gauge(self, name: str, value: float,
                  labels: Optional[Dict[str, str]] = None) -> None:
        with self._lock:
            if not self._claim(name, "gauge"):
                return
            self.gauges[(name, self._key(labels))] = float(value)

    def observe_latency(self, name: str, duration_sec: float) -> None:
        with self._lock:
            if not self._claim(name, "summary"):
                return
            self.latencies[name].append(duration_sec)
            self.latency_counts[name] += 1
            self.latency_sums[name] += duration_sec

    def observe_latencies(self, name: str, samples: Iterable[float]) -> None:
        for s in samples:
            self.observe_latency(name, s)

    def reset(self) -> None:
        """Drop all state. The store collector rebuilds from scratch per scrape."""
        with self._lock:
            self._types.clear()
            self.counters.clear()
            self.gauges.clear()
            self.latencies.clear()
            self.latency_counts.clear()
            self.latency_sums.clear()

    # ── render ──────────────────────────────────────────────────────────────
    def generate_prometheus_text(self) -> str:
        """Text exposition, one `# TYPE` line immediately before its own family."""
        lines: List[str] = []
        with self._lock:
            families: Dict[str, List[Tuple[LabelKey, float]]] = collections.defaultdict(list)
            for (name, labels), val in self.gauges.items():
                families[name].append((labels, val))
            for (name, labels), val in self.counters.items():
                families[name].append((labels, val))

            for name in sorted(families):
                lines.append(f"# TYPE {name} {self._types.get(name, 'untyped')}")
                for labels, val in sorted(families[name]):
                    lines.append(f"{name}{_format_labels(labels)} {val}")

            for name in sorted(self.latencies):
                samples = self.latencies[name]
                if not samples:
                    continue
                ordered = sorted(samples)
                n = len(ordered)

                def quantile(p: float, _o=ordered, _n=n) -> float:
                    return _o[max(0, min(int((_n - 1) * p), _n - 1))]

                lines.append(f"# TYPE {name} summary")
                for q in (0.5, 0.9, 0.95, 0.99):
                    lines.append(f'{name}{{quantile="{q}"}} {quantile(q):.6f}')
                lines.append(f"{name}_count {self.latency_counts[name]}")
                lines.append(f"{name}_sum {self.latency_sums[name]:.6f}")

        return "\n".join(lines) + "\n"


REGISTRY = MetricsRegistry()

# Long pattern titles are label values, so the family is capped rather than left
# to grow one series per distinct finding title.
_MAX_PATTERN_SERIES = 20


def collect_from_store(registry: Optional[MetricsRegistry] = None) -> MetricsRegistry:
    """Rebuild `registry` from the session store. Returns it for chaining.

    Safe to call on every scrape: it resets first, so a workspace that stops
    reporting drops its series instead of freezing at its last value.
    """
    reg = registry or REGISTRY
    reg.reset()

    from prismor.runtime.store import get_aggregate_stats, get_hook_latency_ms

    totals = get_aggregate_stats(hours=_ALL_TIME_HOURS)
    window = get_aggregate_stats(hours=_GAUGE_WINDOW_HOURS)

    # ── counters (cumulative, safe under rate()) ────────────────────────────
    for row in totals.get("toolCallBreakdown") or []:
        reg.set_counter("prismor_tool_calls_total", row.get("count", 0),
                        {"tool": row.get("tool", "unknown")})

    for category, count in (totals.get("threatsByCategory") or {}).items():
        reg.set_counter("prismor_threats_total", count, {"category": category})

    for row in totals.get("agentBlockedCommands") or []:
        reg.set_counter("prismor_blocked_total", row.get("blocked", 0),
                        {"agent": row.get("agent", "unknown")})

    for row in (totals.get("topPatterns") or [])[:_MAX_PATTERN_SERIES]:
        reg.set_counter("prismor_pattern_hits_total", row.get("count", 0), {
            "pattern": row.get("pattern", "unknown"),
            "category": row.get("category", "unknown"),
            "severity": row.get("severity", "unknown"),
        })

    # ── gauges (the dashboard's own 24h window) ─────────────────────────────
    kpis: Dict[str, Any] = window.get("kpis") or {}
    reg.set_gauge("prismor_active_sessions", kpis.get("activeSessions", 0))
    reg.set_gauge("prismor_tool_calls_inspected_24h", kpis.get("toolCallsInspected24h", 0))
    reg.set_gauge("prismor_dangerous_commands_prevented_24h",
                  kpis.get("dangerousCommandsPrevented24h", 0))

    for severity, count in (window.get("severityBreakdown") or {}).items():
        reg.set_gauge("prismor_findings_by_severity", count, {"severity": severity})

    # ── latency summary (hook durations, ms in the store → seconds here) ────
    reg.observe_latencies("prismor_hook_latency_seconds",
                          (ms / 1000.0 for ms in get_hook_latency_ms()))
    return reg


def render() -> str:
    """The body of GET /metrics."""
    return collect_from_store().generate_prometheus_text()
