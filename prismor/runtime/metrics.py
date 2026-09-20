"""Lightweight Prometheus metrics exporter for Prismor runtime."""

import collections
import threading
from typing import Dict, List, Optional, Tuple


def _escape_label_value(val: str) -> str:
    return str(val).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


class MetricsRegistry:
    def __init__(self):
        self._lock = threading.Lock()
        self.counters: Dict[Tuple[str, Tuple[Tuple[str, str], ...]], float] = collections.defaultdict(float)
        self.gauges: Dict[Tuple[str, Tuple[Tuple[str, str], ...]], float] = collections.defaultdict(float)
        
        # Summary percentiles: sliding window of max 10,000 samples
        self.latencies: Dict[str, collections.deque] = collections.defaultdict(lambda: collections.deque(maxlen=10000))
        # Lifetime cumulative totals
        self.latency_counts: Dict[str, int] = collections.defaultdict(int)
        self.latency_sums: Dict[str, float] = collections.defaultdict(float)

    def inc_counter(self, name: str, value: float = 1.0, labels: Optional[Dict[str, str]] = None) -> None:
        label_key = tuple(sorted(labels.items())) if labels else ()
        with self._lock:
            self.counters[(name, label_key)] += value

    def set_gauge(self, name: str, value: float, labels: Optional[Dict[str, str]] = None) -> None:
        label_key = tuple(sorted(labels.items())) if labels else ()
        with self._lock:
            self.gauges[(name, label_key)] = float(value)

    def observe_latency(self, name: str, duration_sec: float) -> None:
        with self._lock:
            self.latencies[name].append(duration_sec)
            self.latency_counts[name] += 1
            self.latency_sums[name] += duration_sec

    def _format_labels(self, labels_tuple: Tuple[Tuple[str, str], ...]) -> str:
        if not labels_tuple:
            return ""
        items = [f'{k}="{_escape_label_value(v)}"' for k, v in labels_tuple]
        return "{" + ",".join(items) + "}"

    def generate_prometheus_text(self) -> str:
        lines: List[str] = []
        with self._lock:
            # Emit Gauges
            gauge_names = {name for (name, _) in self.gauges.keys()}
            for gname in sorted(gauge_names):
                lines.append(f"# TYPE {gname} gauge")
            for (name, label_tuple), val in sorted(self.gauges.items()):
                lines.append(f"{name}{self._format_labels(label_tuple)} {val}")

            # Emit Counters
            counter_names = {name for (name, _) in self.counters.keys()}
            for cname in sorted(counter_names):
                lines.append(f"# TYPE {cname} counter")
            for (name, label_tuple), val in sorted(self.counters.items()):
                lines.append(f"{name}{self._format_labels(label_tuple)} {val}")

            # Emit Summaries (Latency)
            for name, samples_deque in self.latencies.items():
                if not samples_deque:
                    continue
                sorted_samples = sorted(samples_deque)
                n = len(sorted_samples)

                # Standard 0-indexed quantile: int((n - 1) * p)
                def get_quantile(p: float) -> float:
                    idx = max(0, min(int((n - 1) * p), n - 1))
                    return sorted_samples[idx]

                lines.append(f"# TYPE {name} summary")
                lines.append(f'{name}{{quantile="0.5"}} {get_quantile(0.5):.6f}')
                lines.append(f'{name}{{quantile="0.9"}} {get_quantile(0.9):.6f}')
                lines.append(f'{name}{{quantile="0.95"}} {get_quantile(0.95):.6f}')
                lines.append(f'{name}{{quantile="0.99"}} {get_quantile(0.99):.6f}')
                lines.append(f"{name}_count {self.latency_counts[name]}")
                lines.append(f"{name}_sum {self.latency_sums[name]:.6f}")

        return "\n".join(lines) + "\n"


REGISTRY = MetricsRegistry()


def record_request(status: str = "success") -> None:
    REGISTRY.inc_counter("prismor_requests_total", labels={"status": status})


def record_finding(rule: str, category: str) -> None:
    REGISTRY.inc_counter("prismor_findings_total", labels={"rule": rule, "category": category})


def record_block(rule: str) -> None:
    REGISTRY.inc_counter("prismor_blocked_total", labels={"rule": rule})


def record_budget_rate_event(event_type: str) -> None:
    REGISTRY.inc_counter("prismor_budget_rate_events_total", labels={"type": event_type})


def record_latency(duration_sec: float) -> None:
    REGISTRY.observe_latency("prismor_enforcement_latency_seconds", duration_sec)