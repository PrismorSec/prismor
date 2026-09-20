"""Lightweight Prometheus metrics exporter for Prismor runtime."""

import threading
import time
from collections import defaultdict


class MetricsRegistry:
    def __init__(self):
        self._lock = threading.Lock()
        # Counters: (name, tuple of sorted (label_key, label_val)) -> float/int
        self.counters = defaultdict(float)
        # Latency samples: name -> list of latencies
        self.latencies = defaultdict(list)

    def inc_counter(self, name: str, value: float = 1.0, labels: dict = None):
        label_key = tuple(sorted(labels.items())) if labels else ()
        with self._lock:
            self.counters[(name, label_key)] += value

    def observe_latency(self, name: str, duration_sec: float):
        with self._lock:
            self.latencies[name].append(duration_sec)
            # Retain a moving window of the last 10,000 requests
            if len(self.latencies[name]) > 10000:
                self.latencies[name] = self.latencies[name][-10000:]

    def _format_labels(self, labels_tuple: tuple) -> str:
        if not labels_tuple:
            return ""
        items = [f'{k}="{v}"' for k, v in labels_tuple]
        return "{" + ",".join(items) + "}"

    def generate_prometheus_text(self) -> str:
        lines = []
        with self._lock:
            # Output Counters
            for (name, label_tuple), val in sorted(self.counters.items()):
                lbl_str = self._format_labels(label_tuple)
                lines.append(f"{name}{lbl_str} {val}")

            # Output Latency Percentiles
            for name, samples in self.latencies.items():
                if not samples:
                    continue
                sorted_samples = sorted(samples)
                n = len(sorted_samples)
                p50 = sorted_samples[int(n * 0.50)]
                p90 = sorted_samples[min(int(n * 0.90), n - 1)]
                p95 = sorted_samples[min(int(n * 0.95), n - 1)]
                p99 = sorted_samples[min(int(n * 0.99), n - 1)]

                lines.append(f'{name}{{quantile="0.5"}} {p50:.6f}')
                lines.append(f'{name}{{quantile="0.9"}} {p90:.6f}')
                lines.append(f'{name}{{quantile="0.95"}} {p95:.6f}')
                lines.append(f'{name}{{quantile="0.99"}} {p99:.6f}')
                lines.append(f"{name}_count {n}")
                lines.append(f"{name}_sum {sum(sorted_samples):.6f}")

        return "\n".join(lines) + "\n"


REGISTRY = MetricsRegistry()


# Helper hooks to match issue requirements
def record_request(status: str = "success"):
    REGISTRY.inc_counter("prismor_requests_total", labels={"status": status})


def record_finding(rule: str, category: str):
    REGISTRY.inc_counter("prismor_findings_total", labels={"rule": rule, "category": category})


def record_block(rule: str):
    REGISTRY.inc_counter("prismor_blocked_total", labels={"rule": rule})


def record_budget_rate_event(event_type: str):
    REGISTRY.inc_counter("prismor_budget_rate_events_total", labels={"type": event_type})


def record_latency(duration_sec: float):
    REGISTRY.observe_latency("prismor_enforcement_latency_seconds", duration_sec)
