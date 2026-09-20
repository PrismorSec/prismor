"""Tests for Prometheus metrics exporter and /metrics server endpoint."""

import unittest
from prismor.runtime.metrics import (
    MetricsRegistry,
    record_request,
    record_finding,
    record_block,
    record_budget_rate_event,
    record_latency,
    REGISTRY,
)


class TestMetricsRegistry(unittest.TestCase):
    def setUp(self):
        self.registry = MetricsRegistry()

    def test_counter_increments(self):
        self.registry.inc_counter("test_counter", 1.0, labels={"status": "ok"})
        self.registry.inc_counter("test_counter", 2.0, labels={"status": "ok"})
        
        output = self.registry.generate_prometheus_text()
        self.assertIn('test_counter{status="ok"} 3.0', output)

    def test_latency_percentiles(self):
        # Insert known latency distribution
        for i in range(1, 101):
            self.registry.observe_latency("test_latency_seconds", float(i))

        output = self.registry.generate_prometheus_text()
        self.assertIn('test_latency_seconds{quantile="0.5"} 51.000000', output)
        self.assertIn('test_latency_seconds{quantile="0.9"} 90.000000', output)
        self.assertIn('test_latency_seconds{quantile="0.95"} 95.000000', output)
        self.assertIn('test_latency_seconds{quantile="0.99"} 99.000000', output)
        self.assertIn("test_latency_seconds_count 100", output)

    def test_global_helper_functions(self):
        record_request(status="blocked")
        record_finding(rule="prompt_injection", category="security")
        record_block(rule="secret_leak")
        record_budget_rate_event(event_type="rate_limit")
        record_latency(0.045)

        output = REGISTRY.generate_prometheus_text()
        self.assertIn('prismor_requests_total{status="blocked"}', output)
        self.assertIn('prismor_findings_total{category="security",rule="prompt_injection"}', output)
        self.assertIn('prismor_blocked_total{rule="secret_leak"}', output)
        self.assertIn('prismor_budget_rate_events_total{type="rate_limit"}', output)
        self.assertIn("prismor_enforcement_latency_seconds", output)


if __name__ == "__main__":
    unittest.main()
      
