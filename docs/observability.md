# Observability & Prometheus Metrics

Prismor exposes an OpenMetrics/Prometheus compatible `/metrics` endpoint on the dashboard server.

## Prometheus Scrape Configuration

Add the following to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'prismor'
    scrape_interval: 15s
    static_configs:
      - targets: ['localhost:7070']