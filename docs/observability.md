# Observability & Prometheus Metrics

The dashboard server exposes a Prometheus text exposition at `/metrics`.

## Where the numbers come from

Every metric is read back out of the session store on each scrape, not counted
in memory. The hook dispatcher (`prismor/runtime/cli.py`) is a separate
short-lived process per tool call — a counter incremented there would die with
the hook and never reach the long-lived `prismor serve` process that answers the
scrape. The store is the only state the two share.

That has one consequence worth knowing: `/metrics` reflects what has been
persisted, so it inherits the store's latency, and a workspace that is not
registered does not appear.

## Scrape configuration

Start the server, then point Prometheus at it:

```bash
prismor serve --port 7070
```

```yaml
scrape_configs:
  - job_name: 'prismor'
    scrape_interval: 30s
    static_configs:
      - targets: ['localhost:7070']
```

A scrape that cannot read the store answers `500` rather than an empty body, so
the target goes down in Prometheus instead of graphing a flat zero.

## Metrics

Counters are queried over an unbounded window so they stay monotonic and are
safe under `rate()`. Gauges use the dashboard's own 24h window.

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `prismor_tool_calls_total` | counter | `tool` | Tool calls inspected, by tool |
| `prismor_threats_total` | counter | `category` | Threat findings, by category |
| `prismor_blocked_total` | counter | `agent` | Blocked commands, by agent |
| `prismor_pattern_hits_total` | counter | `pattern`, `category`, `severity` | Top 20 finding patterns |
| `prismor_active_sessions` | gauge | — | Sessions active in the last 24h |
| `prismor_tool_calls_inspected_24h` | gauge | — | Tool calls inspected in the last 24h |
| `prismor_dangerous_commands_prevented_24h` | gauge | — | Dangerous commands prevented in the last 24h |
| `prismor_findings_by_severity` | gauge | `severity` | Findings in the last 24h, by severity |
| `prismor_hook_latency_seconds` | summary | `quantile` | Per-call hook duration (p50/p90/p95/p99) |

`prismor_pattern_hits_total` is capped at 20 series because its `pattern` label
carries a finding title; without the cap the family grows one series per
distinct title.

## Grafana

`grafana/prismor-dashboard.json` imports as-is — the datasource is a
`DS_PROMETHEUS` input, so Grafana prompts for it on import rather than pinning a
uid. Four panels: tool call volume, threat rate by category, findings by
severity, and hook latency percentiles.
