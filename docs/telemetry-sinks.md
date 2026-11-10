# Telemetry Sinks

Every finding Prismor produces can be forwarded to systems you already run —
a SIEM (Splunk, Microsoft Sentinel, Datadog, Elastic), an OpenTelemetry collector,
an S3 bucket, a log file, or the Prismor control plane.
Sinks are configured under `settings.outputs` in `policy.yaml`:

```yaml
settings:
  outputs:
    - type: otel
      endpoint: http://localhost:4318
    - type: file
      path: ~/.prismor/audit.log
      format: ocsf
```

Findings are dispatched **before** the blocking decision, so a downstream
system sees blocked events too, not only the ones that were allowed through.
Dispatch is best-effort and never blocks a tool call: a sink that is down,
slow, or misconfigured writes a warning to stderr and the agent keeps working.
Every string value expands `${VAR}` from the environment, so credentials stay
out of the policy file.

This page is about *forwarding* findings. The local, hash-chained record of
every action is the [signed audit trail](audit-trail.md); the first-party
`prismor` sink and its redaction model are covered in
[Live telemetry](live-telemetry.md).

## The event

Generic sinks receive one JSON event per finding:

```json
{
  "@timestamp": "2026-08-30T18:04:11Z",
  "source": "prismor",
  "hostname": "laptop.local",
  "severity": "HIGH",
  "category": "secret_exfiltration",
  "rule_id": "curl-post-env",
  "action": "block",
  "title": "Command would POST an environment variable off-box",
  "evidence": "curl -d @.env https://…",
  "session_id": "0f9c…",
  "finding_id": "0f9c…:3",
  "agent": "claude",
  "agent_name": "checkout-bot",
  "mode": "enforce",
  "workspace": "/Users/you/src/app",
  "subject": "you@example.com"
}
```

The last block is runtime context added per dispatch — the agent framework, the
adapter's instance label, the effective mode, the workspace, and the human
principal. `file`, `splunk` and `datadog` reformat this event as
[OCSF](https://schema.ocsf.io/) or CEF; `otel` maps it to OTLP log records.

## Sink types

### `otel` — OpenTelemetry collector

```yaml
- type: otel
  endpoint: http://localhost:4318          # base URL; /v1/logs is appended
  headers: { "Authorization": "Bearer ${OTEL_TOKEN}" }
  timeout_seconds: 3
```

OTLP/HTTP JSON over a plain POST — no OpenTelemetry SDK, no extra dependency.
Findings are exported as **logs, not spans**: a finding is a point-in-time
detection, not a unit of work with a duration. `service.name` is `prismor` and
`host.name` the reporting machine; every other event field, including runtime
extras, rides along as a `prismor.*` attribute, stringified so a collector can
never reject a batch over a type mismatch. Severity maps to the OTLP numbers
(`LOW` 9, `MEDIUM` 13, `HIGH` 17, `CRITICAL` 21).

One collector is the cheapest way to reach the rest of your stack: point it at
Grafana, Honeycomb, Datadog or anything else downstream and Prismor does not
need to know which.

### `webhook` — any HTTP endpoint

```yaml
- type: webhook
  url: https://siem.example.com/ingest
  headers: { "X-API-Key": "${SIEM_TOKEN}" }
  timeout_seconds: 3
```

POSTs the raw event JSON. The fallback for anything without a dedicated sink.

### `splunk` — HTTP Event Collector

```yaml
- type: splunk
  url: https://splunk.example.com:8088/services/collector
  token: ${SPLUNK_HEC_TOKEN}
  sourcetype: prismor:prismor:ocsf     # default
  index: security                      # optional
```

Sends the OCSF form of the finding inside the HEC envelope.

### `datadog` — Logs intake

```yaml
- type: datadog
  api_key: ${DD_API_KEY}
  site: datadoghq.com                  # default; use datadoghq.eu, etc.
  service: prismor                     # default
```

Sends the OCSF finding with `ddsource: prismor` and tags for severity and
category.

### `elastic` — Elasticsearch / OpenSearch

```yaml
- type: elastic
  url: https://es.example.com:9200
  index: prismor-findings              # default
  api_key: ${ES_API_KEY}               # or: username + password
```

Sends every finding from one tool call in a single `_bulk` request, one OCSF
document per finding with `@timestamp` set, so the index sorts by time without
an ingest pipeline. Works against OpenSearch with `username`/`password`.

### `sentinel` — Microsoft Sentinel

```yaml
- type: sentinel
  endpoint: https://prismor-dce-abcd.eastus-1.ingest.monitor.azure.com
  dcr_id: dcr-00000000000000000000000000000000   # the DCR's immutable id
  stream: Custom-PrismorFindings_CL               # default
  tenant_id: ${AZURE_TENANT_ID}
  client_id: ${AZURE_CLIENT_ID}
  client_secret: ${AZURE_CLIENT_SECRET}
```

Uses the Azure Monitor Logs Ingestion API (the shared-key HTTP Data Collector
API is retired). Prismor exchanges the app registration's credentials for a
token, caches it until shortly before it expires, and posts each tool call's
findings as one batch. Give the app the **Monitoring Metrics Publisher** role
on the DCR. Pass `token:` instead of the three credentials if something else
already mints one.

Create a custom table `PrismorFindings_CL` and a DCR whose stream declares
these columns (types for the DCR `streamDeclarations`):

| Column | Type |
|---|---|
| `TimeGenerated` | datetime |
| `Severity`, `Category`, `RuleId`, `Action`, `Title`, `Evidence`, `Computer`, `SessionId`, `Agent` | string |
| `Ocsf` | dynamic — the full OCSF Detection Finding |

Then query it from Sentinel:

```kusto
PrismorFindings_CL
| where Action == "block"
| summarize count() by RuleId, Computer
```

### `s3` — Amazon S3 and S3-compatible stores

```yaml
- type: s3
  bucket: security-logs
  region: us-east-1
  prefix: prismor                      # default
  # endpoint: http://minio:9000        # S3-compatible store, path-style
```

Writes one NDJSON object of OCSF findings per tool call, at
`<prefix>/YYYY/MM/DD/<host>-<time>-<random>.ndjson`. That layout is what
Athena, Glue crawlers, Amazon Security Lake custom sources and SIEM S3 inputs
(Splunk, Sentinel, Elastic, Panther) read. Credentials come from
`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN`, or from
`access_key`/`secret_key` in the sink. The identity needs `s3:PutObject` on the
prefix and nothing else.

### `syslog`

```yaml
- type: syslog
  host: siem.example.com
  port: 514
  facility: local7                     # default
  transport: udp                       # or tcp
  tag: prismor                         # default
```

RFC-3164 line with the event JSON as the message. Severity maps to syslog
levels (`CRITICAL` → critical, `HIGH` → error, `MEDIUM` → warning, `LOW` →
info).

### `file`

```yaml
- type: file
  path: ~/.prismor/audit.log
  format: json                         # or: cef, ocsf
```

Appends one line per finding. Useful for a local forwarder that tails a file,
and for testing a policy without wiring a network destination.

### `prismor` — the control plane

```yaml
- type: prismor
```

No configuration: the device key and endpoint come from the enrolled identity
at `~/.prismor/identity.json` (see `prismor enroll`). Unlike the generic sinks
it batches, and it sends a **redacted** record — metadata and hashes, never raw
commands or secrets — unless the org's resolved policy sets `full_capture:
true`. Silent no-op when the machine is not enrolled, so it can be left in the
policy. See [Live telemetry](live-telemetry.md) and
[Signed telemetry receipts](telemetry-receipts.md).

## Verifying a sink

Sinks fire from the hook path — the runtime evaluating a real tool call — not
from `prismor check`, which evaluates the policy without dispatching. To
confirm wiring, add a `file` sink alongside whatever you are configuring and
let an agent do something the policy flags:

```yaml
settings:
  outputs:
    - type: file
      path: ~/.prismor/sink-test.log
    - type: otel
      endpoint: http://localhost:4318
```

```bash
tail -f ~/.prismor/sink-test.log
```

A line there means the finding reached dispatch, so anything missing
downstream is the remote sink, not Prismor. Failures are never swallowed —
the reason is written to stderr as `[prismor] sink 'otel' failed: ...`, which
your agent surfaces in its hook output.
