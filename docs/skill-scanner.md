# Skill Scanner

MCP servers and skills extend what your agent can do, but they also extend the attack surface. Studies have found that a significant percentage of community skills contain malicious patterns. Prismor's skill scanner checks every MCP server and skill config installed on your machine before you use them.

```bash
prismor scan                    # scan all agents (Claude, Cursor, Windsurf, OpenClaw, Hermes)
prismor scan --agent claude     # only Claude Code configs
prismor scan --json             # machine-readable output
```

## Config locations

The scanner automatically discovers configs from:

| Agent       | Config locations checked                                           |
| ----------- | ------------------------------------------------------------------ |
| Claude Code | `~/.claude/settings.json`, `.claude/settings.json`                 |
| Cursor      | `~/.cursor/mcp.json`, `.cursor/mcp.json`                           |
| Windsurf    | `~/.codeium/windsurf/mcp_config.json`, `.windsurf/mcp.json`        |
| OpenClaw    | `~/.openclaw/config.json`, `~/.openclaw/skills.json`               |
| Hermes      | `~/.hermes/config.json`, `~/.hermes/skills.json`, `~/.hermes/plugins.json` |

Each MCP server and skill entry is evaluated against Prismor's policy rules. Findings are sorted by severity (critical first) so the most dangerous issues are always at the top.

## Remote MCP transport checks

MCP servers increasingly run over the network (`http`, `sse`, `streamable-http`) instead of a local stdio process. `prismor scan` audits the transport of every remote MCP server it discovers and raises a finding for each insecure pattern:

| Rule ID                      | Severity | What it flags                                                                 |
| ---------------------------- | -------- | ----------------------------------------------------------------------------- |
| `mcp-cleartext-transport`    | HIGH     | Endpoint uses `http://` or `ws://` — traffic and tokens travel unencrypted    |
| `mcp-remote-raw-ip`          | HIGH     | Endpoint is a bare IP address — no TLS hostname trust, a common C2 shape       |
| `mcp-remote-not-allowlisted` | MEDIUM   | Endpoint domain is not on your `egress_allowlist` (raw IPs use the rule above) |
| `mcp-hardcoded-secret`       | MEDIUM   | A literal token sits in the server's `headers`/`env` instead of `${ENV}` or cloaking |

`mcp-hardcoded-secret` only fires on literal values — `${VAR}` references and `@@SECRET:<name>@@` cloaking placeholders are treated as safe — and the secret value is never printed in the finding's evidence.

### Configuring the action

By default these findings are warnings. Set them to block (they then carry `action: block` in `prismor scan --json`, and block in enforce mode) in your project's `.prismor/policy.yaml`:

```yaml
settings:
  mcp_transport_action: block   # "warn" (default) or "block"
```

## Hermes gateway

Hermes stores per-session JSONL transcripts at `~/.hermes/sessions/` and a queryable SQLite index with FTS5 at `~/.hermes/state.db`. Prismor hooks intercept tool calls at the gateway layer before the transcript is written. The session store can also be ingested offline for retrospective analysis:

```bash
prismor analyze-history --agent hermes
```
