# Shadow-agent discovery

`prismor discover` still inventories agents, MCP servers, and provider keys
and prints the legacy report.

`prismor discover mcp` also shows, for each server, how many copies are
running and their resident memory (stdio servers, from `ps`), and for Claude
Code servers how many sessions in the last 7 days called one of its tools
(from the local store). An agent starts its own copy of every server in its
user-level config for each session, so a server that runs in 3 or more
copies but was called in fewer than 1 in 10 of at least 10 sessions is
flagged: declare it only in the projects that use it.

Two flags act on the flagged servers. Both list what they will do and ask
first (`-y` skips the question):

- `--prune` removes them from the user-level config file, after copying it to
  `<file>.prismor-<time>.bak`. New sessions stop starting them. To use one in a
  project, copy its entry from the backup into that project's `.mcp.json`.
- `--stop` ends the copies running now (each copy and everything under it).
  Sessions that are open lose those servers' tools until they restart. Without
  `--prune`, new sessions start them again.

The surfaces below add a unified inventory
(`prismor.inventory.v1`, one JSON object per line).

| Command | What it reads |
|---|---|
| `prismor discover endpoint --all-users` | Local profiles: agents, MCP configs, JetBrains, VS Code-family extensions, WSL homes |
| `prismor discover jetbrains` | JetBrains IDEs, AI Assistant, Junie, Copilot for JetBrains |
| `prismor discover extensions` | VS Code, Insiders, vscode-server, Cursor, Windsurf extension directories |
| `prismor discover wsl` | Running WSL distros only (`wsl.exe -l --running -q`) |
| `prismor discover inventory` | Whatever `inventory.yaml` lists under `surfaces` |

Output is a table on a terminal and NDJSON otherwise. `--format json|ndjson|table`,
`--out FILE`, `--sink NAME`, `--fail-on low|medium|high|critical`,
`--dry-run`, `--strict`. Exit codes: 0 ok, 1 risk threshold, 2 usage,
3 auth failure (plugin collectors), 4 diagnostics with `--strict`.

Secrets are names only. Usernames are HMAC-SHA256 with the org salt
(`hash_users: true` by default). Commands go through `redact_command`, URLs
through `redact_url`.

## Try it on the fixtures

```bash
PRISMOR_INVENTORY_OS=windows \
PRISMOR_INVENTORY_PROFILES=tests/fixtures/inventory/windows-dev/profiles \
PRISMOR_INVENTORY_WSL=tests/fixtures/inventory/windows-dev/wsl \
PRISMOR_INVENTORY_SALT=demo \
python3 -m prismor.runtime.cli discover endpoint --all-users --format table \
  --workspace tests/fixtures/inventory/windows-dev/workspace
```

## Fleet

`prismor system-sync` (already scheduled every minute as SYSTEM) calls
`maybe_fleet_scan` when `inventory.yaml` exists and the interval has elapsed.
Results land in `<system directory>/inventory/last.ndjson`
(`C:\ProgramData\Prismor\inventory` on Windows,
`/Library/Application Support/Prismor/inventory` on macOS,
`/etc/prismor/inventory` on Linux). Intune passes `-Discover`.
Sinks are listed in `inventory.yaml`; their secrets stay in the environment.
An inventory sink can point at a policy output instead of repeating it, so
events and inventory share one connection. Keys next to `ref` override the
output's; `--sink` takes the output's name:

```yaml
sinks:
  - ref: contoso-sentinel   # a settings.outputs name in policy.yaml
```

See [Deploy with Intune](deploy-intune.md).

## Plugins

Collectors and sinks can ship outside this package. A collector registers
under the `prismor.inventory_collectors` entry-point group (a module with
`SURFACE` and `collect(ctx)`; the entry point name becomes the
`prismor discover <name>` alias). A sink registers under `prismor.sinks`: the
entry point name is the sink `type`, and the module may define
`dispatch_events(cfg, events)`, `dispatch_inventory(cfg, rows)` and the
lifecycle hooks `start_background`, `exit_flush`, `system_sync` and `doctor`.
Events and rows are built and scrubbed here before any plugin sees them.

## Unverified in this build

Items marked `verified: false` in `prismor/runtime/inventory/catalog/` still
match, with `confidence: unverified`. See the catalog NOTICE and the pull
request for the list. JetBrains `llm.mcpServers.xml` element names come from
published user configs; the official help page documents the JSON shape only.
Cursor and Windsurf extension directories were not confirmed
against a current vendor doc.
