# MCP Gateway

`prismor mcp-gateway` is a single MCP connector that fronts **all** of your MCP
servers. Your agent (Claude Code, Cursor, Claude Desktop — any MCP client) is
configured with one MCP server: Prismor. The gateway aggregates your real
servers behind it and becomes the enforcement point for every tool call:

- **Outbound**: every `tools/call` is evaluated against your Prismor policy
  before it is forwarded — org tool denies, lethal-trifecta tag crossover
  (e.g. *read email* + *send message* in one session), per-agent kill
  switches, IAM, and all policy rules.
- **Inbound**: every tool **result** is scanned as untrusted content (prompt
  injection, poisoned tool output) before the model ever sees it. A flagged
  response is withheld and replaced with the reason.
- **Telemetry**: with a `PRISMOR_AGENT_KEY` (or an enrolled device), every
  verdict streams to the control plane and signed policy updates are pulled
  on the hot path — an admin's tool deny or kill switch takes effect on the
  next call.

Zero per-framework code: any MCP-speaking agent gets coverage without a hook
install or SDK adapter.

## Quick start

1. Move your existing `mcpServers` block into the gateway config
   (`~/.prismor/mcp-gateway.json`) — verbatim, same shape:

   ```json
   {
     "mcpServers": {
       "github": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"]},
       "linear": {"url": "https://mcp.linear.app/sse", "type": "sse"}
     }
   }
   ```

2. Point your agent's `.mcp.json` at the gateway instead:

   ```json
   {
     "mcpServers": {
       "prismor": {
         "command": "prismor",
         "args": ["mcp-gateway", "--config", "~/.prismor/mcp-gateway.json"]
       }
     }
   }
   ```

Or let Prismor do both steps for the current workspace:

```bash
prismor mcp-gateway install       # moves this workspace's .mcp.json servers (backup kept)
prismor mcp-gateway install --all # every MCP config on this machine
prismor mcp-gateway uninstall     # restores the original .mcp.json
```

`--all` migrates every config `prismor discover` can find — Claude Desktop,
Cursor, Windsurf, VS Code, Cline — not just the workspace's own `.mcp.json`.
It handles any JSON config declaring servers under `mcpServers` or `servers`
(VS Code's spelling), preserves everything outside that block verbatim, and
writes a `.bak` alongside each file before changing it.

A config whose shape it does not recognise is reported and **left untouched**
rather than guessed at — Zed declares servers under `context_servers`, and
Codex uses TOML. Move those two by hand.

Your agent now sees the same tools, namespaced as `<server>__<tool>`
(e.g. `github__create_issue`), and every call and response flows through
Prismor.

## Modes and flags

```bash
prismor mcp-gateway [serve] [--config PATH] [--mode enforce|observe]
                    [--upstream <url|'command'>] [--server name=<url|command>]
                    [--namespace plain|none] [--workspace PATH]
```

- `--mode enforce` blocks policy violations; `observe` logs only. A bare
  `serve` defaults to `observe`; `install` writes `--mode enforce` into the
  configs it migrates.
  The control plane can still force enforce per agent/device.
- **Shim mode** — front a single server with no config file:
  `prismor mcp-gateway --upstream 'npx -y @modelcontextprotocol/server-github'`
  or `--upstream https://mcp.linear.app/sse`. Add `--namespace none` to keep
  raw tool names.
- `--server github='npx -y @modelcontextprotocol/server-github'` declares
  upstreams inline (repeatable).

Downstream transports: stdio subprocesses and streamable-HTTP/SSE URLs. The
client-facing side is stdio.

## How blocking looks to the agent

A denied call returns a normal MCP tool result with `isError: true`:

```
Blocked by Prismor: [critical] Untrusted content + critical action in one
session (rule: trifecta-crossover)
Recommended fix: ...
```

The model reads the reason and can adapt or ask the user. A flagged tool
*response* is replaced the same way (`[Prismor] response withheld: ...`).
JSON-RPC errors are used only for protocol failures (unknown tool, upstream
server died).

## Mirrored built-ins (`--mirror`, `prismor mirror`)

> Choosing between this and hooks: see
> [Governance surfaces](governance-surfaces.md). Short version — hooks
> wherever the agent has them, the mirror where it does not.

Hooks see a tool call before it runs, but they cannot hand the model a
*redacted* file, and hostless agents have no hooks at all. With `--mirror` the
gateway also serves Prismor-executed look-alikes of the agent's own
`Bash` / `Read` / `Write` / `Edit` / `Glob` / `Grep` / `WebFetch` — same names, same
schemas — so the tool executes inside Prismor: policy before, the real output
redacted after, one telemetry event, reported under the native tool name so
every rule and deny written against `Bash` keeps applying.

For Claude Code there is a one-command switch:

```bash
prismor mirror on            # register the mirror + deny the native tools (next session)
prismor mirror status        # configured? governing / pass-through / paused? live gateways?
prismor mirror off           # hand the built-ins back to the agent (next session)
```

Switching a host over takes four coordinated changes, and missing any one of
them leaves the agent with *no* file or shell tools — the natives are denied but
the replacement never loads. `on` does all four, backing up each file it touches
as `*.pre-mirror.bak` and changing nothing else in them:

| # | Change | File | Why it is required |
|---|---|---|---|
| 1 | `prismor-tools` server entry | `.mcp.json` | serves the mirrored built-ins |
| 2 | natives denied | `.claude/settings.json` | so the model reaches for the mirror, not its own tools |
| 3 | `enabledMcpjsonServers: ["prismor-tools"]` | `.claude/settings.local.json` | a project-declared MCP server does not load until a human trusts it — and a project file cannot vouch for itself, so putting this in the shared `settings.json` does nothing |
| 4 | `mcp__prismor-tools__*` allowed | `.claude/settings.json` | MCP tools sit behind the same permission prompt as any tool, and renaming `Bash` invalidates every allow rule the human had |

Step 4 translates rather than grants: a native that was already allowed gets its
mirrored twin allowed, one that was not keeps prompting exactly as before.
Headless runs (`claude -p`, CI) cannot answer a prompt at all — use
`prismor mirror on --allow-tools` there to pre-allow the whole roster.

`off` removes exactly those four. `--mode observe` logs without blocking.

Scope is deliberately the project you are standing in, with no machine-wide or
agent-wide variant. Fleet-level rollout belongs to the control plane, which
already pushes device mode, agent kill switches and pause that way — those are
an administrator's decisions, not a CLI's. (The user-level MCP config is also
owned and rewritten wholesale by the running host, so an edit there does not
reliably survive.)

### Codex

```bash
prismor mirror on --agent codex        # machine-wide
prismor mirror off --agent codex
```

Wired through Codex's own CLI (`codex mcp add`, `codex features disable`) rather
than by editing `config.toml`, so the vendor's supported writer owns its own
file. Two differences from Claude Code, both stated by the command before it
changes anything:

- **Machine-wide, not per project.** Codex reads MCP servers and `[features]`
  only from the user-level config — a project-scoped `.codex/config.toml` is
  ignored for features — so there is no project variant to offer.
- **The sandbox gates mirrored calls, not approvals.** A mirrored tool runs
  inside Prismor, outside Codex's OS sandbox, so a restrictive sandbox cancels
  it with `user cancelled MCP tool call`, and `approval_policy="never"` does
  *not* change that. Run Codex with a sandbox mode that permits the call. This
  is a real trade: mirroring Codex swaps its OS-level sandboxing for Prismor's
  policy and redaction.

Both `shell_tool` **and** `unified_exec` are disabled: `unified_exec` is a
second shell surface, and leaving it on lets the model route around the mirror.
`off` re-enables only the features `on` actually turned off.

Verified on codex-cli 0.145.0: `config.py` came back as
`postgres://[REDACTED:secret]@db.internal…` and a `.env` read was blocked —
result-side redaction Codex has never had (see prismor#152).

### OpenCode

```bash
prismor mirror on --agent opencode     # this project
prismor mirror off --agent opencode
```

The highest-value host to mirror: OpenCode has no hook protocol, so MCP is the
only interposition point that exists for it - without this Prismor cannot see an
OpenCode session at all.

Everything is one project-scoped `opencode.json`, and there is **no trust gate** -
the project file both declares the server and grants it. Note the MCP block is
keyed directly under `mcp`, **not** `mcp.servers`, which published guidance says
and OpenCode 1.18 rejects.

Verified on OpenCode 1.18.16: after `on`, `opencode mcp list` reports
`prismor-tools connected` and `opencode debug agent build` shows
`bash, read, write, edit, grep, glob` all disabled; `off` restores them and
leaves any tool the developer had disabled themselves alone.

Other hosts: run `prismor mcp-gateway --mirror` as an MCP server and disable the
host's own built-ins yourself. The server is host-agnostic — only the config
wiring is per-host, and `prismor mirror status` lists what is wired today.

**One Prismor, not two.** The hook layer and the gateway both see a mirrored
call and stay consistent only because they share code: the gateway drops a
marker the hook reads (screened once, not twice) and the hook maps
`mcp__prismor-tools__Bash` back to `Bash` (so a session scope judges it as the
tool it really is). If `prismor install-hooks` wired an older or different
checkout, both agreements break — the scope denies what the gateway allows, and
`prismor pause` reaches only one layer. `mirror on` and `mirror status` compare
the two and warn; the fix is to re-run `prismor install-hooks` from the same
install.

**Getting out of the way — no restart needed.** Both are read on every call:

- `prismor pause` lifts enforcement for the gateway exactly as it does for the
  hooks: calls still execute, still get evaluated and logged, but nothing is
  blocked, withheld, or redacted until `prismor resume` (or the 24h
  auto-resume). This applies to remote MCP servers behind the gateway too.
- `prismor mirror passthrough on` does the same for just this workspace's
  mirror, indefinitely — the same switch as the mirror card in
  `prismor dashboard`. The mirror keeps *serving* its tools while passing
  through: the host's natives are denied, so a mirror that went silent would
  leave the agent with no shell or file access mid-session.

A blocked mirrored call tells the agent which of these to ask the human to
run. The agent cannot run them itself: `prismor mirror on|off|passthrough`,
`prismor pause`, and writes to `.prismor/mirror.json` are covered by the
`prismor-self-edit` rule, so an agent whose Bash *is* the mirror cannot hand
itself the native tools back (see [Policy layers](policy-layers-and-exemptions.md)).

Tools the host owns cannot be mirrored (`Task`/`Agent`, `Skill`,
`AskUserQuestion`); they stay native. `on` also denies `MultiEdit` and
`NotebookEdit`, since an ungoverned native file-writer next to a governed
`Edit` would be a bypass, not a mirror.

## Policy matching

Events are recorded with `tool_name = mcp__<server>__<tool>` using the **real
downstream server name** — so existing matchers work unchanged: trifecta tag
defaults (`mcp__*__send_email`), org tool denies, tool-tag rules pushed from
the control plane, and the console's tool inventory. One gateway process is
one Prismor session; the trifecta ledger spans your whole agent session.

## Server-declared tags (`_meta`)

At `tools/list` time the gateway reads tags a server self-declares on each
tool definition — `_meta.prismor.tags` (also `_meta.tags` or
`annotations["prismor/tags"]`) — sanitizes them, and stamps them onto every
call event. They feed tool-tag classification *below* the explicit org map:
an admin's tag always wins over a server's self-declaration. See
[Tool Tags](tool-tags.md).

## Governing tools (admins)

Beyond blocking a whole server, an admin can turn off **individual tools** —
for everyone, or for one person — from the console **MCP Hub** (per-server
*Tools* panel):

- **For everyone:** an org-scoped tool deny on `mcp__<server>__<tool>`. It
  rides the signed org policy, so it applies to every gateway — local and
  hosted alike. The same thing can be set as code in `policy.yaml`
  (`settings.tool_denies`) and shipped with `prismor-cli policy apply`.
- **For one person:** a per-user rule (`settings.subject_controls` →
  `deny_tools` for `user:<id>`). It applies when the gateway runs under that
  person's subject — a hosted instance bound to them, or `PRISMOR_SUBJECT`
  set locally. A denied tool is blocked before it reaches the server, with the
  usual `isError` reason returned to the model.

## Hosted instances (Enterprise)

Everything above runs the gateway **locally** on your machine — available on
every plan. Enterprise adds a **hosted** option: from the MCP Hub in the
console, *Spin up MCP instance* provisions a governed MCP URL on Prismor's
managed edge:

```
https://mcp.prismor.dev/mcp/<instance-key>
```

Paste that one URL into any agent, on any machine — no local install. The
servers you registered in the Hub are attached automatically (their secrets
stay server-side, encrypted at rest and only ever decrypted for the fleet).
The instance is a service identity, so the full control loop applies: every
call is policy-evaluated and streamed to your Activity feed, an admin can flip
it between observe/enforce from the console, and revoking it is an instant kill
switch. The instance key *is* the credential in the URL — treat it like a
secret; it's shown only once.

Local gateway vs hosted instance:

| | Local (`prismor mcp-gateway`) | Hosted instance |
|---|---|---|
| Plan | Any | Enterprise |
| Runs on | Your machine | Prismor edge (mcp.prismor.dev) |
| Setup | CLI / config file | One click, paste a URL |
| Secrets | In your local config | Encrypted server-side |
| Telemetry / policy / kill switch | Yes (enrolled) | Yes (built in) |

## Notes

- The gateway config may contain tokens in `env` blocks; `install` writes it
  with `0600` permissions and Prismor never logs config values.
- Aggregation is tools-only: resources/prompts from downstream servers are
  not advertised in v1.
- If policy evaluation itself fails in enforce mode, the call is **denied**
  (fail-closed), never silently allowed.
