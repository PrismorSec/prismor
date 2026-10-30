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


## Tools a caller can never use are not listed

In enforce mode, `tools/list` leaves out the tools this caller could only fail
with, so the agent never plans around them. A tool is hidden when every call to
it would be refused whatever its arguments:

- a control-plane refusal: agent paused, the tool denied for this agent or org,
  the end user suspended or denied the tool, or identity required and missing;
- a [`when:`](attribute-conditions.md) rule matched on the tool name whose
  condition reads no `args.*` or `resource.*` (for example
  `when: "'admin' not in principal.roles"`).

A tool whose outcome depends on its arguments (`args.amount >= 500`) stays
listed and is decided per call.

To filter by the user's verified roles, give the gateway the user's token and
your IdP (the same flags as `eval-server`):

```bash
PRISMOR_IDENTITY_TOKEN_FILE=/run/user/1000/idp-token \
prismor mcp-gateway --mode enforce \
  --identity-issuer https://acme.okta.com/oauth2/default \
  --identity-audience api://agents --identity-roles-claim groups \
  --identity-mode require
```

The token file is re-read on every call, so a refresher can rotate it as the
token expires; `PRISMOR_IDENTITY_TOKEN` works for a static token. When the
token changes to another user, the gateway sends `tools/list_changed` on the
next call so the host re-lists with that user's tools. Under `require`, no
valid token means no tools. See [identity verification](identity-verification.md). Calling a hidden tool by name anyway is
blocked by the policy that hid it and logged like any other blocked call, so an
agent probing for denied tools shows up in the console. Observe mode hides
nothing (except tools a server entry's tool selection leaves out, below).
The gateway also passes each call's arguments to `when:` rules as `args.*`.

### Exposing only some of a server's tools

A server entry can name the tools the gateway exposes, by the names the server
lists them under (globs allowed):

```json
{
  "mcpServers": {
    "github": {
      "type": "http",
      "url": "https://api.githubcopilot.com/mcp/",
      "headers": { "Authorization": "Bearer ${GITHUB_PAT}" },
      "tools": { "allow": ["get_*", "list_*", "search_*"], "deny": ["get_secret_scanning_alert"] }
    }
  }
}
```

`allow` keeps only the matching tools (leave it out to keep every tool); `deny`
removes tools from what is left. A tool left out is hidden from `tools/list` in
every mode, and a call to it by name is denied and logged as an agent-control
block. Hosted endpoints use this for the tools you select per endpoint in the
console, and for **New tools start off**, where `allow` is the tools you have
reviewed, so a tool the server adds later stays off until you turn it on.

### Renaming tools, caching the tool list, and timeouts

```json
{
  "mcpServers": {
    "github": {
      "type": "http",
      "url": "https://api.githubcopilot.com/mcp/",
      "timeout": 60,
      "tools": {
        "cacheTtl": 300,
        "overrides": {
          "search_code": {
            "name": "find_code",
            "description": "Search code in the acme org only.",
            "inputSchema": { "type": "object", "properties": { "query": { "type": "string" } }, "required": ["query"] }
          }
        }
      }
    }
  }
}
```

- `tools.overrides` changes what the agent sees for a tool: its `name`,
  `description` or `inputSchema`. Use it to give an agent a description you have
  reviewed instead of whatever the server sends, or a narrower schema. It only
  changes the display. Policy rules, `allow`/`deny`, definition pinning and the
  console all keep the server's own name and definition, so renaming a tool
  does not get it past a rule that denies it, and a changed upstream definition
  is still caught. The new name is still namespaced (`github__find_code`).
- `tools.cacheTtl` reuses the server's tool list for that many seconds instead
  of asking it on every `tools/list`. The cache is dropped as soon as the
  server announces its tools changed. Leave it out to ask every time.
- `timeout` is how many seconds a tool call to this server may take (default
  300).

Five more keys on a server entry:

- `forwardHeaders: ["X-Request-Id"]` copies those headers from the caller's
  request to a remote server, on hosted endpoints (a local gateway has no
  caller headers). `Authorization`, `Cookie`, `Host`, `Content-Length` and
  `Mcp-Session-Id` are never forwarded, and the entry's own `headers` win over
  a caller's value.
- `logPayloads: true` keeps each call's arguments and result in the activity
  log, even when the organization keeps telemetry redacted. Both are masked
  first (cloaked secrets and data-boundary values), capped at 4 KB, and the
  record is marked as not redacted.
- `maxBodyBytes: 1048576` refuses a call whose arguments are bigger than this,
  and fails a call whose reply is, with an error naming the limit.
- `sigv4: {"service": "lambda", "region": "us-east-1"}` signs every request to
  a remote server with AWS SigV4, using `AWS_ACCESS_KEY_ID`,
  `AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN` from the environment or the
  entry's `env`. Without credentials the request is refused, never sent
  unsigned. OAuth sign-in is off for such a server.
- `managedSession: false` stops the gateway keeping the server's
  `Mcp-Session-Id`, for servers that reject sessions. By default it keeps the
  session and, when the server says it expired (HTTP 404), opens a new one and
  retries once.

## Signing in to OAuth servers

Many remote MCP servers (Linear, Stripe, Neon, PostHog, Atlassian) take no API
key: they answer with `401` and expect the client to sign the user in with
OAuth. The gateway does that sign-in itself, so each person reaches the server
as themselves instead of through a shared token pasted into `headers`:

```bash
prismor mcp-gateway login linear   # opens the browser; tokens stored for you
prismor mcp-gateway auth           # sign-in status of every remote server
prismor mcp-gateway logout linear  # revoke the tokens at the server and forget them
```

`login` follows the MCP authorization spec: it reads the server's protected
resource metadata (RFC 9728) to find its authorization server, registers
Prismor as a client (RFC 7591) or uses a `client_id` you give it, and runs the
authorization-code flow with PKCE and a loopback redirect, asking for a token
bound to that one server (RFC 8707 `resource`). Endpoints that receive codes or
tokens must be `https` (plain `http` only on loopback).

Tokens are written to `~/.prismor/mcp-oauth/` (`0600`), keyed by the server's
URL rather than its name in the config, so a renamed entry or a name pointed at
another host never receives a token minted for a different server. A running
gateway reads that store on every call: it picks up a new sign-in (a server that
failed to start for want of one comes up on the next tool list), stops sending
the token after `logout`, refreshes a token before it expires, and on a `401`
refreshes once and retries. `logout` also revokes the tokens at the server
(RFC 7009) when it offers a revocation endpoint. When it cannot (never signed
in, refresh revoked), the call fails with a message telling the model to ask the
user to run `prismor mcp-gateway login <server>`.

OAuth is used only for remote servers whose entry sends no `Authorization`
header of its own. Per entry:

```json
{
  "mcpServers": {
    "linear": {"type": "http", "url": "https://mcp.linear.app/mcp"},
    "internal": {"type": "http", "url": "https://mcp.corp.example/mcp",
                 "oauth": {"client_id": "prismor-gw", "scopes": ["tools.read"]}},
    "legacy": {"type": "http", "url": "https://legacy.example/mcp", "oauth": false}
  }
}
```

Use `"oauth": {"client_id": …}` (and `client_secret` if the client is
confidential) when the authorization server does not allow dynamic
registration; `false` turns sign-in off. On a machine without a browser, pass
`--no-browser` to print the URL, and `--callback-port` to fix the loopback port
so you can forward it over SSH.

Sign-in is for the local gateway. Hosted endpoints run without a person at a
browser and still use the token stored with the server in the registry.

## Modes and flags

```bash
prismor mcp-gateway [serve] [--config PATH] [--mode enforce|observe]
                    [--upstream <url|'command'>] [--server name=<url|command>]
                    [--namespace plain|none] [--workspace PATH]
```

- `--mode enforce` blocks policy violations; `observe` logs only. Serving
  defaults to `observe`; `prismor mcp-gateway install` writes `enforce` into
  the connector unless you pass `--mode observe`. The control plane can still
  force enforce per agent/device.
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

OpenCode is governed by hooks first (`prismor install-hooks --agent opencode`
writes a plugin into `.opencode/plugins/`). The mirror is the optional second
layer: it replaces OpenCode's own tools with Prismor's, so a call is screened
even where the plugin is not loaded (for example `opencode --pure`, which skips
external plugins).

Everything is one project-scoped `opencode.json`, and there is **no trust gate** -
the project file both declares the server and grants it. Note the MCP block is
keyed directly under `mcp`, **not** `mcp.servers`, which published guidance says
and OpenCode 1.18 rejects.

The natives are switched off with `permission: {<tool>: "deny"}`, written last
in the project's `permission` block and again under `agent.<build|plan|general|explore>.permission`.
`tools: {<tool>: false}` is not enough: OpenCode merges any `permission` the
developer set (a global `"permission": "allow"` included) over it, and the
natives come back. `off` takes the denies out again and gives back the
`permission` and `agent` blocks as they were, keeping edits made in between.

Verified on OpenCode 1.19.2: after `on`, `opencode mcp list` reports
`prismor-tools connected`, and `opencode debug agent build` / `explore` show no
native tool even with `"permission": "allow"` in the global config; a model
asking for `bash` is told the tool is unavailable. `off` restores the file.

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

## Tool definitions are checked before the model reads them

A tool's description and input schema are instructions the model follows, and
the server can change them at any time. Two published attacks use exactly that:
**tool poisoning** (a description that tells the model to read
`~/.ssh/id_rsa` and pass it in an extra `sidenote` argument, and not to mention
it) and the **rug pull** (a tool you have been using for weeks quietly changes
its description or adds a parameter). The gateway checks every definition at
`tools/list`, before it reaches the model:

- **Scanned like a skill.** The name, title, description and every parameter's
  name and description run through the `skill_manifest` rules, including
  `mcp-tool-poisoning`: hiding things from the user, coercion ("otherwise the
  tool will not work"), overriding other servers' tools, redirecting
  recipients, plus the existing secret-read, exfil-endpoint and prompt-override
  rules. Each distinct definition is scanned once per gateway process.
- **Pinned on first use.** The first time a server lists a tool, a hash of its
  definition is stored in `~/.prismor/mcp-tool-pins/` (`0600`), keyed by the
  server's URL or command, not its name in the config. A later change to the
  description, schema or annotations is held until someone reviews it. A tool
  that changes back to the pinned version is released again.

In enforce mode a held tool is left out of `tools/list`, and calling it by name
is blocked (and logged) with the reason. The poisoned text itself is never
echoed back to the model. Observe mode lists it and writes
`would hide in enforce mode` to stderr. New tools from a server you already
use are scanned and pinned like the first ones.

Review and accept from a terminal:

```bash
prismor mcp-gateway tools            # every server: pinned count, and what is held and why
prismor mcp-gateway tools github     # one server, with each held definition as a diff against the pinned one
prismor mcp-gateway approve github create_issue@3f9c1a2b7d4e   # accept exactly that version
prismor mcp-gateway approve github   # accept everything held for github
```

`tools` prints each held definition with a short hash, as a diff against the pinned version (or in full, for a tool never pinned), so a change outside the description is visible too. Approving `name@hash`
accepts only that version: if the server changed the tool again after you read
it, nothing is approved and you are asked to review the current one (a server
cannot show you a harmless version and swap in another before you approve).

An approved definition is not re-scanned while it stays the same. Approving is
a human's decision: an agent running `prismor mcp-gateway approve` or writing
to the pin files is blocked by `prismor-self-edit`. Set `"pin": false` on a
server entry to turn both checks off for it (for a server you develop yourself,
whose tools change all the time).

Hosted endpoints run the same checks, but their pins live in the endpoint's
temporary storage and start over after a cold start, so there drift is only
caught while an instance stays warm. The scan applies regardless.

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

## Hosted endpoints (Team and Enterprise)

Everything above runs the gateway **locally** on your machine, on every plan.
Team and Enterprise add a **hosted** option: in the console's MCP Hub, *Spin up
MCP instance* gives you one governed MCP URL for the servers you choose from your
registry. Paste it into any agent on any machine; there is nothing to install.

```
<your org's endpoint>/mcp/<key>
```

The console shows the URL once, as a ready-to-run Claude Code command
(`claude mcp add --transport http prismor <url>`) or as the `.mcp.json` block any
MCP client reads. The key in the URL *is* the credential: anyone with it can call
the endpoint's tools, so store it like a secret.

- **Servers.** Remote (HTTPS) servers are called from Prismor's side, and `npx` /
  `uvx` servers run there too, so nothing runs on the laptop. A server that needs
  a token keeps it in the registry, encrypted, and the token never reaches the
  machine using the endpoint. Servers that drive a browser (Playwright,
  Puppeteer) are marked *local only*: run them in a local gateway.
- **Governance.** An endpoint runs this same gateway as its own service identity
  (`gateway: <label>` under Devices): every call is checked against the org's
  signed policy, every result is screened before the model sees it, and calls
  stream to Activity and Sessions. An admin switches it between observe and
  enforce from the console. Endpoints start in enforce.
- **Per-person keys.** Expand an endpoint to give each person, device or agent
  their own key on it: their calls are attributed to them, follow their own tool
  rules, and can be revoked on their own.
- **Kill switch.** Revoking an endpoint (or a person's key) cuts it off within
  30 seconds; clients then get `403 invalid or revoked instance key`.
- **Version.** The Hosted endpoints table shows the Prismor runtime each endpoint
  runs and flags one that is behind the current release.

How it runs: each org's endpoints are served by one AWS Lambda function built from
this repo (`deploy/lambda/Dockerfile.mcp`, `prismor.runtime.lambda_mcp_handler`)
and released with every runtime version. Each key gets its own warm gateway
process: the first call after a cold start takes about a second, and the first
tool list with `npx` / `uvx` servers about ten while their packages download.
Operators: see `deploy/lambda/README.md`.

Local gateway vs hosted endpoint:

| | Local (`prismor mcp-gateway`) | Hosted endpoint |
|---|---|---|
| Plan | Any | Team, Enterprise |
| Runs on | Your machine | Prismor (AWS Lambda, one function per org) |
| Setup | CLI / config file | One click: paste a URL or a `claude mcp add` command |
| Secrets | In your local config | Encrypted server-side |
| Browser servers (Playwright) | Yes | No, local only |
| Telemetry / policy / kill switch | Yes (enrolled) | Yes (built in) |

## Notes

- The gateway config may contain tokens in `env` blocks; `install` writes it
  with `0600` permissions and Prismor never logs config values.
- Resources and prompts are aggregated too. Resource URIs pass through
  unchanged (the first server to list a URI serves it); prompts are named
  `<server>__<prompt>` like tools. `resources/read` and `prompts/get` are judged
  as `mcp__<server>__read_resource` (the URI in its arguments) and
  `mcp__<server>__prompt__<name>`, so a server-wide deny covers them, and what
  they return is masked and scanned like a tool result: a poisoned resource is
  withheld. Mirrored built-ins serve tools only.
- Upstreams are started concurrently and may take up to 10 minutes to answer
  `initialize` (a cold `npx -y` install). `tools/list` waits up to 30s for
  servers still in their handshake; one that is still starting after that is
  left out of the answer and announced with `notifications/tools/list_changed`
  once it is up, so a client that lists once at startup re-lists and sees it.
- If policy evaluation itself fails in enforce mode, the call is **denied**
  (fail-closed), never silently allowed.
