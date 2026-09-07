# CLI Reference

Every capability in the toolkit is reachable through the single `prismor`
command. This page is the **map**: it lists every command, what it does, and
links to the dedicated deep-dive doc for that capability.

```
prismor <command> [options...]
prismor <domain> <action> [options...]
prismor --help               # the same map, in your terminal
prismor <command> --help     # help for one command
```

There are two shapes:

- **Top-level commands** — `prismor status`, `prismor audit`, `prismor check …`
- **Domains** that take an action — `prismor cloak add …`, `prismor canary plant …`

`prismor` is a deprecated drop-in alias for `prismor`; it forwards everything
unchanged and prints a migration notice. Use `prismor`.

---

## Quick start

| Command | What it does | Deep dive |
|---|---|---|
| `prismor setup` | Interactive onboarding wizard: pick mode, choose which rules block, select agents, enable cloaking, choose install scope, set the unlock password. | [Onboarding](#onboarding--lifecycle) |
| `prismor status` | One-shot health check: workspace, hooks, mode, cloak, latest session, next action. | [Dashboard & sessions](dashboard.md) |
| `prismor audit` | Full security-posture audit across every subsystem. `--fix` auto-remediates. | [Prismor](prismor-runtime.md#security-audit) |
| `prismor --help` | The full command map. | — |

---

## The command map

```
prismor
│
├─ Onboarding & lifecycle
│   ├─ setup                  Interactive onboarding wizard (TUI)
│   ├─ install-hooks          Wire Prismor hooks into an agent/IDE
│   ├─ uninstall-hooks        Remove hooks
│   ├─ update                 Self-update check / upgrade
│   └─ status [--all]         Health check (this workspace / all workspaces)
│
├─ Runtime protection (policy engine)
│   ├─ check                  Pre-check a command or path against policy
│   ├─ allow <rule>           Make an exception to a rule that blocked you
│   ├─ unlock / lock          Open/close the agent self-edit window (password)
│   ├─ semantic-check         Hybrid LLM prompt-injection guard
│   ├─ sandbox <action>       status · check · run — Docker command sandbox
│   ├─ eval-server            HTTP evaluation endpoint for non-Python adapters
│   ├─ proxy                  LLM proxy — screens model traffic and proposed tool calls
│   ├─ inference-hook <action> serve · test · secret — Claude Inference Hooks AI security server
│   ├─ egress <action>        show · report · test · allow · deny · mode — network egress policy
│   ├─ mirror <action>        on · off · status · passthrough — governed built-ins over MCP
│   └─ policy <action>        init · validate · show · edit · test
│
├─ Visibility (audit & forensics)
│   ├─ audit                  Full posture audit (--fix to remediate)
│   ├─ scan                   Scan MCP servers & skills for risk
│   ├─ deps                   Check project deps vs. threat feed
│   ├─ analyze / ingest       Run the engine over a JSONL session
│   ├─ ingest --discover      Reconstruct past agent activity from on-disk transcripts
│   ├─ sessions / session     List / show stored sessions
│   ├─ trail <action>         verify · show · checkpoint — signed audit trail
│   ├─ attest [verify|coverage]  Signed evidence bundle + framework coverage
│   ├─ discover [section]     Sweep host for ungoverned agents, MCP servers, keys (--fix to govern them)
│   ├─ status --all           Terminal overview of all workspaces
│   └─ dashboard              Local web dashboard (127.0.0.1:7070, opens browser)
│
├─ Secret prevention
│   ├─ cloak <action>         install · add · list · remove · status · pattern
│   └─ sweep                  Find & vault leaked secrets on disk
│
├─ Identity & scoping
│   ├─ iam <action>           Named agent identities / permission profiles
│   ├─ agents <action>        Named agent instances — list · show · set (kill-switch, mode, IAM)
│   ├─ scope <action>         Session-scoped, task-specific rules
│   └─ canary <action>        Plant & manage honeytoken tripwires
│
├─ Adaptive defense
│   └─ learn                  Mine session history for new rules
│
├─ Enterprise / org
│   ├─ enroll <token>         Enroll this machine against your org's control plane
│   ├─ enroll-status          Show enrollment + applied policy version
│   ├─ workspace <action>     Show/set whether this workspace is org-managed or personal
│   ├─ exempt <action>        Request an admin exemption for this repo
│   └─ logout                 Un-enroll (remove device identity + cached policy)
│
└─ Supply chain
    └─ supplychain <action>   npm/pip/pnpm/uv/cargo/go install gate · harden
```

---

## Onboarding & lifecycle

| Command | Key flags | Description |
|---|---|---|
| `prismor setup [DIR]` | `--non-interactive`, `--mode`, `--enforce-rules`, `--recommended`, `--agents`, `--cloak/--no-cloak` | Interactive wizard (or scripted with flags / `PRISMOR_MODE`, `PRISMOR_CLOAK` env vars). Picks mode, chooses which rules block, selects agents, enables cloaking, and optionally sets an unlock password. See [Choosing what blocks](#choosing-what-blocks). |
| `prismor install-hooks` | `--agent <name\|all>` (required), `--mode <observe\|enforce>`, `--scope <project\|user>` | Writes hook config for the chosen agent so Prismor sees tool calls. Without hooks, nothing is monitored. |
| `prismor uninstall-hooks` | `--agent <name\|all>`, `--scope` | Removes Prismor hooks for an agent. For `claude`/`all`, this also removes cloaking hooks (`prismor cloak install`) — secrets are no longer protected at the tool boundary until you reinstall with `prismor cloak install`. |
| `prismor status` | `--workspace`, `--all`, `--days N` | Health check: hooks, mode, cloak state, latest session, and the single next action. Run this first every session. `--all` shows every registered workspace. |
| `prismor update` | `--check` | Check for (or install) a newer prismor release. |
| `prismor info` | `--workspace` | _Deprecated_ alias of `status`. |

Agent → config matrix and per-agent details: [AGENT_INTEGRATIONS.md](../AGENT_INTEGRATIONS.md).
Modes (`observe` vs `enforce`): [Prismor](prismor-runtime.md).

### Choosing what blocks

`observe` reports everything and blocks nothing, so setup leaves every rule on.

`enforce` asks which rules should block, and starts with **none of them
selected** — including the safety floor, which is marked *recommended* rather
than assumed. Nothing blocks until you choose it. Press `a` on that screen to
take the recommended set.

The choice is written to `.prismor/policy.yaml` as `settings.selection:
explicit` plus one entry per rule, so what blocks is legible in the file rather
than implied by the defaults. Scripted installs say the same thing with
`--recommended` or `--enforce-rules id1,id2`; `--mode enforce` with neither
installs with nothing blocking and tells you so.

Two things the selection does not reach:

- **Prismor's self-protection rules** always block. They are what stops the
  agent editing the choices above, so offering them as a checkbox would make
  every other checkbox decorative.
- **Org-managed workspaces** keep the full safety floor. `selection: explicit`
  is honored only for a locally-authored policy on an unmanaged machine, and is
  ignored if it arrives in a signed org bundle.

### Making exceptions

When a rule blocks something it should not, the block prints the command that
fixes it:

```
prismor allow secret-exfiltration --pattern 'curl -F f=@.env'   # just this case
prismor allow secret-exfiltration --observe                     # keep the rule, stop it blocking
prismor allow secret-exfiltration --off --yes                    # off in this workspace
prismor allow --list                                             # what you have added
prismor allow --undo allow-secret-exfiltration                   # remove one
```

Add `--expires 30m` to make an exception temporary — it lapses instead of
quietly becoming permanent policy.

**These are for the human at the keyboard.** An agent that runs them is blocked,
along with every other route to Prismor's own config: the policy file, the
dashboard's write API, and the unlock credential. To hand the agent that
ability for a few minutes, run `prismor unlock` and enter your password
(`prismor unlock --set-password` if you have not set one). Inside the window the
agent can adjust policy; it still cannot touch the self-protection rules or the
password itself, and the window closes on its own.

An unhooked agent — one running through a framework Prismor does not see — is
outside all of this, the same as every other Prismor control.

---

## Runtime protection

| Command | Key flags | Description |
|---|---|---|
| `prismor check "<value>"` | `--type <command\|read\|write>`, `--explain`, `--from-log`, `--suggest-allowlist` | Dry-run a command or file path against the active policy. Returns ALLOW / WARN / BLOCK + reason without executing. Exit `2`=block, `1`=warn, `0`=clean. |
| `prismor semantic-check [TEXT]` | `--mode <hybrid\|heuristic\|api>`, `--json`, `--cli-path` | Run the semantic prompt-injection guard on text or stdin. See [Semantic Guard](semantic-guard.md). |
| `prismor allow <rule>` | `--pattern`, `--expires`, `--observe`, `--off`, `--yes`, `--reason`, `--list`, `--undo`, `--workspace` | Make an exception to a rule that blocked you, narrowest first. With no `--pattern` it uses the text of the most recent block for that rule. `--observe` keeps the rule but stops it blocking; `--off` disables it for the workspace (needs `--yes`). Refuses self-protection rules, refuses to turn a floor rule off, and refuses everything where an org's signed policy governs. See [Making exceptions](#making-exceptions). |
| `prismor unlock` | `--for`, `--status`, `--set-password`, `--system-password`, `--forget`, `--workspace` | Open a short window (default 3 minutes) in which the agent may edit Prismor's own policy. Asks for your unlock password; needs a terminal. `--system-password` verifies against your operating-system account instead of storing a Prismor one. |
| `prismor lock` | — | Close the self-edit window early. |
| `prismor policy init` | `--workspace` | Scaffold `.prismor/policy.yaml`. |
| `prismor policy show` | `--workspace` | Print active rules after merging defaults + project overrides. |
| `prismor policy export` | `--json`, `--output PATH`, `--workspace` | Print the effective merged policy as stable, sorted JSON — patterns already resolved and disabled rules dropped — for non-Python consumers and for committing/diffing. |
| `prismor policy edit` | `--workspace` | Interactive TUI to toggle rules on/off. |
| `prismor policy validate <file>` | — | Static-validate a policy YAML file. |
| `prismor policy test` | `--file` | Run declarative policy tests (falls back to the bundled OWASP LLM starter pack). |
| `prismor sandbox <status\|check\|run>` | `--workspace` | Docker-backed command sandbox: show config, check the backend, or run one command isolated. See [Docker sandbox](docker.md). |
| `prismor egress show` | `--workspace` | Effective network egress policy, its mode, and which layer (default / project / org) set it. See [Network Isolation](network-isolation.md). |
| `prismor egress report` | `--last N`, `--fail-on-block`, `--workspace` | Every destination recorded sessions actually contacted, with the verdict the current policy gives it. The on-ramp before flipping to enforce; `--fail-on-block` gates CI. |
| `prismor egress test <target>...` | `--agent <name>`, `--workspace` | Dry-run a URL, host, or whole shell command against the policy. Exit `1` if anything would be blocked. |
| `prismor egress allow <host>...` | `--reason`, `--workspace` | Add hosts, wildcards, IPs, or CIDRs to `settings.egress.allow` (`egress deny` / `egress rm` for the others). |
| `prismor egress mode <observe\|enforce>` | `--workspace` | Flip enforcement (`egress default <allow\|deny>` sets the no-match verdict; `egress enable` / `disable` toggle screening). |
| `prismor mirror on` | `--mode <enforce\|observe>`, `--agent <claude\|codex\|opencode\|claude-desktop>`, `--allow-tools`, `--workspace` | Serve `Bash`/`Read`/`Write`/`Edit`/`Glob`/`Grep`/`WebFetch` through Prismor instead of Claude Code's own: registers the `prismor-tools` MCP server and denies the native tools in `.claude/settings.json` (backups as `*.pre-mirror.bak`, nothing else touched). Also trusts the server for this project and carries your existing tool permissions onto the mirrored names — without those the agent boots with no tools at all. `--allow-tools` pre-allows the whole roster for headless runs. Verifies the server starts before denying anything. Takes effect on the next session. `--agent codex` and `--agent claude-desktop` wire those hosts machine-wide instead; the desktop app has no deny-list, so there the mirror adds governed tools without removing the app's own. Claude Code keeps its native `WebFetch` (already hook-screened, and it summarises the page); OpenCode's is disabled, since it has no hooks at all. See [MCP Gateway](mcp-gateway.md#mirrored-built-ins---mirror-prismor-mirror). |
| `prismor mirror off` | `--workspace` | Undo exactly what `on` did — the agent uses its native tools again from the next session. |
| `prismor mirror status` | `--workspace` | Where the mirror is configured, whether it is governing / passing through / paused, its tool roster, live gateway processes. |
| `prismor mirror passthrough <on\|off>` | `--workspace` | Runtime switch, no restart: `on` runs mirrored built-ins ungoverned (logged, not blocked or redacted). `prismor pause` does the same for hooks + gateway together, with auto-resume. |
| `prismor egress migrate` | `--workspace` | Convert a legacy warn-only `settings.egress_allowlist` into an enforceable `settings.egress`. |
| `prismor tags list` | `--last N`, `--workspace` | Tools seen in recent sessions + resolved tags + which tier resolved them (explicit / `_meta` / default / inference). See [Tool Tags](tool-tags.md). |
| `prismor tags set <tool> <tag>...` | `--workspace` | Tag a tool or glob in `.prismor/policy.yaml` (`tags rm` removes). |
| `prismor tags rules [add\|rm]` | `--workspace` | List, add, or remove tag-rule expressions, e.g. `"untrusted_content then critical_action -> block"`. Adds are parse-checked with caret diagnostics. |
| `prismor tags edit` | `--workspace` | Interactive wizard: tag tools, author rules, flip mode. |
| `prismor tags lint [file]` | `--workspace` | Validate every rule expression in a policy file. Exit `1` on errors. |
| `prismor tags test` | `--session <id>`, `--last N`, `--rule "<expr>"`, `--fail-on-hit` | Dry-run tag rules against recorded session logs: prints WOULD BLOCK / WOULD WARN per call, touches no enforcement state. `--rule` adds what-if candidates. |

### eval-server

| Command | Key flags | Description |
|---|---|---|
| `prismor eval-server` | `--port` (default 7071), `--host` (default 127.0.0.1), `--workspace` | HTTP evaluation endpoint (`POST /v1/evaluate`) so non-Python adapters (Vercel AI SDK, anything HTTP) get the same policy pipeline. See [Frameworks overview](frameworks-overview.md) and [Vercel AI SDK](frameworks-vercel-ai.md). |

### proxy

| Command | Key flags | Description |
|---|---|---|
| `prismor proxy` | `--port` (default 7080), `--host` (default 127.0.0.1), `--mode observe\|enforce`, `--workspace`, `--config`, `--session-id`, `--agent-name` | Policy proxy for model traffic. Point an agent at it with `ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL`; the outbound prompt is screened and cloak-masked, and every `tool_use` in the response is evaluated as the tool call it is. See [the LLM proxy](llm-proxy.md). |

### inference-hook

| Command | Key flags | Description |
|---|---|---|
| `prismor inference-hook serve` | `--host`, `--port` (7072), `--signing-secret`, `--previous-signing-secret`, `--fail-open`, `--mode enforce|shadow`, `--allow-unsigned`, `--api-key`, `--config`, `--workspace`, `-v` | Run the AI security server for [Claude Inference Hooks](inference-hook.md): Anthropic POSTs each governed prompt (claude.ai, Claude Code, Cowork) as a signed frame; Prismor evaluates the transcript and returns `{action: allow|deny}`. Fail-closed by default; any path is the endpoint; `GET /health`. |
| `prismor inference-hook test` | `--url`, `--secret`, `--sample clean|pci|secret|injection|config-test|all`, `--frame file.json`, `--unsigned`, `--bearer`, `--expect`, `--json` | Send Standard-Webhooks-signed sample frames to a server (or evaluate in-process with no `--url`) and print the verdicts. Exit 0 allow · 1 deny · 2 error/mismatch. |
| `prismor inference-hook secret` | — | Print a fresh `whsec_` secret for local end-to-end runs. |

`prismor inference-hook-server` remains as an alias for `serve`.

Full policy model, rule schema, and the default rule list: [Prismor](prismor-runtime.md).

---

## Visibility

| Command | Key flags | Description |
|---|---|---|
| `prismor audit` | `--fix`, `--json`, `--workspace` | Posture audit across hooks, policy, cloak, permissions, feed, network, supply chain. `--fix` applies safe remediations. |
| `prismor scan` | `--agent`, `--json` | Scan installed MCP servers and skills for dangerous patterns. See [Skill Scanner](skill-scanner.md). |
| `prismor deps` | `--json`, `--workspace` | Cross-reference project dependencies against the signed IOC feed + lockfile integrity. See [Supply Chain](supply-chain.md). |
| `prismor analyze [FILE]` | `--input`, `--json`, `--sarif` | Run the engine over a JSONL session (or the most recent one). SARIF output feeds GitHub Code Scanning. |
| `prismor ingest --input <file>` | `--session-id`, `--agent` | Analyze a single pre-normalized JSONL session and store it in the local DB. |
| `prismor ingest --discover` | `--agent`, `--since`, `--max-events`, `--no-persist`, `--strict`, `--semantic`, `--json` | Sweep this machine for agent transcripts, replay them through the live policy engine, and report what the current policy **would have blocked** vs warned. Backfills the dashboard with history from before install. `--strict` exits non-zero if a non-empty transcript yields no events; `--semantic` re-enables the semantic guard (off during sweeps so it can't fire an LLM call per event across all history). See [Transcript Ingest](transcript-ingest.md). |
| `prismor ingest --discover --coverage` | `--json` | Show sessions that ran with no live Prismor record — activity that executed ungoverned. |
| `prismor ingest --discover --show <rule>` | — | List the individual tool calls behind one rule id. |
| `prismor ingest --discover --export-corpus <dir>` | — | Write redacted, labelled rule fixtures (positives + negatives) from real usage. |
| `prismor sessions` | `--findings-only`, `--global`, `--limit`, `--json` | List stored sessions, optionally only flagged ones, optionally across all workspaces. |
| `prismor session <id>` | `--json` | Drill into one session's tool-call trace + findings. |
| `prismor trail verify` | `--pubkey`, `--json` | Verify the signed audit trail end-to-end: recompute hashes, prev-hash linkage, seq gaps, Ed25519 signatures. Exit non-zero on anything but a clean chain. See [Signed Audit Trail](audit-trail.md). |
| `prismor trail show` | `--last N` | Render recent audit-trail records (verdict, agent, tool, input). |
| `prismor trail checkpoint` | `--out FILE` | Export a signed chain-head checkpoint for anchoring outside the machine. |
| `prismor attest` | `--out FILE`, `--workspace` | Build a signed evidence bundle: posture findings, agent inventory, and the trail anchor in one Ed25519-signed file. See [Attestation Bundle](attestation-bundle.md). |
| `prismor attest verify <bundle>` | `--pubkey`, `--json` | Re-verify a bundle's content hash and signature. `--pubkey` pins an out-of-band signer key. Exit non-zero on failure. |
| `prismor attest coverage` | `--json`, `--workspace` | Show which compliance-framework controls the active policy covers (OWASP LLM/Agentic, NIST AI RMF, EU AI Act). |
| `prismor discover [all\|agents\|mcp\|keys]` | `--fix`, `--yes`, `--fix-mode`, `--json`, `--report`, `--no-file-scan`, `--fail-on-shadow`, `--workspace` | Sweep this host for the AI surface running outside Prismor's coverage (shadow AI): agents without hooks, MCP servers not routed through the gateway, and provider keys not registered with Cloak. Ends with a coverage score. Pass a section to limit the report; `--fail-on-shadow` exits 1 for CI; `--report` sends the inventory to your organization console for the fleet-wide Shadow AI view (enrolled devices only, and a no-op otherwise). `--fix` governs what it found — hooks the unmanaged agents, moves MCP servers behind the gateway (any config declaring `mcpServers`/`servers`, not just the workspace's), imports dotenv keys into Cloak — printing the plan and asking first (`--yes` to skip the prompt, `--fix-mode enforce` to install in enforce). Without `--fix` it is read-only; credential-shaped values in MCP URLs and argv are redacted before they reach output. On an enrolled device each reported finding also carries whether it is fixable and the command that fixes it, so the console can show what is actionable today. See [Host discovery](attestation-bundle.md#host-discovery). |
| `prismor status --all` | `--days N` | Terminal overview of every registered workspace. See [Dashboard](dashboard.md). |
| `prismor dashboard` | `--port`, `--host`, `--no-open` | Local web dashboard at `http://127.0.0.1:7070` (opens a browser tab). See [Dashboard](dashboard.md). |
| `prismor serve` | `--port`, `--host`, `--no-open` | _Deprecated_ alias of `dashboard --no-open` (headless server only). |

---

## Secret prevention

| Command | Key flags | Description |
|---|---|---|
| `prismor cloak install` | `--scope`, `--no-userprompt-guard`, `--no-secret-guard`, `--sweep-on-stop` | Install cloaking hooks so real secrets stay out of model context. |
| `prismor cloak add <name>` | `--from-file` | Register a secret under a placeholder. Value read from stdin / hidden prompt — never argv. |
| `prismor cloak add --env-file .env` | — | Import every `KEY=VALUE` entry from a dotenv file as `@@SECRET:KEY@@`. |
| `prismor cloak list` | — | List registered placeholder names (never values). |
| `prismor cloak remove <name>` | — | Delete a registered secret. |
| `prismor cloak status` | `--scope` | Show whether cloaking hooks are installed + secret count. |
| `prismor cloak run -- <command>` | — | Run a command with `@@SECRET:name@@` placeholders resolved locally and stdout/stderr scrubbed. Use this for Codex, whose hooks are block-only. |
| `prismor cloak pattern <list\|add\|remove>` | — | Manage the secret-detection regexes. |
| `prismor sweep` | `--redact`, `--clean`, `--restore`, `--show-vault`, `--purge` | Find secrets already leaked into AI tool configs and vault/redact them. |

Design, setup, best practices, and threat model: [Sweep & Cloak](sweep-and-cloak.md).

---

## Identity & scoping

| Command | Key flags | Description |
|---|---|---|
| `prismor iam init` | `--scope <global\|project>` | Scaffold an `iam.yaml` of agent identities. |
| `prismor iam list` | — | List defined identities; marks the active `PRISMOR_AGENT_ID`. |
| `prismor iam show <agent>` | — | Show one identity's permission profile. |
| `prismor iam check <agent> --value "<v>"` | `--type <command\|read\|write\|network>` | Test whether an identity may perform an action. |
| `prismor scope show [id\|latest]` | — | Show session-scoped rules (all, or one session; `latest` or a unique id prefix). |
| `prismor scope list` | — | List sessions with active scoped rules. |
| `prismor scope edit <id\|latest>` | — | Edit a session's scoped rules in `$EDITOR` (freezes auto-widening for that session). |
| `prismor scope clear <id>` | — | Remove a session's scoped rules. |
| `prismor agents list` | — | List every named agent instance seen (the adapter's `name=`), with framework + control state. |
| `prismor agents show <name>` | — | Show one named agent's control settings (enabled, mode, IAM profile, last seen). |
| `prismor agents set <name>` | `--enabled/--disabled`, `--mode <observe\|enforce>`, `--iam-profile <p>` | Per-agent runtime control: kill-switch, mode override, forced IAM profile. Config lives in `agents.yaml`. |
| `prismor canary plant <path>` | `--type <aws\|ssh\|env\|generic>`, `--webhook`, `--force` | Plant a honeytoken credential tripwire. |
| `prismor canary list` | — | List planted canaries (markers redacted). |
| `prismor canary status` | — | Summary of canaries by type. |
| `prismor canary remove <id\|path>` | — | Remove a canary. |

Deep dives: [IAM](iam.md) · [Scoped Agent](scoped-agent.md) · [Canary](canary.md).

---

## Adaptive defense

| Command | Key flags | Description |
|---|---|---|
| `prismor learn` | `--min-support`, `--fp-threshold`, `--json` | Mine session history for repeated blocked / near-miss patterns and propose new rules. |
| `prismor learn --candidates` | — | List pending candidate rules. |
| `prismor learn --apply <id>` | — | Accept a candidate into project policy. |
| `prismor learn --reject <id>` | — | Reject a candidate. |

Deep dive: [Learning](learning.md).

---

## Enterprise / org

| Command | Key flags | Description |
|---|---|---|
| `prismor enroll <token>` | `--label`, `--api-base` | Exchange a single-use org token (minted in the dashboard) for this machine's device identity; pulls the signed org policy. |
| `prismor enroll-status` | — | Show enrollment state, device label, and the applied policy version. |
| `prismor workspace [managed\|personal\|auto]` | — | With no argument, shows whether this workspace is org-managed (org policy + telemetry) or personal (local-only). Pass `managed`/`personal`/`auto` to set it. Org-claimed repos can't be downgraded, and `personal` is ignored entirely when the org policy sets `allow_personal_workspaces: false`. |
| `prismor exempt request` | `--reason` | Ask an org admin to relax specific non-floor rules for this repo; served back in the signed policy. |
| `prismor logout` | — | Un-enroll: removes the device identity and cached remote policy. Local protection stays on. |

Deep dive: [Connecting to the platform](connecting-to-the-platform.md) · [Policy layers & exemptions](policy-layers-and-exemptions.md).

---

## Supply chain

| Command | Description |
|---|---|
| `prismor supplychain npm install <pkg>` | Score `<pkg>` (age, maintainers, install scripts, IOC match) and block if dangerous before npm runs. |
| `prismor supplychain pip install <pkg>` | Same gate for PyPI. |
| `prismor supplychain <pnpm\|yarn\|uv\|cargo\|go> …` | Same gate per ecosystem. Non-install commands pass through transparently. |
| `prismor supplychain harden [--dry-run] [PATH]` | Write hardening settings (`ignore-scripts`, `save-exact`, pinned fetch) into package-manager configs. |

Scoring table, IOC feed, ecosystem support: [Supply Chain](supply-chain.md).

---

## Environment variables

| Variable | Used by | Effect |
|---|---|---|
| `PRISMOR_MODE` | `setup --non-interactive` | Default enforcement mode (`observe` / `enforce`). |
| `PRISMOR_CLOAK` | `setup --non-interactive` | Enable cloaking (`1`/`true`/`yes`/`on`). |
| `PRISMOR_WORKSPACE` | all commands | Override the resolved workspace path. |
| `PRISMOR_AGENT_ID` | `iam` | Active agent identity for IAM enforcement. See [IAM](iam.md). |
| `PRISMOR_SWEEP_PASS` | `sweep` | Vault passphrase for non-interactive runs. |
| `EDITOR` | `scope edit` | Editor for scoped-rule editing. |

---

## See also

- [Governance surfaces](governance-surfaces.md) — hooks vs the MCP mirror, per agent

- [Prismor](prismor-runtime.md) — policy engine, session logs, audit, modes
- [Supply Chain](supply-chain.md) — install-time enforcement and scoring
- [Network Isolation](network-isolation.md) — egress allowlists, raw-IP detection
- [Skill Scanner](skill-scanner.md) — MCP + skill risk scanning
- [Sweep & Cloak](sweep-and-cloak.md) — secret prevention
- [Semantic Guard](semantic-guard.md) — LLM-assisted injection defense
- [Canary](canary.md) · [IAM](iam.md) · [Scoped Agent](scoped-agent.md) · [Learning](learning.md) · [Dashboard](dashboard.md)
- [Docker & Containers](docker.md) · [Architecture](architecture.md)
