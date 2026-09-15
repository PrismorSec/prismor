# Dashboard & Sessions

Prismor logs every agent tool call — not just the ones it blocks — to a local
SQLite store. This doc covers the three ways to read that history: the
**terminal dashboard**, the **local web dashboard**, and the **session**
commands for drilling into a single run.

Everything is local. `serve` binds to `127.0.0.1` by default; there is no cloud
component and no external service.

Implementation: [`prismor/runtime/server.py`](../prismor/runtime/server.py), session store in
[`prismor/runtime/store.py`](../prismor/runtime/store.py).

---

## Where the data lives

```
.prismor/
├─ sessions/<session-id>.jsonl   append-only log, one JSON object per tool call
└─ prismor.db                     SQLite, indexed for cross-session queries
```

Workspaces are registered as you install hooks, so the dashboards can aggregate
across every project you've protected.

```
   workspace A ─┐
   workspace B ─┼─► registered workspaces ─► status --all / dashboard ─► you
   workspace C ─┘        (prismor.db each)
```

---

## Terminal: `prismor status` and `prismor status --all`

```bash
prismor status        # THIS workspace: hooks, mode, cloak, latest session, next step
prismor status --all  # ALL workspaces: risk, findings, mode, last activity
```

- **`status`** is the per-workspace health check — run it first every session. It
  ends with the single next action that matters (install hooks, switch to
  enforce, review findings, or "clean").
- **`status --all`** is the cross-project bird's-eye view: one line per registered
  workspace with its latest risk score, finding count, mode, and how long ago it
  was active. Add `--days N` to change the activity window (default 7).

---

## Web: `prismor dashboard`

```bash
prismor dashboard                   # opens http://127.0.0.1:7070 in your browser
prismor dashboard --port 8080       # custom port
prismor dashboard --host 127.0.0.1  # bind host (keep it local)
prismor dashboard --no-open         # headless: start the server, don't open a browser
```

> `prismor serve` is the deprecated alias of `prismor dashboard --no-open`.

Serves a self-contained HTML dashboard plus a small JSON API over the registered
workspace databases. The only external resources are a Chart.js CDN link and the
Inter / JetBrains Mono webfonts (Google Fonts) loaded by the browser; the data
never leaves your machine.

| Endpoint | Returns |
|---|---|
| `GET /` | The HTML dashboard |
| `GET /health` | `{"status": "ok", "ts": …}` |
| `GET /api/stats` | Aggregate stats for the KPIs / charts |
| `GET /api/sessions` | Paginated sessions (`?page&limit&sort&dir`) |
| `GET /api/findings` | Paginated findings (`?page&limit&agent&severity&category&q`) |
| `GET /api/events` | Paginated events (`?page&limit&verdict&agent`) |
| `GET /api/supply-chain` | Supply-chain enforcement stats |
| `GET /api/agents` | Agent registry merged with per-agent call stats |
| `POST /api/agents/<name>` | Update per-agent controls: `{enabled?, mode?, iam_profile?}` |
| `GET /api/policy` | Effective policy state: mode, blocking/total rule counts, `explicitSelection`, editability |
| `GET/PUT /api/policy/egress` | Read / edit `settings.egress` (`{action: set|add|remove, …}`); hostnames are validated |
| `PUT /api/policy/rules` | Toggle rule enable/mode from the Policy tab |

If you run `dashboard` before installing hooks anywhere, it warns that no workspaces
are registered yet — install hooks in a project first to collect data.

### Policy tab

Shows the **effective** state, not the static file: the mode chip reflects what
actually blocks (an explicit-selection install shows *N blocking / M total*
with per-rule blocks/reports pills), and the YAML editor edits the project
layer through the same writer as `prismor allow`. A **Network egress** tab
edits `settings.egress` (enable, mode, default verdict, allow/deny hosts)
without hand-writing YAML. On an **org-managed** workspace every write control
is disabled with a banner — the signed org bundle would overwrite local edits
on the next pull, so the console (or `prismor exempt request`) is the path
instead. All of these writes are also blocked for agents by the
self-protection rules; the dashboard write API is one of the guarded routes.

### Agents tab

The **Agents** tab manages every agent that has run in a Prismor-enabled
workspace (Claude Code, Codex, Cursor, … — they auto-register on first run):

- **Enabled toggle** — the per-agent kill switch. Off = every tool call from
  that agent is denied with a CRITICAL `agent-disabled` finding.
- **Mode** — override the enforcement mode for one agent: `inherit (global)`,
  `observe` (log only), or `enforce` (block in real time).
- **IAM profile** — pin the agent to a least-privilege profile from `iam.yaml`.

Changes are written to `.prismor/agents.yaml` and picked up by running
agents within 30 s. The topbar also shows the **effective enforcement mode**
(observe/enforce, merged across enterprise > project > global policy) at all
times.

### Approvals tab (human-in-the-loop)

A policy rule with `action: step_up` doesn't allow or block — it holds the
action for a human. On Claude and Copilot that's an inline "ask" in the
terminal. For a **headless** agent (a framework worker, CI) with no one at the
keyboard, the enterprise build routes the held action to the **Approvals** tab
instead, so a person still decides:

- **Pending queue** — each waiting request shows the tool, the reason the rule
  gave, the exact call (`params`: command/args/URL — *what* runs, not just the
  tool name), and the severity. The requesting agent is **blocked in-process**
  the whole time, so this is time-sensitive: an unactioned request expires and
  fails closed.
- **Show context** — expands the run-up: the device and session it came from,
  the conversation chain that led to the call (so you can read what the user
  actually asked for), and the last tool calls before the step-up.
- **Approve / Deny** — approve lets the waiting agent proceed; deny (with an
  optional reason) fails it closed. Either way the decision is recorded on the
  signed audit trail with who decided and why.
- **Decision history** — a table of previously approved/denied requests and who
  actioned each, with the full record on click.

Approvals are **ADMIN+** only and scoped to your org. See the `step_up` action
in [prismor-runtime.md](prismor-runtime.md#rule-actions) for how to write a rule that
requires approval, and [audit-trail.md](audit-trail.md) for the approval records.

---

## Drilling in: `sessions` and `session`

```bash
prismor sessions                          # recent sessions, this workspace
prismor sessions --findings-only          # only flagged runs, sorted by risk
prismor sessions --findings-only --global # flagged runs across all workspaces
prismor sessions --limit 50 --json        # machine-readable

prismor session <id>                      # full trace + findings for one session
prismor session <id> --json
```

Every shell command, file read/write, web fetch, and user prompt is captured, so
`prismor session <id>` is your forensic timeline for a specific incident — what
the agent did, in order, and which findings fired.

### Cost per session

Each row in `prismor sessions` carries an estimated spend (`cost=$5.38 est`),
and `prismor tokens --session <id>` breaks it down by model, with input,
output, and cache read/write tokens (1-hour cache writes are priced
separately). Usage is read from the agent's own transcript — Claude Code's
`~/.claude/projects/*/<session>.jsonl` and Codex's `~/.codex/sessions`
rollouts — and priced from LiteLLM's public price list, refreshed at most once
every 12 hours into `~/.prismor/pricing-cache.json` (a built-in snapshot covers
offline machines; `PRISMOR_PRICING_OFFLINE=1` never fetches). Drop a
`~/.prismor/pricing.json` (`{"model": {"input", "output", "cache_read",
"cache_write"}}` in USD per 1M tokens) to add or override a rate. `cost=?`
means no transcript is on this machine for that agent; `—` means the model has
no known price.

---

## Offline analysis: `analyze` and `ingest`

For CI gating or replaying an old trace against a newer policy:

```bash
prismor analyze                       # analyze the most recent session
prismor analyze --input session.jsonl # analyze a specific JSONL log
prismor analyze --sarif               # SARIF 2.1.0 for GitHub Code Scanning
prismor ingest --input session.jsonl  # analyze AND store in the DB
```

`--sarif` output drops straight into GitHub Code Scanning or the VS Code SARIF
viewer, with full rule metadata.

## Historical sessions: `ingest --discover`

Hooks only see sessions that start after they are installed, so a fresh install
opens an empty dashboard. `prismor ingest --discover` reconstructs what your
agents did *before* that, by replaying their on-disk transcripts through the
same policy engine live tool calls go through:

```bash
prismor ingest --discover --since 90d
```

Reconstructed sessions land in the same store and appear in `prismor sessions`,
`prismor session <id>`, and every dashboard view. They are distinguishable from
live capture in two ways:

| | Live capture | Reconstruction |
|---|---|---|
| `sessions.source` | `hook` | `transcript` |
| `session_id` | the agent's own id | `replay:<agent>:<id>` |

The namespacing is not cosmetic: the store is `INSERT OR REPLACE` keyed on
`session_id`, and an agent's transcript carries the *same* id its live hooks
used, so an unprefixed replay would overwrite real enforcement history.

A reconstructed finding means a rule matched a recorded action. It does **not**
mean the action was blocked at the time — Prismor was not running. Use
`prismor ingest --discover --coverage` to see which sessions had no live record
at all. See [Transcript Ingest](transcript-ingest.md).

---

## See also

- [Prismor](prismor-runtime.md) — session-log schema and the audit command
- [Transcript Ingest](transcript-ingest.md) — reconstructing pre-install activity
- [Learning](learning.md) — mines this same history for new rules
- [CLI Reference](cli-reference.md) — all commands at a glance
