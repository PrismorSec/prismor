# Live telemetry — goal, why it wasn't automatic, and the fix

## The goal

An org admin opens **Admin → Activity** and sees their developers' AI-agent
security activity **stream in live, automatically** — no per-developer manual
steps, no refreshing. When a developer's Claude/Cursor/etc. session triggers a
Prismor finding (a blocked `rm -rf`, a secret-exfil attempt, a risky MCP call),
it should appear in the dashboard within seconds, **redacted** (metadata +
hashes, never raw commands or secrets).

Each record on that wire is a signed receipt. The format is specified in
[Signed Telemetry Receipts](telemetry-receipts.md) — canonical bytes, the two
integrity layers, and a reference verifier for consumers that are not Prismor.

## How it's supposed to work (the pipeline)

```
Developer's AI agent (Claude Code)
   │  every tool call fires a hook
   ▼
prismor hook-dispatch            ← the installed `prismor` runtime
   │  PolicyEngine evaluates the event → findings
   ▼
prismor telemetry sink            ← prismor/runtime/sinks.py _dispatch_prismor
   │  builds a REDACTED record (prismor/runtime/enterprise/telemetry.py), uses the enrolled
   │  device key (~/.prismor/identity.json) → POST
   ▼
POST /api/telemetry/ingest        ← prismor-web, device-auth
   │  writes TelemetryEvent scoped to {org, user, device}
   ▼
Dashboard (AgentMonitoringView)   ← polls /api/telemetry/stats every 15s
   │  "Waiting for telemetry…" → live data, no refresh
```

For this to be automatic, the **code the hook runs** must contain the cloud
sink, and the machine must be **enrolled** (`prismor enroll <token>`).

This page is about the first-party control-plane sink. To send the same
findings to a SIEM or an OpenTelemetry collector instead of, or alongside, the
console, see [Telemetry sinks](telemetry-sinks.md).

## Why it wasn't happening automatically

Diagnosed on 2026-06-10. The dashboard was frozen at ~3h old because:

1. The user's Claude Code hooks invoke the **pipx-installed** runtime:
   `~/.local/pipx/venvs/immunity-agent/.../prismor/runtime/cli.py hook-dispatch …`
   (the package was then still called `immunity-agent`; it is now `prismor`)
2. That install is **v1.5.8 — predating the cloud sink**. It's missing
   `identity.py`, `telemetry.py`, `remote_policy.py`, and its `sinks.py` has no
   `prismor` dispatcher.
3. So every live tool call wrote findings to the **local** `prismor.db`, but
   **nothing uploaded**. The dashboard only had data from a one-time **manual
   backfill** of 3,067 historical local findings — hence "last activity 3h ago."

In short: **enrolled ✓, but the live hook runs old code with no uploader.**

## The solution

### Production (the real "automatic")
Ship the cloud sink (`identity`/`telemetry`/`remote_policy` + the `prismor`
sink, since 1.6.x) on PyPI as `prismor`. Developers `pipx upgrade prismor`
(or `pip install -U prismor`). Their existing hooks already call the installed
`prismor/runtime/cli.py`, so once it's the new code, **every finding uploads live with
zero further steps**. Enrollment is one-time (`prismor enroll <token>`).

### Local / pre-release (stopgap for testing)
Point the Claude Code hooks at the dev checkout so live sessions run the new
code now, and keep the local control-plane server running:

```jsonc
// ~/.claude/settings.json — hook command
"PYTHONPATH=<repo> <repo>/venv/bin/python -m prismor.runtime.cli \
   hook-dispatch --agent claude --workspace \"$HOME\" --mode observe"
```
(Requires the local prismor-web server up at the `api_base` in
`~/.prismor/identity.json`. A new Claude session must be started to pick up the
hook change.)

## Verification (tested 2026-06-10)

- Ran a finding through the **dev** `hook-dispatch` with the real enrolled
  identity → uploaded a `secret_exfiltration` event **live** to the org,
  redacted, within ~1s. Dashboard (15s poll) reflects it with no refresh.
- Backfill of 3,067 historical local findings → all ingested redacted.
- Full control loop, a real remote Linux box, and a tamper test all pass.

## Known limitation (follow-up)

Telemetry currently uploads **only when there is a finding** — the sink fires on
`current_findings`. Benign tool calls (`git status`, a normal file read) produce
no event. So the **"Tool Calls Inspected (24h)" KPI counts flagged calls, not
total tool calls** — the label oversells.

Planned fix: emit a lightweight redacted event for **every** tool call (type +
verdict=`allowed`), so the dashboard reflects true volume and the KPI is honest.
Until then, the dashboard is an accurate view of *security-relevant* activity
(blocks/warns), which for typical usage is still substantial.

## Operational notes

- **Redaction:** records carry severity/category/verdict/tool/title +
  `evidenceHash` — never raw commands, paths, prompts, or secrets (unless an org
  admin opts into full capture).
- **Heartbeat:** `Device.lastSeenAt` updates on every upload; a device that
  stops reporting is the detectable signal (see the tamper analysis).
- **Local server dependency:** the stopgap points live telemetry at the local
  dev server — if it stops, uploads fail silently (best-effort, never blocks the
  agent). Production removes this dependency.
