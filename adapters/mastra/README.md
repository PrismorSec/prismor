# prismor-mastra

Prismor adapter for **Mastra** (TypeScript). Every tool call is routed
through the Prismor eval-server (`prismor eval-server`, a local HTTP
sidecar wrapping the same policy engine the Python adapters call
in-process) before the tool body runs.

## Why this hook point (and a correction from the roadmap entry)

The roadmap entry for Mastra pointed at `processOutputStep` — Mastra's own
type docs describe it as running "after each LLM response, before tool
execution," with an injected `abort()` to deny. **This turned out not to
be reliable when tested against a real agent run** (`@mastra/core` v0.x,
2026-07): calling `abort()` from `processOutputStep` throws a
workflow-level error, but the tool's `execute` function runs anyway —
confirmed with timestamped logging showing `execute` firing *after*
`abort()` was called. Coarse-grained (aborts the whole step) was always a
known caveat; not actually blocking the tool at all is a different and
more serious problem, so this adapter does not use it.

Instead, `prismorTool`/`prismorTools` wrap a tool's `execute` function
directly — the same pattern the CrewAI/LangChain adapters use — which
**is** reliable: the wrapped function is what Mastra actually calls, so a
thrown error genuinely prevents the tool body from running. Since 0.2.0 the
wrapper is built on the [`prismor-sdk`](https://www.npmjs.com/package/prismor-sdk)
client; every `PrismorClient` option works here.

## Install

```bash
npm install prismor-mastra
```

Start the eval-server once, alongside your app:

```bash
prismor eval-server --port 7071
```

## Use

```ts
import { Agent } from "@mastra/core/agent";
import { openai } from "@ai-sdk/openai";
import { prismorTool } from "prismor-mastra";

const guardedRunShell = prismorTool("run_shell", runShell, {
  mode: "enforce",
  subject: "user:alice",
});

const agent = new Agent({
  name: "ops",
  model: openai("gpt-4o-mini"),
  tools: { run_shell: guardedRunShell },
});
```

A denied call throws `PrismorBlocked`; Mastra's tool-execution step
catches the thrown error and feeds it back to the model as the tool's
result, so the conversation continues with the denial visible. `mode:
"observe"` is log-only. `failMode` controls what happens if the
eval-server is unreachable (`"closed"` in enforce mode by default — a
policy suspension must hold even when the sidecar is down).

## Options

Every `PrismorClient` option from `prismor-sdk` is accepted:

| Option | Default | Description |
|---|---|---|
| `evalUrl` | `http://127.0.0.1:7071` | Eval-server URL |
| `apiKey` | `$PRISMOR_EVAL_KEY` | Bearer token for an auth-enabled eval-server |
| `mode` | `"enforce"` | Enforce blocks; observe logs only (this package keeps `enforce` as its default) |
| `failMode` | `"closed"` in enforce, `"open"` in observe | Behavior when the eval-server is unavailable |
| `subject` | resolved per call | `"user:alice"`; else the ambient `useSubject()`, else `$PRISMOR_SUBJECT` |
| `agent` / `agentName` | `"mastra"` / same as `agent` | Telemetry id / per-instance name (kill-switch) |
| `sessionId` | `mastra-<pid>-<n>` per wrapped tool | Session the calls are recorded under |
| `budget`, `metadata` | — | Recorded on every event; no rule enforces a budget yet |
| `onPolicyBlock` | — | `(decision, ctx) => result`: called on a denial instead of throwing |
| `raiseOnBlock` | `true` | `false` returns the `⛔ Prismor blocked …` string instead of throwing |
| `timeoutMs`, `workspace`, `eventType` | `10000`, `process.cwd()`, `"shell"` | |

> **Changed in 0.2.0:** built on `prismor-sdk`. `PrismorBlocked` now carries
> `.decision` and its message is `Blocked by Prismor: <reason>`; tool results
> are masked through the eval-server's `/v1/redact` before the model sees
> them; observe mode prints what enforce mode would block; the subject and
> agent name are sent as headers and `useSubject()` is exported. The
> `enforce` default is unchanged.

## Verified

Live-tested against a real Mastra `Agent` running `gpt-4o-mini` (via
`@ai-sdk/openai`) with a genuine OpenAI API key and a local `prismor
eval-server`: a destructive shell command was denied before the tool's
JavaScript implementation ever ran; a benign command executed normally.
