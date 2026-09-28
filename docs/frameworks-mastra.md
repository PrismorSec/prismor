# Mastra (TypeScript) integration

Prismor adapter for **Mastra**. This is a genuinely separate npm package —
`prismor-mastra` — since a Python wheel can't bundle TypeScript. Source
lives at [`adapters/mastra/`](../adapters/mastra/).
Registry entry: `id: mastra` in
[`prismor/runtime/integrations/registry.yaml`](../prismor/runtime/integrations/registry.yaml).

Every tool call is routed through the Prismor **eval-server** (a local HTTP
sidecar wrapping the same policy engine the Python adapters call
in-process) before the tool body runs.

## Why this hook point (and a correction from the original plan)

The original plan pointed at `processOutputStep` — Mastra's own type docs
describe it as running "after each LLM response, before tool execution,"
with an injected `abort()` to deny. **This turned out not to be reliable
when tested against a real agent run** (`@mastra/core` v0.x, 2026-07):
calling `abort()` from `processOutputStep` throws a workflow-level error,
but the tool's `execute` function runs anyway — confirmed with timestamped
logging showing `execute` firing *after* `abort()` was called.

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

## Connect to the console

To see this agent's tool calls in the Prismor console and control it from there:

1. In the console, open **Agents**. Under **SDK & deployed agents**, enter a workload name and click **Mint agent key**. The key is shown once, so put it in your deployment's secret manager.
2. Set it as `PRISMOR_AGENT_KEY` in the environment of the `prismor eval-server` process. The TypeScript adapter never sees the key; the eval-server evaluates, reports and pulls policy.
3. Run the agent. Its first guarded tool call pulls your org's signed policy and starts reporting, and the agent appears in the console under that workload name. Changes you make in the console (mode, blocked tools) reach it on its next tool call, at most about 30 seconds later.

Without a key the eval-server still enforces your local policy but reports nothing. To check the connection, run `prismor doctor` on the eval-server host with the same `PRISMOR_AGENT_KEY` set.

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

## Per-user control

`subject` follows the same convention as the Vercel AI SDK adapter's
`useSubject()` / the Python adapters' `use_subject()` — pass it per-call
or set it on `prismorTool`/`prismorTools` — and is forwarded to the
eval-server, resolved to per-user IAM profiles, and recorded in telemetry.

## Verified

Live-tested against a real Mastra `Agent` running `gpt-4o-mini` (via
`@ai-sdk/openai`) with a genuine OpenAI API key and a local `prismor
eval-server`: a destructive shell command was denied before the tool's
JavaScript implementation ever ran; a benign command executed normally.

## See also

- [Framework adapters overview](frameworks-overview.md)
- [SDK clients](sdk-clients.md) — the `prismor-sdk` client this adapter is built on
- [Vercel AI SDK integration](frameworks-vercel-ai.md) — the reference HTTP adapter pattern this one follows
- [IAM](iam.md) — per-user permission profiles
