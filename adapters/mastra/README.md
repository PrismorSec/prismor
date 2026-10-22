# @prismor/mastra

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
thrown error genuinely prevents the tool body from running.

## Install

```bash
npm install @prismor/mastra
```

Start the eval-server once, alongside your app:

```bash
prismor eval-server --port 7071
```

## Use

```ts
import { Agent } from "@mastra/core/agent";
import { openai } from "@ai-sdk/openai";
import { prismorTool } from "@prismor/mastra";

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

## Verified

Live-tested against a real Mastra `Agent` running `gpt-4o-mini` (via
`@ai-sdk/openai`) with a genuine OpenAI API key and a local `prismor
eval-server`: a destructive shell command was denied before the tool's
JavaScript implementation ever ran; a benign command executed normally.
