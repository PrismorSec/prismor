# prismor-warden

Prismor adapter for the [Vercel AI SDK](https://sdk.vercel.ai).

Wraps tool `execute` functions to call the Prismor HTTP eval-server before
the tool body runs. Works with any framework that uses the Vercel AI SDK —
Next.js, Remix, Node.js, edge runtimes.

## Prerequisites

Start the eval-server (Python — `pip install prismor`):

```bash
prismor eval-server --port 7071 --workspace /path/to/project
```

## Install

```bash
npm install prismor-warden
```

## Usage

```typescript
import { generateText, tool } from "ai";
import { openai } from "@ai-sdk/openai";
import { z } from "zod";
import { prismorTools } from "prismor-warden";

const run_shell = tool({
  description: "Run a shell command",
  inputSchema: z.object({ command: z.string() }),
  execute: async ({ command }) => {
    // ... your implementation
  },
});

// Wrap all tools — every execute() is now policy-checked
const tools = prismorTools({ run_shell }, { subject: `user:${userId}` });

const result = await generateText({
  model: openai("gpt-5-mini"),
  tools,
  prompt: "List the files in the current directory",
});
```

A blocked call throws `PrismorBlocked`. In a Next.js API route:

```typescript
import { PrismorBlocked } from "prismor-warden";

try {
  const result = await generateText({ model, tools, prompt });
} catch (e) {
  if (e instanceof PrismorBlocked) {
    return Response.json({ error: e.message }, { status: 403 });
  }
  throw e;
}
```

## Per-user (multi-tenant)

Guard the tools once at module scope, then wrap each request handler in
`useSubject()` — every guarded tool call inside is attributed to that user,
matching the Python adapters' `use_subject()`:

```typescript
import { prismorTools, useSubject } from "prismor-warden";

const tools = prismorTools(myTools); // once, at module scope

// Next.js API route
export async function POST(req: Request) {
  const { prompt } = await req.json();
  const session = await getSession(req);

  const result = await useSubject(`user:${session.userId}`, () =>
    generateText({ model, tools, prompt }));
  return Response.json({ text: result.text });
}
```

The subject propagates via `AsyncLocalStorage`, so concurrent requests with
different users cannot bleed into each other. Per-call resolution priority:
the `subject` option, then the ambient `useSubject()` context, then the
`PRISMOR_SUBJECT` environment variable. (Passing `subject` per
`prismorTools()` call still works and takes precedence.)

## LangChain JS / LangGraph JS

The same package guards LangChain JS tools — and therefore LangGraph agents
(`ToolNode`, `createReactAgent`), which execute those tools. Guard the tool
objects once; graphs already holding a reference are covered because `invoke`
is wrapped in place:

```typescript
import { tool } from "@langchain/core/tools";
import { createReactAgent } from "@langchain/langgraph/prebuilt";
import { prismorLangChainTools, useSubject } from "prismor-warden";

const tools = prismorLangChainTools([run_shell, fetch_url]);
const agent = createReactAgent({ llm, tools });

await useSubject(`user:${userId}`, () => agent.invoke({ messages }));
```

A denied call throws `PrismorBlocked`; LangGraph's `ToolNode` catches tool
errors by default and returns the message to the model as a `ToolMessage`, so
the run recovers gracefully. All options (`failMode`, `timeoutMs`, `subject`,
`eventType`, …) work identically.

## Fail mode

If the eval-server cannot answer (not running, crashed, timeout), the adapter
follows `failMode`:

- `mode: "enforce"` (default) **fails closed** — the tool call is blocked with
  `PrismorBlocked`. An enforced policy (e.g. a suspended user) holds even when
  the sidecar is down.
- `mode: "observe"` fails open — monitoring never breaks the app.
- Set `failMode: "open"` or `"closed"` explicitly to override either default.

> **Changed in 0.3.0:** enforce mode previously failed open. Pass
> `failMode: "open"` to restore the old behavior.

## Options

| Option | Type | Default | Description |
|---|---|---|---|
| `evalUrl` | `string` | `http://127.0.0.1:7071` | Eval-server URL |
| `apiKey` | `string` | `$PRISMOR_EVAL_KEY` | Bearer token for an auth-enabled eval-server |
| `subject` | `string` | `""` | End-user: `"user:alice"` or `"user=alice;team=data"` |
| `mode` | `"enforce"\|"observe"` | `"enforce"` | Enforce blocks; observe logs only |
| `failMode` | `"open"\|"closed"` | `"closed"` in enforce, `"open"` in observe | Behavior when the eval-server is unavailable |
| `timeoutMs` | `number` | `10000` | Max wait for the eval-server per call |
| `workspace` | `string` | `process.cwd()` | Project path for policy/IAM lookup |
| `agent` | `string` | `"vercel-ai"` | Agent identifier in telemetry |
| `agentName` | `string` | same as `agent` | Per-instance name for kill-switch / per-agent controls |
| `eventType` | `string` | `"shell"` | Event type: `shell`, `network`, `file_write`, … |
