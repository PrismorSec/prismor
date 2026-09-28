# prismor-sdk

The Prismor client for TypeScript/JavaScript agents. Every tool call is
checked by the local Prismor eval-server (the same policy pipeline behind the
coding-agent hooks) before it runs; denied calls never execute, and results
are masked before the model sees them. The client never talks to the control
plane.

```bash
npm install prismor-sdk
prismor eval-server --port 7071 --workspace .   # the sidecar (pip install prismor)
```

```ts
import { PrismorClient, PrismorBlocked, useSubject } from "prismor-sdk";

const client = new PrismorClient({ mode: "enforce" });

// Guard any function: check → run → redact. A denied call throws PrismorBlocked.
const runShell = client.guard(async ({ command }) => exec(command), { toolName: "run_shell" });

// Or check first and decide yourself — check() never throws on a denial.
const decision = await client.check("run_shell", { command: "rm -rf /" });
if (!decision.allow) console.log(decision.verdict, decision.rule_id, decision.reason);

// Multi-tenant: attribute every call inside the handler to the caller.
await useSubject(`user:${userId}`, () => runShell({ command: "ls" }));
```

| Option | Default | Meaning |
|---|---|---|
| `evalUrl` | `http://127.0.0.1:7071` | the eval-server |
| `apiKey` | `PRISMOR_EVAL_KEY` | bearer token when the server runs with `--api-key` |
| `mode` | `"observe"` | `"enforce"` blocks; `"observe"` logs what would block |
| `failMode` | closed in enforce, open in observe | what to do when the server cannot answer |
| `agent` / `agentName` | `"sdk"` / same as `agent` | framework id / per-instance name (kill-switch) |
| `sessionId` | `<agent>-<pid>-<n>` | session the calls are recorded under |
| `subject` | resolved per call | explicit → `useSubject()` → `PRISMOR_SUBJECT` |
| `budget`, `metadata` | — | recorded on every event; no rule enforces a budget yet |
| `onPolicyBlock(decision, ctx)` | — | its return value becomes the tool result on a denial |
| `raiseOnBlock` | `true` | `false` returns the `⛔ Prismor blocked …` string instead |
| `timeoutMs`, `workspace`, `eventType`, `fetch` | `10000`, `process.cwd()`, `"shell"`, global | |

Node 18 or later; no runtime dependencies; CommonJS with type declarations.
Full guide: [docs/sdk-clients.md](https://github.com/PrismorSec/prismor/blob/main/docs/sdk-clients.md).
The `prismor-warden` (Vercel AI SDK, LangChain JS) and `prismor-mastra`
packages are thin wrappers over this client.
