# SDK clients (Python and TypeScript)

The client SDK is the check/enforce surface the framework adapters are built
on. Use it directly when your agent is not one of the supported frameworks, or
when you want the policy decision without an adapter's wrapping.

See also: [sdk-integration.md](sdk-integration.md) (the adapters, and the one
rule below) · [decision-contract.md](decision-contract.md) (what a `Decision`
means) · [frameworks-overview.md](frameworks-overview.md).

**The one rule:** the client talks to the **local runtime**, never the control
plane. Every check goes through `prismor.runtime.runtime.evaluate_tool_call`,
the same function behind the coding-agent hooks. The runtime evaluates policy
locally and is the only component that phones home (telemetry, heartbeat,
signed-policy pull). The client has no control-plane credentials and no
control-plane URL.

**Always honor `Decision.allow`.** The runtime folds the requested mode *and*
any org per-agent control (kill-switch, forced enforce) into it. The client
never re-derives a verdict from its own `mode`, and neither should you.

## Python: `prismor.sdk`

Ships inside the `prismor` package (`pip install prismor`); nothing extra to
install.

```python
from prismor.sdk import PrismorClient, PrismorBlocked, use_subject
```

### Guard a callable

```python
client = PrismorClient(workspace=".", mode="enforce")

def run_shell(command: str) -> str:
    ...

run_shell = client.guard(run_shell)   # sync or async — detected automatically
run_shell(command="ls")               # allowed: runs, output redacted
run_shell(command="rm -rf /")         # denied: never runs; returns the denial string
```

`guard` runs the whole sequence on every call: build the event → check → (on
a denial) headless approval → run, or render the denial → redact the result.
An async callable gets an async wrapper; its decision and any approval wait run
in a worker thread so the event loop keeps servicing other tools.

### Check without guarding

```python
decision = client.check("run_shell", kwargs={"command": "rm -rf /"})
decision.allow      # False
decision.verdict    # "block" | "step_up" | "defer" | "modify" | "allow"
decision.rule_id    # the rule that produced the verdict
decision.reason     # "[CRITICAL] destructive-command ..."
decision.findings   # every finding, blocking or not
```

`check` never raises. Positional arguments, keyword arguments, or an explicit
`payload=` string become the matched value; `event_type` selects the field
(`shell` → `command`, `file_read` / `file_write` → `path`, `network` → `url`,
`prompt` → `prompt`, `tool_result` → `response`).

### Handle a block

Three ways, in precedence order:

```python
# 1. Decide in the app: the callback's return value is the tool's result.
def on_block(decision, ctx):
    return f"Not allowed: {decision.reason} (tool {ctx.tool_name}, args {ctx.kwargs})"

client = PrismorClient(mode="enforce", on_policy_block=on_block)

# 2. Hard stop.
client = PrismorClient(mode="enforce", raise_on_block=True)
try:
    run_shell(command="rm -rf /")
except PrismorBlocked as exc:
    exc.decision.blocking   # the finding that blocked

# 3. Default: the denial string the model sees —
#    "⛔ Prismor blocked this tool call: [CRITICAL] destructive-command ..."
```

`ctx` is a `BlockContext(tool_name, args, kwargs, session_id, event)`. An
exception raised by the callback propagates.

### Headless approvals

A `step_up` verdict needs a human. With no one at the keyboard, the client
posts an approval request to the console and waits (`resolve_block`, or
`resolve_block_async` from an async tool). The result is a `BlockResolution`:

| `approved` | `redacted` | Meaning |
|---|---|---|
| `False` | — | denied, timed out, not enrolled, approvals off, or any error on the path. **Fail closed.** |
| `True` | `False` | run the call as-is |
| `True` | `True` | run it with `res.args` / `res.kwargs`, from which the approver's flagged values were stripped on-device |

`guard` does this for you. Pass `approvals=False` to skip the flow and treat
every denial as final.

### Redact tool output

```python
client.redact(result, decision)
```

The pre-call check can only refuse; a tool that reads a file with a credential
in it is allowed, and the credential is in the return value. `redact` masks
cloaked secrets and data-boundary values in strings, containers and objects (in
place). `guard` applies it to every result. Never raises.

### Sessions, subjects and budgets

```python
client = PrismorClient(
    agent="support-bot",           # framework/agent id (telemetry, heartbeat)
    agent_name="support-bot-eu",   # per-instance name (dashboard kill-switch)
    session_id="conv-42",          # default: f"{agent}-{pid}"
    subject="user:alice",          # or resolve per call — see below
    budget={"max_tool_calls": 50},
)
client.check("run_shell", kwargs={"command": "ls"},
             session_id="conv-43", budget={"max_tool_calls": 10})
```

- **Session** groups events in the session store and the console. The client
  default is one per process; pass one per conversation, or per call.
- **Subject** attributes each call to an end user. Priority: `subject=` on the
  call → `subject=` on the client → the ambient `use_subject("user:alice")`
  context (a contextvar, async- and thread-safe) → `PRISMOR_SUBJECT` → the
  enrolled device identity → anonymous. `use_subject` is the same object the
  adapters export.
- **Budget** is a free-form, JSON-serialisable value recorded as
  `metadata.budget` on every event, so it reaches the session store, the audit
  trail and telemetry. **No built-in rule enforces it yet.** It is there for
  your own policy rules and for the console to read.

### Declare tools and intent

```python
client.declare_tools(["run_shell", "fetch_url"], goal="triage support tickets")
```

Registers the agent and its tool roster in the workspace inventory (the
console's capability view) and, with a `goal`, synthesizes the session's
intent-scoped rules so the runtime can refuse calls that do not serve the
task. Best-effort: never raises.

### Event shape

`client.build_event(...)` (or the module-level `prismor.sdk.build_event`)
returns the canonical event the runtime evaluates: `contract.new_event` plus
the metadata keys the adapters write — `tool_name`, `framework`, `args`,
`kwargs`, `subagent_id`, `subagent_type`, `surface` (`"sdk-adapter"`), and
`budget` when set. Caller-supplied `metadata=` is merged first; those fixed
keys win. `check_event(event)` evaluates a pre-built event.

### How the framework adapters use it

| Adapter | What it keeps | What the client does |
|---|---|---|
| `prismor.langchain` | wraps `tool.func` / `tool.coroutine`; `PrismorCallbackHandler` reads the LangGraph node | `guard`; `check` + `resolve_block` (handler); `declare_tools` |
| `prismor.crewai` | picks `func` / `_run` / `run` | `guard`; `declare_tools` |
| `prismor.openai` | wraps `FunctionTool.on_invoke_tool`, reads the active agent for handoffs; a plain callable returns the `Decision` when not raising | `build_event` + `check_event`; `resolve_block_async`; `on_blocked`; `redact` |
| `prismor.browser_use` | patches `Registry.execute_action`, picks the event type per action, keeps its `⛔ Prismor blocked action '<name>'` wording | `check`; `resolve_block_async`; `on_blocked`; `redact` |

Every adapter accepts `on_policy_block=` and re-exports the one shared
`PrismorBlocked`, so `except PrismorBlocked` works whichever adapter raised it.

## TypeScript: `prismor-sdk`

```bash
npm install prismor-sdk                          # Node 18+, no runtime dependencies, CommonJS + types
prismor eval-server --port 7071 --workspace .    # the sidecar (pip install prismor)
```

TypeScript cannot run the Python policy engine in-process, so the client
talks to the **eval-server**, a local sidecar that calls the same
`evaluate_tool_call` and answers with the decision's wire form. Set
`PRISMOR_AGENT_KEY` on the eval-server process (not the app) to connect it
to the console; beyond loopback, run it with `--api-key` and pass `apiKey`.

### Guard a function

```ts
import { PrismorClient, PrismorBlocked } from "prismor-sdk";

const client = new PrismorClient({ mode: "enforce" });
const runShell = client.guard(async ({ command }) => exec(command), { toolName: "run_shell" });

await runShell({ command: "ls" });         // allowed: runs, result redacted
await runShell({ command: "rm -rf /" });   // denied: throws PrismorBlocked, tool never runs
```

`guard` evaluates the first call argument (pass `args: (...callArgs) => …`
to pick something else, as the LangChain wrapper does for a `ToolCall`
envelope), then runs the function and masks its result through
`/v1/redact`. The wrapper is always async.

### Check without guarding

```ts
const decision = await client.check("run_shell", { command: "rm -rf /" });
decision.allow          // false
decision.verdict        // "block" | "step_up" | "defer" | "modify" | "allow"
decision.rule_id        // "destructive-command"
decision.reason         // "[CRITICAL] …"
decision.findings       // every finding
```

`check` never throws on a denial. Arguments must be an object; anything
else is sent as `{ value }`.

### Handle a block

```ts
// 1. Decide in the app: the callback's return value is the tool's result.
new PrismorClient({ mode: "enforce", onPolicyBlock: (decision, ctx) =>
  `Not allowed: ${decision.reason} (tool ${ctx.toolName})` });

// 2. Default: throw. `err.decision` carries the verdict.
try { await runShell({ command: "rm -rf /" }); }
catch (err) { if (err instanceof PrismorBlocked) console.log(err.decision.rule_id); }

// 3. Return the denial string the model sees instead of throwing.
new PrismorClient({ mode: "enforce", raiseOnBlock: false });
```

`ctx` is `{ toolName, args, sessionId }`. An exception thrown by the
callback propagates.

### When the eval-server cannot answer

Enforce mode **fails closed** (the call is denied with a synthetic
`allow: false` decision and one `console.error` line); observe mode **fails
open** (allowed, one `console.warn`). `failMode: "open" | "closed"` overrides
either default; `timeoutMs` (default 10 s) bounds the wait.

### Subjects, sessions and budgets

```ts
import { useSubject } from "prismor-sdk";

const client = new PrismorClient({
  agent: "support-bot", agentName: "support-bot-eu",
  sessionId: "conv-42", budget: { max_tool_calls: 50 },
});

app.post("/chat", (req, res) =>
  useSubject(`user:${req.user.id}`, () => handle(req, res)));   // every check inside is attributed

await client.check("run_shell", { command: "ls" }, { sessionId: "conv-43", budget: 10 });
```

- **Subject** priority: `subject` on the call → `subject` on the client →
  the ambient `useSubject()` scope (AsyncLocalStorage; concurrent requests
  cannot bleed) → `PRISMOR_SUBJECT`. It is sent in the body and as the
  `X-Prismor-Subject` header.
- **Session** defaults to `<agent>-<pid>-<n>` per client; the framework
  wrappers build one client per wrapped tool.
- **Budget** and **metadata** are merged into the event's metadata by the
  eval-server (its own keys win). **No built-in rule enforces a budget yet.**

### Redaction, health, contract

`client.redact(value)` masks a value through `/v1/redact` (best effort;
`guard` does it for every result). `client.health()` and
`client.contract()` read `/health` and `/v1/contract`, so an app can check
the sidecar and its `contract_version` at startup.

### Options

| Option | Default | Meaning |
|---|---|---|
| `evalUrl` | `http://127.0.0.1:7071` | the eval-server |
| `apiKey` | `PRISMOR_EVAL_KEY` | bearer token when the server runs with `--api-key` |
| `workspace` | `process.cwd()` | forwarded to the policy engine |
| `agent` / `agentName` | `"sdk"` / same as `agent` | framework id / per-instance name (kill-switch) |
| `mode` | `"observe"` | `"enforce"` blocks; `"observe"` logs what would block |
| `failMode` | closed in enforce, open in observe | what to do when the server cannot answer |
| `timeoutMs` | `10000` | per-request bound |
| `subject`, `sessionId`, `eventType` | see above / `<agent>-<pid>-<n>` / `"shell"` | |
| `budget`, `metadata` | — | recorded on every event |
| `onPolicyBlock(decision, ctx)` | — | its return value becomes the tool result on a denial |
| `raiseOnBlock` | `true` | `false` returns the `⛔ Prismor blocked …` string |
| `fetch` | the global `fetch`, resolved at call time | injectable transport (tests) |

### Built on it

[`prismor-warden`](frameworks-vercel-ai.md) (Vercel AI SDK, LangChain JS /
LangGraph JS) and [`prismor-mastra`](frameworks-mastra.md) are thin wrappers:
each wrapped tool gets a `PrismorClient` with the framework's `agent` id and
`guard` around its `execute` / `invoke`. Every `PrismorClient` option is
accepted by their `prismorTools(...)` / `prismorTool(...)` calls, and they
re-export `PrismorClient`, `PrismorBlocked` and `useSubject`.
