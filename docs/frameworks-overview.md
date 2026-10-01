# Framework adapters — overview

Prismor intercepts tool calls in production framework agents — not just
local coding agents. The integration is designed to be **a single function call**
on your existing agent or controller object, with no changes to your tool logic.

## UX at a glance

| Framework | Language | Install | Guard | Multi-tenant |
|---|---|---|---|---|
| OpenAI Agents SDK | Python | `pip install "prismor[openai-agents]"` | `guard_agent(agent)` | `use_subject("user:alice")` |
| LangChain / LangGraph | Python | `pip install "prismor[langchain]"` | `guard_tools([...])` | `use_subject("user:alice")` |
| CrewAI | Python | `pip install "prismor[crewai]"` | `guard_tools([...])` | `use_subject("user:alice")` |
| browser-use | Python | `pip install "prismor[browser-use]"` | `guard_controller(controller)` | `use_subject("user:alice")` |
| Pydantic AI | Python | `pip install "prismor[pydantic-ai]"` | `guard_toolsets([...])` | `subject="user:alice"` |
| AutoGen Core (Microsoft) | Python | `pip install "prismor[autogen-core]"` | `PrismorInterventionHandler(...)` | `subject="user:alice"` |
| Agno | Python | `pip install "prismor[agno]"` | `tool_hooks=[prismor_tool_hook]` | `subject="user:alice"` |
| Semantic Kernel (Microsoft) | Python | `pip install "prismor[semantic-kernel]"` | `add_filter(..., make_filter(...))` | `subject="user:alice"` |
| Google ADK | Python | `pip install "prismor[google-adk]"` | `before_tool_callback=make_before_tool_callback(...)` | `subject="user:alice"` |
| BeeAI Framework | Python | `pip install "prismor[beeai]"` | `guard_tool(tool)` / `guard_tools([...])` | `subject="user:alice"` |
| Claude Code Agent SDK | Python | `pip install "prismor[claude-agent-sdk]"` | `hooks={"PreToolUse": [prismor_hook_matcher(...)]}` | `subject="user:alice"` |
| Vercel AI SDK | TypeScript | `npm install prismor-warden` | `prismorTools(tools)` | `useSubject("user:alice", fn)` |
| LangChain JS / LangGraph JS | TypeScript | `npm install prismor-warden` | `prismorLangChainTools([...])` | `useSubject("user:alice", fn)` |
| Mastra | TypeScript | `npm install prismor-mastra` | `prismorTool(name, tool)` | `subject: "user:alice"` |
| Any language | Any | — (HTTP client only) | `POST /v1/evaluate` | `X-Prismor-Subject` header |

> The Python adapters ship inside the `prismor` package (no separate PyPI
> packages) — each extra just pulls the framework itself.
> `prismor[frameworks]` installs all of them. Vercel AI SDK / LangChain JS
> ship as the `prismor-warden` npm package; Mastra ships separately as
> `prismor-mastra` since it wraps tools directly rather than going through
> an eval-server client — both are genuinely separate packages since a
> Python wheel can't bundle TypeScript.

The multi-tenant pattern is the same in every language: guard once at startup
with no bound subject, then wrap each request with `use_subject` (Python) or
`useSubject` (TypeScript). A context variable (`ContextVar` / `AsyncLocalStorage`)
threads the subject through the evaluation pipeline — thread-safe and
async-safe, so concurrent requests for different users cannot bleed.

For raw HTTP callers: pass `subject` per call in the request body or
`X-Prismor-Subject` header. The eval-server resolves it identically.

## Connect to the console

To see this agent's tool calls in the Prismor console and control it from there:

1. In the console, open **Agents**. Under **SDK & deployed agents**, enter a workload name and click **Mint agent key**. The key is shown once, so put it in your deployment's secret manager.
2. Set it as `PRISMOR_AGENT_KEY` in the agent's environment.
3. Run the agent. Its first guarded tool call pulls your org's signed policy and starts reporting, and the agent appears in the console under that workload name. Changes you make in the console (mode, blocked tools) reach it on its next tool call, at most about 30 seconds later.

Without a key the adapter still enforces your local policy but reports nothing. To check the connection, run `prismor doctor` with the same `PRISMOR_AGENT_KEY` set.

## What "guard" does

Regardless of framework, every adapter does the same three things:

1. **Intercept** — wraps the framework's tool execution surface (see table below)
   so the original callable is never reached on a denied call.
2. **Evaluate** — calls `prismor.runtime.runtime.evaluate_tool_call()` with a canonical
   event and the resolved subject. Same pipeline as coding-agent hooks.
3. **Block or allow** — in `enforce` mode a denied call returns a denial string
   to the model (the run recovers gracefully) or raises `PrismorBlocked`. In
   `observe` mode findings are recorded but the call always proceeds.

## Hook points by framework

| Framework | What gets wrapped | When it fires |
|---|---|---|
| OpenAI Agents SDK | `FunctionTool.on_invoke_tool` (async) | after the LLM decides to call a tool, before the function runs |
| LangChain / LangGraph | `tool.func` + `tool.coroutine` | before `tool.invoke()` / `tool.ainvoke()` executes |
| CrewAI | `tool.func` → `tool._run` → `tool.run` (first found) | before the tool implementation runs |
| browser-use | `Registry.execute_action` | before Playwright executes any browser action |
| Pydantic AI | `WrapperToolset.call_tool(name, tool_args, ctx, tool)` | before `super().call_tool(...)` — the single choke point for every tool |
| AutoGen Core (Microsoft) | `InterventionHandler.on_send(message, ...)` | before any `FunctionCall` message reaches a `ToolAgent` |
| Agno | `tool_hooks` list on `Agent`/`Team` | before `function_call(**arguments)` continues the chain |
| Semantic Kernel (Microsoft) | filter `filter_fn(context, next)` in the invocation middleware stack | before `await next(context)` — which calls `context.function.invoke(...)` |
| Google ADK | `before_tool_callback(tool, args, tool_context)` | before the tool call — returning a dict skips it entirely |
| BeeAI Framework | `Tool`'s `Emitter` `"start"` event | before `self._run(...)` inside `Tool.run()` |
| Claude Code Agent SDK | `PreToolUse` hook (`HookMatcher`) | before Claude runs the tool — same hook system as the CLI |
| Vercel AI SDK | `tool.execute` | before the tool body runs, after the LLM emits the tool call |
| LangChain JS / LangGraph JS | `tool.invoke` (StructuredTool) | before the tool runs — covers LangGraph's `ToolNode` / `createReactAgent` |
| Mastra | `tool.execute` | before the tool body runs, after the LLM emits the tool call |
| HTTP (any language) | caller-side `POST /v1/evaluate` | before calling the tool implementation |

## Eval-server (non-Python languages)

For TypeScript, Go, Ruby, Java, Rust — any language that can make an HTTP request
— run the **eval-server** as a sidecar and call it before executing each tool:

```bash
prismor eval-server --port 7071 --workspace /path/to/project
```

```
POST /v1/evaluate
{
  "tool_name": "run_shell",
  "arguments": { "command": "rm -rf /" },
  "event_type": "shell",
  "mode": "enforce",
  "subject": "user:alice"
}

→ { "allow": false, "reason": "[CRITICAL] ...", "subject": { "user_id": "alice" } }
```

The Python policy engine, IAM, and telemetry run inside the sidecar. Adapters
in other languages are ~25 lines of HTTP client code with no Python dependency.
If the eval-server is down, the shipped TypeScript adapter **fails closed in
enforce mode** (a suspension or deny keeps holding) and **open in observe mode**
(monitoring never breaks the agent), overridable via `failMode`. Raw HTTP
callers choose their own failure behavior — match these defaults.

Validated live on an Ubuntu EC2 instance with real OpenAI function calls:

| Language | Adapter size | Dependencies |
|---|---|---|
| TypeScript (Vercel AI SDK) | ~80 lines | `npm install prismor-warden` |
| Node.js (raw) | ~25 lines | built-in `fetch` |
| Ruby | ~20 lines | stdlib `Net::HTTP` |
| Java 21 | ~25 lines | stdlib `java.net.http` |
| Rust | ~25 lines | `ureq` crate |

See `examples/multilang/` for runnable examples in all four languages.

## Naming agents

Every guard entry point takes an optional `name=` — an **instance label**
distinct from the framework id. Multiple agents on the same framework
("checkout-bot" and "support-bot", both on the OpenAI Agents SDK) become
individually visible and controllable:

```python
guard_agent(agent, name="checkout-bot")            # OpenAI Agents SDK
tools = guard_tools(tools, name="support-bot")     # LangChain / CrewAI
guard_controller(controller, name="browser-bot")   # browser-use
```

```ts
const tools = prismorTools(myTools, { agentName: 'checkout-bot' });  // Vercel AI SDK
```

What a name unlocks:

- **Its own row** in the org dashboard's Connections view (and a per-agent
  activity drill-in), instead of blending into the framework's aggregate.
- **Per-agent runtime control** via `prismor agents set <name>` — kill-switch
  (`--disabled` hard-blocks every call), a mode override, and a forced IAM
  profile. Config lives in `agents.yaml` (global `~/.prismor/` or per-project
  `.prismor/`); agents self-register on first sight.

```bash
prismor agents list                                # every named instance seen
prismor agents set checkout-bot --mode enforce     # this bot only
prismor agents set support-bot --disabled          # kill switch
```

Unnamed agents keep working unchanged — they report under the framework id.

## Modes

```python
guard_agent(agent, mode="observe")   # log findings, never block — safe rollout
guard_agent(agent, mode="enforce")   # block denied calls before execution
```

Start in `observe` to understand blast radius, switch to `enforce` once confident.
Policy is YAML — change it without redeploying agents.

## Per-user IAM

Add `user:<id>` or `team:<id>` keys to `.prismor/iam.yaml`:

```yaml
agents:
  # bob keeps every tool except shell + network
  user:bob:
    allowed_tools: ["*"]
    deny_tools: [Bash]
    deny_network: true
    allowed_paths: ["**"]

  # suspend a user entirely: empty allowlist blocks every tool call
  user:mallory:
    allowed_tools: []
    deny_tools: []
    deny_network: true
    allowed_paths: ["**"]
```

When a request runs under `use_subject("user:bob")`, bob's profile is selected
automatically — no env var, no code change, and no per-user re-guarding of
tools. Users without a profile get the org-wide defaults. Tool names match
what the framework sees (the wrapped function or tool's name, e.g.
`fetch_url`), so one profile applies across every framework the user reaches.

## Per-client (multi-client organizations)

If your agent serves several **clients** — your customers, each with many of
their own users — attribute each request with both dimensions using the
structured subject form:

```python
with use_subject("user=alice;team=client-acme"):
    Runner.run_sync(agent, prompt)
```

```typescript
await useSubject("user=alice;team=client-acme", () =>
  generateText({ model, tools, prompt }));
```

`team` is the client dimension: it selects `team:<id>` IAM profiles and is
recorded on every telemetry event, so activity, findings, and blocks can be
sliced per client. One profile then governs every user of that client:

```yaml
agents:
  # tighter rules for one client's tenancy
  team:client-acme:
    allowed_tools: ["*"]
    deny_tools: [run_shell]
    deny_network: true
    allowed_paths: ["**"]

  # offboard / suspend an entire client
  team:client-globex:
    allowed_tools: []
    deny_tools: []
    deny_network: true
    allowed_paths: ["**"]
```

Precedence: a `user:<id>` profile wins over the user's `team:<id>` profile, so
you can suspend one misbehaving user inside an otherwise-healthy client, or
grant one power user more than their client's baseline. Subjects are labels
asserted by your backend — Prismor clamps them to your org server-side, but
choosing which client a request belongs to is your app's authentication job.

## Per-framework guides

- [OpenAI Agents SDK](frameworks-openai-agents.md) — `guard_agent`, `prismor_guard`, FunctionTool patching
- [LangChain / LangGraph](frameworks-langchain.md) — `guard_tools`, `PrismorCallbackHandler`
- [CrewAI](frameworks-crewai.md) — `guard_tools`, BaseTool and structured tool support
- [browser-use](frameworks-browser-use.md) — `guard_controller`, network/file/shell event mapping
- [Pydantic AI](frameworks-pydantic-ai.md) — `guard_toolsets`, `WrapperToolset.call_tool`
- [AutoGen Core (Microsoft)](frameworks-autogen-core.md) — `PrismorInterventionHandler`, `on_send`
- [Agno](frameworks-agno.md) — `tool_hooks`, `make_tool_hook`
- [Semantic Kernel (Microsoft)](frameworks-semantic-kernel.md) — `make_filter`, `AUTO_FUNCTION_INVOCATION`
- [Google ADK](frameworks-google-adk.md) — `make_before_tool_callback`, `before_tool_callback`
- [BeeAI Framework](frameworks-beeai.md) — `guard_tool`, `Emitter` `"start"` event
- [Claude Code Agent SDK](frameworks-claude-agent-sdk.md) — `prismor_hook_matcher`, `PreToolUse` hooks
- [Vercel AI SDK](frameworks-vercel-ai.md) — `prismorTools`, TypeScript, eval-server HTTP protocol
- [Mastra](frameworks-mastra.md) — `prismorTool`, TypeScript, direct `execute` wrapping
