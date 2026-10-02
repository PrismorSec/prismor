# SDK & Framework Integration

Prismor guards production framework agents at the **tool-execution boundary**. An
adapter wraps the one function a framework calls to run a tool, and routes that
call through the **local Prismor runtime** before the tool body executes.

See also: [docs/connecting-to-the-platform.md](connecting-to-the-platform.md)
(the runtime — not the SDK — is what connects to the platform) ·
[docs/frameworks-overview.md](frameworks-overview.md).

## The one rule: the SDK talks to the LOCAL RUNTIME, never the control plane

Every adapter funnels into `prismor.runtime.runtime.evaluate_tool_call(...)` →
`Decision{allow, findings, reason, subject}`. Python adapters import and call it
in-process; non-Python adapters POST to a local sidecar (`prismor/runtime/eval_server.py`)
that calls the same function. The runtime evaluates policy locally and is the
*only* component that phones home (telemetry, heartbeat, signed-policy pull). The
SDK has no control-plane credentials and no control-plane URL.

```
  ┌─────────────────────────────────────────────┐
  │ Your process (framework agent)               │
  │  LLM ──tool call──► Adapter wrap point         │
  │                       │                        │
  │   (Python) in-process │  evaluate_tool_call()   │  (TS / any lang)
  │   ──────────────────► │ ◄──────────────────────  POST /v1/evaluate
  │              prismor.runtime.runtime.evaluate_tool_call  │   (eval-server, same box)
  │                       │ Decision                │
  │             allow ────┴──► run tool             │
  │             deny  ───────► blocked / PrismorBlocked
  └───────────────────────┬─────────────────────────┘
                          │  (runtime only)
                          ▼   redacted telemetry · signed-policy pull · heartbeat
                 Prismor control plane
```

**Always honor `Decision.allow`.** The runtime already folds the requested mode
*and* any org per-agent control (kill-switch / forced-enforce) into
`Decision.allow`. Adapters must block whenever `allow` is `False` — they must not
re-derive the verdict from a locally-passed `mode`, or an org override can be
bypassed.

The canonical event every adapter builds is identical in shape
(`prismor/runtime/hooks.py`): `{ ts, session_id, agent, agent_event, type, command|path|
url|content, metadata{tool_name, framework, args, kwargs} }`. `type` selects the
matched field: `shell→command`, `file_read|file_write→path`, `network→url`,
`prompt|tool_result→content`.

## Multi-tenant subjects

One deployed agent serves many users. Attribute each call with `use_subject`
(a contextvar — async/thread-safe; `prismor/runtime/principal.py`):

```python
from prismor.openai import use_subject
with use_subject("user:alice"):       # also "user=alice;team=data;org=acme"
    Runner.run_sync(agent, prompt)
```

Priority: explicit `subject=` arg → `use_subject` context → `PRISMOR_SUBJECT` env
→ enrolled device identity → anonymous.

These subjects are **asserted**: good for attribution, not proof. When the org
verifies identity, pass the user's IdP token instead and the verified claims
(user, team, roles) replace the asserted subject:

```python
with use_subject(token=user_jwt):
    Runner.run_sync(agent, prompt)
```

See [identity-verification.md](identity-verification.md).

## Per framework

| Framework | Wrap point (patched) | Guard call |
|---|---|---|
| OpenAI Agents | `FunctionTool.on_invoke_tool` | `guard_agent(agent, subject=...)` |
| LangChain/LangGraph | `tool.func` / `tool.coroutine` (+ `PrismorCallbackHandler`) | `guard_tools([...], subject=...)` |
| CrewAI | `tool.func` / `_run` / `run` | `guard_tools([...], subject=...)` |
| browser-use | `Registry.execute_action` | `guard_controller(controller, subject=...)` |
| Vercel AI (TS) | `tool.execute` → HTTP | `prismorTools({...}, { subject })` |

### OpenAI Agents
```python
from agents import Agent, Runner
from prismor.openai import guard_agent, use_subject
agent = Agent(name="ops", tools=[run_shell])
guard_agent(agent, subject="user:alice")     # wraps every FunctionTool
with use_subject("user:alice"):
    Runner.run_sync(agent, "…")
```

### LangChain / LangGraph
```python
from prismor.langchain import guard_tools
tools = guard_tools([run_shell, fetch_url], subject="user:alice")
# Observability-only: config={"callbacks": [PrismorCallbackHandler()]}
```

### CrewAI
```python
from prismor.crewai import guard_tools
tools = guard_tools([run_shell], subject="user:alice")
```

### browser-use
```python
from prismor.browser_use import guard_controller, use_subject
controller = Controller(); guard_controller(controller)   # patch once at startup
with use_subject("user:alice"):
    await Agent(task="…", llm=llm, controller=controller).run()
```

### Vercel AI SDK / any language (HTTP)
Run the sidecar: `prismor eval-server --port 7071 --workspace .`
```ts
import { prismorTools } from "prismor-warden";
const tools = prismorTools({ run_shell, search_web }, { subject: `user:${userId}` });
await generateText({ model, tools, prompt });
```
`POST /v1/evaluate`:
```json
{ "tool_name":"run_shell", "arguments":{"command":"rm -rf /"},
  "event_type":"shell", "agent":"vercel-ai", "mode":"enforce",
  "session_id":"req-1", "subject":"user:alice", "workspace":"/srv/app" }
```
→ `200 {"allow":false,"reason":"[HIGH] …","findings":[…],"subject":{…}}`. Subject
and agent name may also be sent as `X-Prismor-Subject` / `X-Prismor-Agent-Name`
headers; the user's IdP token goes in `X-Prismor-Identity: Bearer <jwt>`, and the
call's target in a `resource` body field ([attribute conditions](attribute-conditions.md)).

## Failure behavior

The eval-server is local; if it is unreachable the HTTP client treats the call as
allowed so an infrastructure fault never breaks the agent. **Note:** failure
handling is not yet uniform across all adapters — a known open item, with an
intended single policy. For non-loopback binds of the eval-server, an auth
follow-up is also planned.

## Licensing

The adapters are **MIT** (`adapters/LICENSE`) — the most permissive terms, so the
ecosystem can integrate and vendor them freely. The Prismor runtime they call into
is Apache-2.0 (repo root `LICENSE`).
