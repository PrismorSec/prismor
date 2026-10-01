# OpenAI Agents SDK integration

Guard every tool your OpenAI Agents SDK agent can call. Prismor checks each
call against your policy before the tool runs, blocks the dangerous ones, and
reports them to the Prismor console. One line wraps the whole agent, and you can
apply different rules to each end user of a multi-tenant deployment.

The adapter ships inside the main `prismor` package (source:
[`adapters/openai-agents/`](../adapters/openai-agents/)).

## Install

```bash
pip install "prismor[openai-agents]"
```

## Connect to the console

To see this agent's tool calls in the Prismor console and control it from there:

1. In the console, open **Agents**. Under **SDK & deployed agents**, enter a workload name and click **Mint agent key**. The key is shown once, so put it in your deployment's secret manager.
2. Set it as `PRISMOR_AGENT_KEY` in the agent's environment.
3. Run the agent. Its first guarded tool call pulls your org's signed policy and starts reporting, and the agent appears in the console under that workload name. Changes you make in the console (mode, blocked tools) reach it on its next tool call, at most about 30 seconds later.

Without a key the adapter still enforces your local policy but reports nothing. To check the connection, run `prismor doctor` with the same `PRISMOR_AGENT_KEY` set.

## Guard an agent (easy path)

```python
from agents import Agent, function_tool
from prismor.openai import guard_agent

@function_tool
def run_shell(command: str) -> str:
    ...

agent = Agent(name="ops", tools=[run_shell])
guard_agent(agent)          # every tool now policy-checked
```

To guard a single tool or a plain callable, use
`prismor_guard(tool, subject="user:alice")`. A denied call raises `PrismorBlocked`
(or, with `raise_on_block=False`, returns the `Decision`); `guard_agent` defaults
to returning a denial string to the model so the run recovers gracefully.
`mode="observe"` is log-only — findings are still recorded, the call proceeds.

## Per-user control (multi-tenant)

The production differentiator: **one deployed agent serves many users**, and each
tool call is attributed to the end-user, not the host device. Guard the agent
once with no bound subject, then set the user per request:

```python
from prismor.openai import use_subject

guard_agent(agent)                       # once, at startup

with use_subject("user:alice"):          # in your per-request handler
    Runner.run_sync(agent, prompt)       # alice's policy + IAM apply
```

`subject` / `use_subject` accept a `Subject`, a string (`"user:alice"`,
`"user=alice;team=data"`), or `None`. Resolution order: explicit arg →
`use_subject` context → `PRISMOR_SUBJECT` → device identity → anonymous (see
[`prismor/runtime/principal.py`](../prismor/runtime/principal.py)). The subject is threaded into
policy evaluation, **IAM** profile selection (`user:<id>` / `team:<id>` profiles
in `iam.yaml`), and telemetry — same agent, different rules per user, no code
changes.

> Verified live: one guarded agent, same safe command — `user:alice` allowed,
> `user:bob` (denied shell tools by IAM) blocked, switched purely via `use_subject`.

## Event mapping

| Concern | Mechanism | Code |
|---|---|---|
| Interception | wrap the callable | `prismor_guard(tool)` |
| Canonical event | `{type, agent, command/path/url, metadata}` | `build_event()` |
| Decision | `evaluate_tool_call(...) → Decision` | [`prismor/runtime/runtime.py`](../prismor/runtime/runtime.py) |
| Block | raise `PrismorBlocked` | adapter wrapper |
| Per-user | `Subject` | [`prismor/runtime/principal.py`](../prismor/runtime/principal.py) |

By default events are emitted as `type: shell`, so `destructive-command`,
`secret-exfiltration`, and the rest of the policy apply to tool arguments. For
tools whose risk is a path, URL, or output, pass `event_type="file_write"` /
`"network"` / `"tool_result"` and a `command_builder`.

## Reference

| Symbol | Purpose |
|---|---|
| `guard_agent(agent_obj, **kwargs)` | Guard all FunctionTools on an Agent in one call |
| `prismor_guard(tool, **kwargs)` | Guard a single tool or callable |
| `use_subject(value)` | Per-request subject contextmanager |
| `PrismorBlocked` | Raised on enforce-mode block (when `raise_on_block=True`) |
| `build_event(...)` | Build a canonical event dict for custom hook points |

All functions accept: `subject`, `workspace`, `agent`, `mode`, `session_id`,
`event_type`, `command_builder`, `raise_on_block`. See
[`adapters/openai-agents/`](../adapters/openai-agents/) for full signatures.

## Other frameworks

- [LangChain / LangGraph](frameworks-langchain.md) — `guard_tools([...])`, `PrismorCallbackHandler`
- [CrewAI](frameworks-crewai.md) — `guard_tools([...])`, BaseTool and structured tool support
- [browser-use](frameworks-browser-use.md) — `guard_controller(controller)`, network/file/shell event mapping
- [All frameworks — UX overview](frameworks-overview.md)
