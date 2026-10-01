# AutoGen (Microsoft) — Core runtime integration

Prismor adapter for the **AutoGen Core** runtime. Source lives at
[`adapters/autogen-core/`](../adapters/autogen-core/), bundled into the main
`prismor` package (no separate PyPI package).
Registry entry: `id: autogen-core` in
[`prismor/runtime/integrations/registry.yaml`](../prismor/runtime/integrations/registry.yaml).

## Install

```bash
pip install "prismor[autogen-core]"
```

## Connect to the console

To see this agent's tool calls in the Prismor console and control it from there:

1. In the console, open **Agents**. Under **SDK & deployed agents**, enter a workload name and click **Mint agent key**. The key is shown once, so put it in your deployment's secret manager.
2. Set it as `PRISMOR_AGENT_KEY` in the agent's environment.
3. Run the agent. Its first guarded tool call pulls your org's signed policy and starts reporting, and the agent appears in the console under that workload name. Changes you make in the console (mode, blocked tools) reach it on its next tool call, at most about 30 seconds later.

Without a key the adapter still enforces your local policy but reports nothing. To check the connection, run `prismor doctor` with the same `PRISMOR_AGENT_KEY` set.

## Why this hook point (and its scope)

`autogen_core.tool_agent.tool_agent_caller_loop` / `ToolAgent` send each
model-requested tool call to the runtime as an individual
`runtime.send_message(FunctionCall, recipient=tool_agent_id)` call. Every
message sent through an `autogen-core` `AgentRuntime` passes through its
registered `InterventionHandler.on_send()` first — that's the real,
genuine pre-execution gate this adapter hooks.

**Scope caveat:** this only covers the low-level `autogen-core` runtime.
The high-level `AgentChat` `AssistantAgent` (what most AutoGen users
actually build with) does not route tool execution through this same
`send_message`/`ToolAgent` path, so this adapter does not cover
`AssistantAgent` usage — only code built directly on `autogen-core`
primitives (`SingleThreadedAgentRuntime`, `ToolAgent`,
`tool_agent_caller_loop`).

## Use

```python
from autogen_core import SingleThreadedAgentRuntime, AgentId
from autogen_core.tool_agent import ToolAgent
from prismor.autogen_core import PrismorInterventionHandler

runtime = SingleThreadedAgentRuntime(
    intervention_handlers=[
        PrismorInterventionHandler(subject="user:alice", mode="enforce"),
    ],
)
await ToolAgent.register(runtime, "tool_agent", lambda: ToolAgent("tools", [run_shell_tool]))
runtime.start()
```

A denied call raises `autogen_core.tool_agent.ToolException` by default —
`tool_agent_caller_loop` specifically catches this exception type and
converts it into a failed `FunctionExecutionResult` fed back to the model,
so the conversation continues with the denial visible to the model. Pass
`drop_instead_of_raise=True` to return `DropMessage` instead (silently
cancels delivery with no result fed back). `mode="observe"` is log-only.

## Per-user control

`subject` (a `Subject`, `"user:alice"`-style string, or `None`) scopes
policy, IAM profile selection, and telemetry to the end-user — the same
generic mechanism every adapter uses.

## Verified

Live-tested against a real `SingleThreadedAgentRuntime` + `ToolAgent` +
`tool_agent_caller_loop`, calling `openai:gpt-4o-mini` with a genuine
OpenAI API key: a shell tool call matching a destructive-command policy
rule was denied before the tool's Python implementation ever ran (the
model received a `ToolException`-derived failure result and reported the
denial), while a benign command executed normally.

## See also

- [Framework adapters overview](frameworks-overview.md)
- [IAM](iam.md) — per-user permission profiles
