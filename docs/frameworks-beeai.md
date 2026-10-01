# BeeAI Framework integration

Prismor adapter for the **BeeAI Framework** (IBM Research / Linux
Foundation). Source lives at [`adapters/beeai/`](../adapters/beeai/),
bundled into the main `prismor` package (no separate PyPI package).
Registry entry: `id: beeai` in
[`prismor/runtime/integrations/registry.yaml`](../prismor/runtime/integrations/registry.yaml).

## Install

```bash
pip install "prismor[beeai]"
```

## Connect to the console

To see this agent's tool calls in the Prismor console and control it from there:

1. In the console, open **Agents**. Under **SDK & deployed agents**, enter a workload name and click **Mint agent key**. The key is shown once, so put it in your deployment's secret manager.
2. Set it as `PRISMOR_AGENT_KEY` in the agent's environment.
3. Run the agent. Its first guarded tool call pulls your org's signed policy and starts reporting, and the agent appears in the console under that workload name. Changes you make in the console (mode, blocked tools) reach it on its next tool call, at most about 30 seconds later.

Without a key the adapter still enforces your local policy but reports nothing. To check the connection, run `prismor doctor` with the same `PRISMOR_AGENT_KEY` set.

## Why this hook point

BeeAI tools are built around an `Emitter`. `Tool.run()` awaits
`context.emitter.emit("start", ToolStartEvent(input=..., options=...))`
*before* calling `self._run(...)`. Verified against source
(`beeai_framework.emitter.Emitter._invoke`): listener callbacks run as
tasks inside an `asyncio.TaskGroup`, which always awaits every task before
the surrounding `async with` block exits, and re-raises if any task
failed. A listener that raises therefore genuinely prevents the tool body
from ever running — this was checked directly against source rather than
assumed, after a different framework's documented "before execution" hook
turned out not to actually block (see the Mastra adapter's notes).

## Use

```python
from beeai_framework.tools.search.duckduckgo import DuckDuckGoSearchTool
from prismor.beeai import guard_tool

tool = guard_tool(DuckDuckGoSearchTool(), subject="user:alice", mode="enforce")
```

A denied call raises inside the `"start"` listener (a plain `RuntimeError`
by default, or `PrismorBlocked` if `raise_on_block=True`); BeeAI's tool
executor surfaces this as a tool error visible to the agent, and
`self._run(...)` is never reached. `guard_tools([...])` wraps a list of
tools in one call.

## Per-user control

`subject` (a `Subject`, `"user:alice"`-style string, or `None`) scopes
policy, IAM profile selection, and telemetry to the end-user — the same
generic mechanism every adapter uses.

## Verified

Live-tested against a real BeeAI `ReActAgent` running `gpt-4o-mini` via
`beeai_framework.backend.chat.ChatModel` with a genuine OpenAI API key: a
destructive shell command was denied before the wrapped tool's `_run`
ever executed; a benign command executed normally.

## See also

- [Framework adapters overview](frameworks-overview.md)
- [IAM](iam.md) — per-user permission profiles
