# Agno integration

Prismor adapter for Agno. Source lives at
[`adapters/agno/`](../adapters/agno/), bundled into the main `prismor`
package (no separate PyPI package).
Registry entry: `id: agno` in
[`prismor/runtime/integrations/registry.yaml`](../prismor/runtime/integrations/registry.yaml).

## Install

```bash
pip install "prismor[agno]"
```

## Connect to the console

To see this agent's tool calls in the Prismor console and control it from there:

1. In the console, open **Agents**. Under **SDK & deployed agents**, enter a workload name and click **Mint agent key**. The key is shown once, so put it in your deployment's secret manager.
2. Set it as `PRISMOR_AGENT_KEY` in the agent's environment.
3. Run the agent. Its first guarded tool call pulls your org's signed policy and starts reporting, and the agent appears in the console under that workload name. Changes you make in the console (mode, blocked tools) reach it on its next tool call, at most about 30 seconds later.

Without a key the adapter still enforces your local policy but reports nothing. To check the connection, run `prismor doctor` with the same `PRISMOR_AGENT_KEY` set.

## Why this hook point

Agno's real hook point is the `tool_hooks` list on `Agent`/`Team` — distinct
from the singular `pre_hook`/`post_hook`. Each hook is threaded into a
nested execution chain around the tool's entrypoint; Agno introspects the
hook's own signature and injects whichever of `function_name` /
`function_call` / `args` (or `arguments`) it declares. `function_call` is
the callable that continues the chain — not calling it means the real tool
never runs, and any exception raised propagates normally (confirmed against
source: the `try/finally` wrapper around hook calls only isolates
message-list state, it does not swallow exceptions).

## Use

```python
from agno.agent import Agent
from agno.models.openai import OpenAIChat
from prismor.agno import prismor_tool_hook

agent = Agent(
    model=OpenAIChat(id="gpt-4o-mini"),
    tools=[run_shell],
    tool_hooks=[prismor_tool_hook],
)
```

Use `make_tool_hook(subject="user:alice", mode="enforce", ...)` instead of
the bare `prismor_tool_hook` to customize subject/workspace/mode. A denied
call raises `RuntimeError` by default (Agno surfaces this to the model as a
tool error); pass `raise_on_block=True` (via `make_tool_hook`) to raise
`PrismorBlocked` instead for a hard stop. `mode="observe"` is log-only.

## Per-user control

`subject` (a `Subject`, `"user:alice"`-style string, or `None`) scopes
policy, IAM profile selection, and telemetry to the end-user — the same
generic mechanism every adapter uses.

## Verified

Live-tested against a real `Agent(model=OpenAIChat(id="gpt-4o-mini"))` with
a genuine OpenAI API key: a shell tool call matching a destructive-command
policy rule was denied before the tool's Python implementation ever ran; a
benign command executed normally.

## See also

- [Framework adapters overview](frameworks-overview.md)
- [IAM](iam.md) — per-user permission profiles
