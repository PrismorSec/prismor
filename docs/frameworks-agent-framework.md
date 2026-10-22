# Microsoft Agent Framework integration

Prismor adapter for [Microsoft Agent Framework](https://learn.microsoft.com/en-us/agent-framework/)
(`pip install agent-framework`). Source lives at
[`adapters/agent-framework/`](../adapters/agent-framework/), bundled into the
main `prismor` package (no separate PyPI package).
Registry entry: `id: agent-framework` in
[`prismor/runtime/integrations/registry.yaml`](../prismor/runtime/integrations/registry.yaml).

## Install

```bash
pip install "prismor[agent-framework]"
```

## Connect to the console

To see this agent's tool calls in the Prismor console and control it from there:

1. In the console, open **Agents**. Under **SDK & deployed agents**, enter a workload name and click **Mint agent key**. The key is shown once, so put it in your deployment's secret manager.
2. Set it as `PRISMOR_AGENT_KEY` in the agent's environment.
3. Run the agent. Its first guarded tool call pulls your org's signed policy and starts reporting, and the agent appears in the console under that workload name. Changes you make in the console (mode, blocked tools) reach it on its next tool call, at most about 30 seconds later.

Without a key the adapter still enforces your local policy but reports nothing. To check the connection, run `prismor doctor` with the same `PRISMOR_AGENT_KEY` set.

## Why this hook point

Agent Framework runs every tool call through its *function middleware*
pipeline: `FunctionMiddleware.process(context, call_next)` wraps the
invocation, and the innermost link of the chain runs the function. Prismor's
middleware checks the call first and, on a deny, sets `context.result` to the
denial and returns without awaiting `call_next()` — the real tool never runs,
the model sees a coherent tool response, and the run carries on. After an
allowed call, the tool's output is redacted before the model reads it.

## Use

```python
from agent_framework import Agent
from agent_framework.openai import OpenAIChatClient
from prismor.agent_framework import PrismorMiddleware

agent = Agent(
    client=OpenAIChatClient(model="gpt-4o-mini"),
    name="ops",
    tools=[run_shell, lookup_order],
    middleware=[PrismorMiddleware(name="ops-bot", mode="enforce")],
)
result = await agent.run("Look up order 4417")
```

> **Pass `mode="enforce"` to block** (the default). `mode="observe"` records
> findings and never refuses a call.

A denied call returns `⛔ Prismor blocked this tool call: ...` as the tool
result; pass `raise_on_block=True` to raise `PrismorBlocked` instead.
`name=` is the instance label the console shows and controls on its own.

## Per-user control

```python
from prismor.agent_framework import use_subject

with use_subject("user:alice"):       # per request; or PrismorMiddleware(subject=...)
    await agent.run(prompt)
```

`subject` scopes policy, IAM profile selection, and telemetry to the end user —
the same mechanism every adapter uses.

## Verified

Live-tested on agent-framework 1.22.0 with `Agent(client=OpenAIChatClient(model="gpt-6-luna"))`
and a real OpenAI key, reporting to the console with an agent key: a
`curl -X POST ... -d @/etc/passwd` call was denied before the tool's Python
implementation ran; a benign lookup executed normally.

## See also

- [Framework adapters overview](frameworks-overview.md)
- [IAM](iam.md) — per-user permission profiles
