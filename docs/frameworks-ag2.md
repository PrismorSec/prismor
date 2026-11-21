# AG2 integration

Prismor adapter for [AG2](https://docs.ag2.ai/) (`pip install ag2`), the
community fork of AutoGen. For Microsoft's `autogen-core`, see
[AutoGen Core](frameworks-autogen-core.md). Source lives at
[`adapters/ag2/`](../adapters/ag2/), bundled into the main `prismor` package
(no separate PyPI package).
Registry entry: `id: ag2` in
[`prismor/runtime/integrations/registry.yaml`](../prismor/runtime/integrations/registry.yaml).

## Install

```bash
pip install "prismor[ag2]"
```

## Connect to the console

To see this agent's tool calls in the Prismor console and control it from there:

1. In the console, open **Agents**. Under **SDK & deployed agents**, enter a workload name and click **Mint agent key**. The key is shown once, so put it in your deployment's secret manager.
2. Set it as `PRISMOR_AGENT_KEY` in the agent's environment.
3. Run the agent. Its first guarded tool call pulls your org's signed policy and starts reporting, and the agent appears in the console under that workload name. Changes you make in the console (mode, blocked tools) reach it on its next tool call, at most about 30 seconds later.

Without a key the adapter still enforces your local policy but reports nothing. To check the connection, run `prismor doctor` with the same `PRISMOR_AGENT_KEY` set.

## AG2 1.x (`import ag2`)

AG2 1.x runs every tool call through its middleware chain:
`BaseMiddleware.on_tool_execution(call_next, event, context)` wraps the
execution, and the tool only runs when `call_next` is awaited. Prismor's
middleware checks the call first. On a deny it returns
`ToolResultEvent.from_call(event, denial)`, the same shape AG2's own
`approval_required` middleware uses, so the model gets the denial as the tool
result and the turn carries on. Allowed output is redacted before the model
reads it.

```python
from ag2 import Agent
from ag2.config import OpenAIConfig
from prismor.ag2 import prismor_middleware

agent = Agent(
    "ops", "You are an ops assistant.",
    config=OpenAIConfig(model="gpt-4o-mini"),
    tools=[run_shell, lookup_order],
    middleware=[prismor_middleware(name="support-bot", mode="enforce")],
)
reply = await agent.ask("Look up order 4417")
```

For an agent you already built, `guard_agent(agent, name="support-bot")` adds
the same middleware.

## AG2 0.x (`import autogen`)

0.x executes tools from the executor agent's `function_map`. Guard the
executor after registering the functions:

```python
from autogen import register_function
from prismor.ag2 import guard_agent

register_function(run_shell, caller=assistant, executor=user_proxy,
                  description="Run a shell command")
guard_agent(user_proxy, name="support-bot", mode="enforce")
```

A denied call returns the denial string as the function's result, so the
executor replies with it and the conversation carries on.

## Options

`mode="enforce"` (the default) blocks; `mode="observe"` records findings and
never refuses a call. `raise_on_block=True` raises `PrismorBlocked` instead of
returning the denial. `name=` is the instance label the console shows and
controls on its own.

## Per-user control

```python
from prismor.ag2 import use_subject

with use_subject("user:alice"):       # per request; or prismor_middleware(subject=...)
    await agent.ask(prompt)
```

## Verified

Live-tested on ag2 1.2.1 with `Agent(config=OpenAIConfig(model="gpt-6-luna", reasoning_effort="none"))`, reporting to the console through an agent key: a benign order lookup ran, and a `curl -X POST ... -d @/etc/passwd` tool call was denied before the tool ran. The 0.x `function_map` path is covered by unit tests.

## See also

- [Framework adapters overview](frameworks-overview.md)
- [IAM](iam.md) — per-user permission profiles
