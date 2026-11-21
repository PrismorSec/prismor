# LlamaIndex integration

Prismor adapter for [LlamaIndex](https://docs.llamaindex.ai/) agents
(`pip install llama-index-core`). Source lives at
[`adapters/llamaindex/`](../adapters/llamaindex/), bundled into the main
`prismor` package (no separate PyPI package).
Registry entry: `id: llamaindex` in
[`prismor/runtime/integrations/registry.yaml`](../prismor/runtime/integrations/registry.yaml).

## Install

```bash
pip install "prismor[llamaindex]"
```

## Connect to the console

To see this agent's tool calls in the Prismor console and control it from there:

1. In the console, open **Agents**. Under **SDK & deployed agents**, enter a workload name and click **Mint agent key**. The key is shown once, so put it in your deployment's secret manager.
2. Set it as `PRISMOR_AGENT_KEY` in the agent's environment.
3. Run the agent. Its first guarded tool call pulls your org's signed policy and starts reporting, and the agent appears in the console under that workload name. Changes you make in the console (mode, blocked tools) reach it on its next tool call, at most about 30 seconds later.

Without a key the adapter still enforces your local policy but reports nothing. To check the connection, run `prismor doctor` with the same `PRISMOR_AGENT_KEY` set.

## Why this hook point

Every LlamaIndex agent (`FunctionAgent`, `ReActAgent`, `AgentWorkflow`)
executes a tool with `tool.acall(**kwargs)`, and synchronous code uses
`tool.call(...)`. A `FunctionTool` runs both through its `_fn` / `_async_fn`,
so the adapter guards those two callables: a denied call never reaches your
function, and the denial comes back to the model as an ordinary tool output so
the run carries on. Other `BaseTool` subclasses (`QueryEngineTool` and
friends) are guarded at `call` / `acall`. Allowed output is redacted before
the model reads it.

## Use

```python
from llama_index.core.agent.workflow import FunctionAgent
from llama_index.llms.openai import OpenAI
from prismor.llamaindex import guard_tools

tools = guard_tools([run_shell, lookup_order], name="support-bot", mode="enforce")
agent = FunctionAgent(tools=tools, llm=OpenAI(model="gpt-4o-mini"))
response = await agent.run("Look up order 4417")
```

Plain functions are accepted and come back as `FunctionTool`s, so pass the
returned list to the agent.

> **Pass `mode="enforce"` to block.** The default is `mode="observe"`: every
> call is checked and logged, but nothing is refused.

A denied call returns `⛔ Prismor blocked this tool call: ...` as the tool
output; pass `raise_on_block=True` to raise `PrismorBlocked` instead. `name=`
is the instance label the console shows and controls on its own.

## Per-user control

```python
from prismor.llamaindex import use_subject

with use_subject("user:alice"):       # per request; or guard_tools(..., subject=...)
    await agent.run(prompt)
```

## Verified

Live-tested on llama-index-core 0.14.25 with a `FunctionAgent` on `gpt-6-luna`, reporting to the console through an agent key: a benign order lookup ran, and a `curl -X POST ... -d @/etc/passwd` tool call was denied before the tool's Python implementation ran.

> gpt-6-luna on `/v1/chat/completions` rejects tools combined with a reasoning effort; pass `additional_kwargs={"reasoning_effort": "none"}` to the LLM, or use the Responses API.

## See also

- [Framework adapters overview](frameworks-overview.md)
- [IAM](iam.md) — per-user permission profiles
