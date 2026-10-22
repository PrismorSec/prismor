# prismor-agent-framework

Prismor adapter for **Microsoft Agent Framework** (`pip install agent-framework`).
Every tool call is routed through Prismor's shared policy pipeline
(`prismor.runtime.runtime.evaluate_tool_call`) before the tool runs — same
engine, observe/enforce model, and per-user attribution as the other
adapters. Registry entry: `id: agent-framework`.

## Install

```bash
pip install "prismor[agent-framework]"   # Prismor runtime + adapter + agent-framework
```

## Use

```python
from agent_framework import Agent
from agent_framework.openai import OpenAIChatClient
from prismor.agent_framework import PrismorMiddleware

agent = Agent(
    client=OpenAIChatClient(model="gpt-4o-mini"),
    name="ops",
    tools=[run_shell],
    middleware=[PrismorMiddleware(name="ops-bot", mode="enforce")],
)
```

`PrismorMiddleware` is a `FunctionMiddleware`. A denied call never reaches
`call_next()`, so the tool does not run; the model gets
`⛔ Prismor blocked this tool call: ...` as the result. Pass
`raise_on_block=True` to raise `PrismorBlocked` instead, `mode="observe"` to
log only. Allowed calls have their output redacted before the model reads it.

See [docs/frameworks-agent-framework.md](../../docs/frameworks-agent-framework.md).
