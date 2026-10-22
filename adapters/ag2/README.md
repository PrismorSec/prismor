# prismor-ag2

Prismor adapter for **AG2** (`pip install ag2`).
Every tool call is routed through Prismor's shared policy pipeline
(`prismor.runtime.runtime.evaluate_tool_call`) before the tool runs — same
engine, observe/enforce model, and per-user attribution as the other
adapters. Registry entry: `id: ag2`.

## Install

```bash
pip install "prismor[ag2]"   # Prismor runtime + adapter + AG2
```

## Use

```python
from ag2 import Agent
from prismor.ag2 import prismor_middleware

agent = Agent("ops", "You are an ops assistant.", config=config, tools=[run_shell],
              middleware=[prismor_middleware(name="ops-bot", mode="enforce")])
```

On AG2 1.x the middleware's `on_tool_execution` refuses a denied call without running it; on AG2 0.x, `guard_agent(executor)` wraps the executor's `function_map`. Pass `raise_on_block=True` to raise `PrismorBlocked` instead, `mode="observe"` to log only. Allowed calls have their output redacted before the model reads it.

See [docs/frameworks-ag2.md](../../docs/frameworks-ag2.md).
