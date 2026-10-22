# prismor-smolagents

Prismor adapter for **Hugging Face smolagents** (`pip install smolagents`).
Every tool call is routed through Prismor's shared policy pipeline
(`prismor.runtime.runtime.evaluate_tool_call`) before the tool runs — same
engine, observe/enforce model, and per-user attribution as the other
adapters. Registry entry: `id: smolagents`.

## Install

```bash
pip install "prismor[smolagents]"   # Prismor runtime + adapter + Hugging Face smolagents
```

## Use

```python
from smolagents import ToolCallingAgent
from prismor.smolagents import guard_agent

agent = ToolCallingAgent(tools=[run_shell], model=model)
guard_agent(agent, name="ops-bot", mode="enforce")
```

`guard_agent` wraps each tool's `forward`, which both `ToolCallingAgent` and a `CodeAgent`'s local executor run. A denied call returns `⛔ Prismor blocked this tool call: ...` as the tool output. Pass `raise_on_block=True` to raise `PrismorBlocked` instead, `mode="observe"` to log only. Allowed calls have their output redacted before the model reads it.

See [docs/frameworks-smolagents.md](../../docs/frameworks-smolagents.md).
