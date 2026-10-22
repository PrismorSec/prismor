# prismor-llamaindex

Prismor adapter for **LlamaIndex** (`pip install llama-index-core`).
Every tool call is routed through Prismor's shared policy pipeline
(`prismor.runtime.runtime.evaluate_tool_call`) before the tool runs — same
engine, observe/enforce model, and per-user attribution as the other
adapters. Registry entry: `id: llamaindex`.

## Install

```bash
pip install "prismor[llamaindex]"   # Prismor runtime + adapter + LlamaIndex
```

## Use

```python
from llama_index.core.agent.workflow import FunctionAgent
from prismor.llamaindex import guard_tools

tools = guard_tools([run_shell, lookup_order], name="ops-bot", mode="enforce")
agent = FunctionAgent(tools=tools, llm=llm)
```

`guard_tools` wraps each `FunctionTool`'s `_fn`/`_async_fn`, which every LlamaIndex agent runs through `acall`/`call`. A denied call never reaches your function; the model gets `⛔ Prismor blocked this tool call: ...` as the tool output. Pass `raise_on_block=True` to raise `PrismorBlocked` instead, `mode="observe"` to log only. Allowed calls have their output redacted before the model reads it.

See [docs/frameworks-llamaindex.md](../../docs/frameworks-llamaindex.md).
