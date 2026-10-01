# Semantic Kernel (Microsoft) integration

Prismor adapter for Semantic Kernel. Source lives at
[`adapters/semantic-kernel/`](../adapters/semantic-kernel/), bundled into
the main `prismor` package (no separate PyPI package).
Registry entry: `id: semantic-kernel` in
[`prismor/runtime/integrations/registry.yaml`](../prismor/runtime/integrations/registry.yaml).

## Install

```bash
pip install "prismor[semantic-kernel]"
```

## Connect to the console

To see this agent's tool calls in the Prismor console and control it from there:

1. In the console, open **Agents**. Under **SDK & deployed agents**, enter a workload name and click **Mint agent key**. The key is shown once, so put it in your deployment's secret manager.
2. Set it as `PRISMOR_AGENT_KEY` in the agent's environment.
3. Run the agent. Its first guarded tool call pulls your org's signed policy and starts reporting, and the agent appears in the console under that workload name. Changes you make in the console (mode, blocked tools) reach it on its next tool call, at most about 30 seconds later.

Without a key the adapter still enforces your local policy but reports nothing. To check the connection, run `prismor doctor` with the same `PRISMOR_AGENT_KEY` set.

## Why this hook point

`kernel.add_filter(FilterTypes.AUTO_FUNCTION_INVOCATION, filter_fn)`
registers a filter of the form `filter_fn(context, next)`. Every registered
filter composes into a single middleware stack; the innermost link calls
`context.function.invoke(...)`. Simply not calling `await next(context)`
means that inner call — and therefore the real tool — never runs. This is
the cleanest gate-then-continue semantics of any framework Prismor
integrates with. (Python confirmed; the .NET `IAutoFunctionInvocationFilter`
equivalent was not independently re-verified.)

## Use

```python
from semantic_kernel import Kernel
from semantic_kernel.filters import FilterTypes
from prismor.semantic_kernel import make_filter

kernel = Kernel()
kernel.add_service(...)
kernel.add_plugin(MyPlugin(), plugin_name="tools")
kernel.add_filter(
    FilterTypes.AUTO_FUNCTION_INVOCATION,
    make_filter(subject="user:alice", mode="enforce"),
)
```

A denied call skips `next(context)` and sets a synthetic
`context.function_result` so the model still sees a coherent (denied) tool
response. Pass `raise_on_block=True` to raise `PrismorBlocked` instead for
a hard stop. `mode="observe"` is log-only.

## Per-user control

`subject` (a `Subject`, `"user:alice"`-style string, or `None`) scopes
policy, IAM profile selection, and telemetry to the end-user — the same
generic mechanism every adapter uses.

## Verified

Live-tested against a real `Kernel` with an `OpenAIChatCompletion` service
(`gpt-4o-mini`) and a genuine OpenAI API key: a plugin function call matching
a destructive-command policy rule was denied before the tool's Python
implementation ever ran; a benign command executed normally.

## See also

- [Framework adapters overview](frameworks-overview.md)
- [IAM](iam.md) — per-user permission profiles
