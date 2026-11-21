# Hugging Face smolagents integration

Prismor adapter for [smolagents](https://huggingface.co/docs/smolagents)
(`pip install smolagents`). Source lives at
[`adapters/smolagents/`](../adapters/smolagents/), bundled into the main
`prismor` package (no separate PyPI package).
Registry entry: `id: smolagents` in
[`prismor/runtime/integrations/registry.yaml`](../prismor/runtime/integrations/registry.yaml).

## Install

```bash
pip install "prismor[smolagents]"
```

## Connect to the console

To see this agent's tool calls in the Prismor console and control it from there:

1. In the console, open **Agents**. Under **SDK & deployed agents**, enter a workload name and click **Mint agent key**. The key is shown once, so put it in your deployment's secret manager.
2. Set it as `PRISMOR_AGENT_KEY` in the agent's environment.
3. Run the agent. Its first guarded tool call pulls your org's signed policy and starts reporting, and the agent appears in the console under that workload name. Changes you make in the console (mode, blocked tools) reach it on its next tool call, at most about 30 seconds later.

Without a key the adapter still enforces your local policy but reports nothing. To check the connection, run `prismor doctor` with the same `PRISMOR_AGENT_KEY` set.

## Why this hook point

Every smolagents tool call ends in `Tool.__call__`, which runs
`self.forward(...)`. A `ToolCallingAgent` calls the tool object directly, and
a `CodeAgent`'s local executor hands the same tool objects to the Python the
model writes, so a tool call inside generated code goes through `forward` too.
The adapter wraps `forward` on each tool instance, which covers both agent
types. A denied call returns the denial as the tool's output and never reaches
your code. `final_answer` is not screened: its argument is the answer, not an
action.

## What this does not cover

- **CodeAgent's own Python.** Code the model writes that does not call a tool
  (`open(...)`, or `os.system` if you allowed the import) is not a tool call.
  Keep `additional_authorized_imports` tight, and run untrusted code in a
  sandboxed executor.
- **Remote executors** (E2B, Docker, Modal) serialize tools into the sandbox,
  so calls made there do not pass through the guarded objects in your process.

## Use

```python
from smolagents import ToolCallingAgent, OpenAIServerModel
from prismor.smolagents import guard_agent

agent = ToolCallingAgent(tools=[run_shell, lookup_order],
                         model=OpenAIServerModel(model_id="gpt-4o-mini"))
guard_agent(agent, name="support-bot", mode="enforce")   # after construction
agent.run("Look up order 4417")
```

`guard_tools([...])` guards a tool list before you build the agent instead.

> **Pass `mode="enforce"` to block.** The default is `mode="observe"`: every
> call is checked and logged, but nothing is refused.

A denied call returns `⛔ Prismor blocked this tool call: ...` as the tool
output; pass `raise_on_block=True` to raise `PrismorBlocked` instead. Managed
(sub)agents are not tools: call `guard_agent` on each of them.

## Per-user control

```python
from prismor.smolagents import use_subject

with use_subject("user:alice"):       # per request; or guard_agent(..., subject=...)
    agent.run(prompt)
```

## Verified

Live-tested on smolagents 1.26.0 with a `ToolCallingAgent` on `gpt-6-luna`, reporting to the console through an agent key: a benign order lookup ran, and a `curl -X POST ... -d @/etc/passwd` tool call was denied before the tool ran. With a `CodeAgent`, the same call made from the model's generated Python was denied too.

> smolagents 1.26 does not know the gpt-6 models yet: it sends `stop` and the default reasoning effort, which the API rejects with tools. Subclass `OpenAIServerModel` with `supports_stop_parameter` returning `False`, and pass `reasoning_effort="none"`.

## See also

- [Framework adapters overview](frameworks-overview.md)
- [IAM](iam.md) — per-user permission profiles
