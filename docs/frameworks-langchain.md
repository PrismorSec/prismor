# LangChain / LangGraph integration

Prismor adapter for LangChain and LangGraph. Source lives at
[`adapters/langchain/`](../adapters/langchain/), bundled into the main
`prismor` package (no separate PyPI package).
Registry entry: `id: langchain` in
[`prismor/runtime/integrations/registry.yaml`](../prismor/runtime/integrations/registry.yaml).

## Install

```bash
pip install "prismor[langchain]"
```

## Connect to the console

To see this agent's tool calls in the Prismor console and control it from there:

1. In the console, open **Agents**. Under **SDK & deployed agents**, enter a workload name and click **Mint agent key**. The key is shown once, so put it in your deployment's secret manager.
2. Set it as `PRISMOR_AGENT_KEY` in the agent's environment.
3. Run the agent. Its first guarded tool call pulls your org's signed policy and starts reporting, and the agent appears in the console under that workload name. Changes you make in the console (mode, blocked tools) reach it on its next tool call, at most about 30 seconds later.

Without a key the adapter still enforces your local policy but reports nothing. To check the connection, run `prismor doctor` with the same `PRISMOR_AGENT_KEY` set.

## Guard tools (easy path)

```python
from langchain_core.tools import tool
from prismor.langchain import guard_tools

@tool
def run_shell(command: str) -> str:
    """Execute a shell command."""
    ...

@tool
def read_file(path: str) -> str:
    """Read a file."""
    ...

tools = guard_tools([run_shell, read_file])   # every tool now policy-checked
agent = create_react_agent(llm, tools)
```

`guard_tools` wraps `tool.func` (sync) and `tool.coroutine` (async) in-place and
returns the same list. Your tool schemas are untouched — the LLM sees the same
tool definitions.

## Guard a single tool

```python
from prismor.langchain import prismor_guard_tool

guarded = prismor_guard_tool(run_shell, mode="enforce", subject="user:alice")
```

## Callback handler (alternative)

If you already use LangChain callbacks or need to guard an agent executor without
modifying its tool list, use `PrismorCallbackHandler`:

```python
from prismor.langchain import PrismorCallbackHandler

handler = PrismorCallbackHandler(mode="enforce")
agent_executor.invoke({"input": prompt}, config={"callbacks": [handler]})
```

The handler fires on `on_tool_start` — before the tool executes. It raises
`PrismorBlocked` in enforce mode, which aborts the tool call and surfaces as an
error in the agent's output.

> Note: `guard_tools` (direct wrapping) blocks before the tool body runs and the
> model recovers gracefully. `PrismorCallbackHandler` raises an exception that
> interrupts execution — use it when you can't modify the tool list.

## Per-user control (multi-tenant)

```python
from prismor.langchain import guard_tools, use_subject

tools = guard_tools([run_shell, read_file])   # once, at startup — no bound subject
agent = create_react_agent(llm, tools)

# per-request handler
with use_subject("user:alice"):
    agent.invoke({"messages": [("user", prompt)]})
```

The `use_subject` context manager sets the subject for every tool call that runs
inside the block. Thread-safe and async-safe (contextvar-backed) — concurrent
requests each see their own subject.

Per-user IAM example (`.prismor/iam.yaml`):

```yaml
agents:
  user:bob:
    deny_tools: [Bash]
    deny_network: true
    allowed_paths: ["**"]
```

`user:bob` will have `run_shell` blocked by IAM even if the call would otherwise
be allowed by the org-wide policy. `user:alice` (no profile) gets org defaults.

## LangGraph

Works identically — guard the tools before passing them to the graph:

```python
from langgraph.prebuilt import create_react_agent
from prismor.langchain import guard_tools, use_subject

tools = guard_tools([run_shell, search])
graph = create_react_agent(llm, tools)

with use_subject("user:alice"):
    result = graph.invoke({"messages": [("user", prompt)]})
```

## Event mapping

| Tool call type | Event type | Field | Rules that apply |
|---|---|---|---|
| Default (shell commands, etc.) | `shell` | `command` | `destructive-command`, `secret-exfiltration`, … |
| Override with `event_type="network"` | `network` | `url` | `suspicious-network`, `secret-in-url-params` |
| Override with `event_type="file_write"` | `file_write` | `path` | path-based rules |

Pass `event_type` and `command_builder` to `prismor_guard_tool` for tools whose
risk is a URL or path rather than a shell command.

## Reference

| Symbol | Purpose |
|---|---|
| `guard_tools(tools, **kwargs)` | Guard a list of LangChain tools in one call |
| `prismor_guard_tool(tool, **kwargs)` | Guard a single tool |
| `PrismorCallbackHandler(**kwargs)` | Callback-based guard (for agent executors) |
| `use_subject(value)` | Per-request subject contextmanager |
| `PrismorBlocked` | Raised on enforce-mode block (when `raise_on_block=True`) |

All functions accept: `subject`, `workspace`, `agent`, `mode`, `session_id`,
`event_type`, `raise_on_block`. See [`adapters/langchain/`](../adapters/langchain/)
for full signatures.
