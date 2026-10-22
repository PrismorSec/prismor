# LLM Framework & Agent Library Coverage

There are two independent kinds of coverage for LLM application frameworks and libraries, and it's easy to conflate them:

1. **Runtime adapters** (`adapters/`, documented in [docs/frameworks-overview.md](docs/frameworks-overview.md)): Prismor wraps the framework's own tool-execution point *inside your running application* (for example `tool.func` in LangChain, `InterventionHandler.on_send` in AutoGen Core), so a call is evaluated and can be blocked before it runs. It is the same policy pipeline as the coding-agent hooks in [AGENT_INTEGRATIONS.md](AGENT_INTEGRATIONS.md), attached at a different point.
2. **Supply-chain coverage** (`supplychain/`): checks on the package itself when it is installed through `prismor supplychain <pm> install`. This applies whether or not a runtime adapter exists, including to frameworks with no programmable hook surface at all.

---

## Runtime adapters

Prismor ships 13 framework adapters. The Python ones are inside the `prismor` package (each extra only pulls in the framework; `prismor[frameworks]` installs all of them). The TypeScript ones are separate npm packages.

| Framework | Language | Install | Guard |
|---|---|---|---|
| OpenAI Agents SDK | Python | `pip install "prismor[openai-agents]"` | `guard_agent(agent)` |
| LangChain / LangGraph | Python | `pip install "prismor[langchain]"` | `guard_tools([...])` |
| CrewAI | Python | `pip install "prismor[crewai]"` | `guard_tools([...])` |
| browser-use | Python | `pip install "prismor[browser-use]"` | `guard_controller(controller)` |
| Pydantic AI | Python | `pip install "prismor[pydantic-ai]"` | `guard_toolsets([...])` |
| AutoGen Core (Microsoft) | Python | `pip install "prismor[autogen-core]"` | `PrismorInterventionHandler(...)` |
| Agno | Python | `pip install "prismor[agno]"` | `tool_hooks=[prismor_tool_hook]` |
| Semantic Kernel (Microsoft) | Python | `pip install "prismor[semantic-kernel]"` | `add_filter(..., make_filter(...))` |
| Google ADK | Python | `pip install "prismor[google-adk]"` | `before_tool_callback=make_before_tool_callback(...)` |
| BeeAI Framework | Python | `pip install "prismor[beeai]"` | `guard_tool(tool)` / `guard_tools([...])` |
| Claude Agent SDK | Python | `pip install "prismor[claude-agent-sdk]"` | `hooks={"PreToolUse": [prismor_hook_matcher(...)]}` |
| Vercel AI SDK, LangChain JS / LangGraph JS | TypeScript | `npm install @prismor/vercel-ai` | `prismorTools(tools)` / `prismorLangChainTools([...])` |
| Mastra | TypeScript | `npm install @prismor/mastra` | `prismorTool(name, tool)` |

Anything else can call `prismor eval-server` over HTTP (`POST /v1/evaluate`); see [docs/decision-contract.md](docs/decision-contract.md). Default modes differ between adapters, so pass the mode explicitly; each framework's page has the details.

**Note on naming:** `AutoGen Core` (the `autogen-core` package, which the adapter targets) and classic `AutoGen` / `pyautogen` (the older Microsoft package, still widely installed) are different packages. The adapter covers the former; supply-chain typosquat checks cover the latter.

---

## Supply-chain coverage for frameworks without an adapter

For frameworks with no runtime adapter, coverage comes from two mechanisms in `supplychain/` and `pipeline/`:

- **Vulnerability lookups at install time.** `prismor supplychain <pm> install <pkg>` checks the version being installed against OSV and the signed IOC feed. `pipeline/fetch_nvd_intel.py` also tracks NVD CVEs for the names in its `KEYWORDS` list.
- **Typosquat checks** (`supplychain/scoring/typosquat.py`): an install name that is a near-miss of a popular package is flagged.

| Framework | NVD keyword | Typosquat target (PyPI) |
|---|---|---|
| LlamaIndex | ✅ | ✅ `llama-index` |
| AutoGen (classic) | ✅ | ✅ `pyautogen` |
| smolagents | ✅ | ✅ `smolagents` |
| Haystack | ✅ | ✅ `haystack-ai` |
| LiteLLM | — | ✅ `litellm` |
| Instructor | ✅ | ✅ `instructor` |
| DSPy | ✅ | ✅ `dspy` |
| Mirascope | ✅ | ✅ `mirascope` |
| Ollama | ✅ | ✅ `ollama` |
| Amazon Bedrock | ✅ | ✅ `boto3` |
| Langflow | ✅ | ✅ `langflow` |
| Promptfoo | ✅ | ✅ `promptfoo` |
| Gradio | ✅ | ✅ `gradio` |
| Flowise, Dify, OpenWebUI, LobeChat | ✅ | — (usually self-hosted, not installed with pip/npm) |
| Vapi, Inferable | ✅ | — (hosted platforms) |
| Goose | ✅ | — (ships as a binary) |

CrewAI, LangChain and Mastra have supply-chain coverage on top of their adapters; the two layers are independent.

**Deliberately not added:** `ai` (the Vercel AI SDK's npm package name) and `@mastra/core` are not typosquat targets. Both reduce to a 2–4 character comparison string (`ai`, `core`) after the scope is stripped, and checking names that short would flag many unrelated legitimate packages.

---

## Sources

- [docs/frameworks-overview.md](docs/frameworks-overview.md): authoritative for runtime adapter coverage.
- `pipeline/fetch_nvd_intel.py`: the NVD keyword list.
- `supplychain/scoring/typosquat.py`: popular-package lists per ecosystem.
- `supplychain/scoring/engine.py`: risk-scoring rules.
