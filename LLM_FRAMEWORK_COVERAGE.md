# LLM Framework & Agent Library Coverage

There are two independent kinds of coverage for LLM application frameworks and libraries, and it's easy to conflate them:

1. **Runtime hook adapters** (`adapters/`, documented in [docs/frameworks-overview.md](docs/frameworks-overview.md)) — Prismor wraps the framework's own tool-execution surface *inside your running application* (e.g. `tool.func` in LangChain, `InterventionHandler.on_send` in AutoGen Core) so a call can actually be evaluated and blocked before it runs. Same enforcement pipeline as the coding-agent hooks in [AGENT_INTEGRATIONS.md](AGENT_INTEGRATIONS.md), different attach point.
2. **Supply-chain coverage** (`supplychain/`) — NVD advisory tracking and typosquat protection for the package itself, evaluated at `pip install` / `npm install` time. This exists regardless of whether a runtime adapter exists, and applies even to frameworks with no programmable hook surface at all.

This file tracks coverage against the 25 frameworks/platforms Langfuse lists as integrations on their docs site, split across both layers.

_Last updated: 2026-07-24._

---

## Runtime adapter coverage

Per [docs/frameworks-overview.md](docs/frameworks-overview.md) (merged 2026-07-24, PR #216 on top of #212/#213/#215), Prismor ships 14 framework adapters total. Of the 25 in scope here, **5 have a full runtime adapter**:

| Framework | Adapter | Hook point | Install |
|---|---|---|---|
| LangChain / LangGraph | `adapters/langchain` on `prismor.sdk` (+ JS via `prismor-warden` npm) | `tool.func` / `tool.invoke` before execution | `pip install "prismor[langchain]"` / `npm install prismor-warden` |
| CrewAI | `adapters/crewai` on `prismor.sdk` | `tool.func` → `tool._run` → `tool.run` before execution | `pip install "prismor[crewai]"` |
| AutoGen Core (Microsoft) | `adapters/autogen-core` | `InterventionHandler.on_send` before a `FunctionCall` reaches a `ToolAgent` | `pip install "prismor[autogen-core]"` |
| Vercel AI SDK | `prismor-warden` (npm, on `prismor-sdk`) | `tool.execute` before the tool body runs | `npm install prismor-warden` |
| Mastra | `adapters/mastra` (`prismor-mastra` npm, on `prismor-sdk`) | `tool.execute` before the tool body runs | `npm install prismor-mastra` |

Prismor also has adapters for 9 frameworks outside the original 25 (OpenAI Agents SDK, browser-use, Pydantic AI, Agno, Semantic Kernel, Google ADK, BeeAI, Claude Code Agent SDK) — not tracked in this file since they weren't in scope, see the overview doc.

**Note on naming:** `AutoGen Core` (`autogen-core` pip package, the adapter target) and classic `AutoGen`/`pyautogen` (the older Microsoft package, still widely installed) are different packages. The adapter covers the former; supply-chain typosquat protection below covers the latter — both matter.

---

## Supply-chain-only coverage (the other 20)

For everything without a runtime adapter, coverage is two mechanisms in `supplychain/`:

- **NVD advisory tracking** (`pipeline/fetch_nvd_intel.py` `KEYWORDS`) — pulls known CVEs mentioning the name into `advisories/immunity-feed.json`; `prismor supplychain <pm> install <pkg>` scores against that feed.
- **Typosquat protection** (`supplychain/scoring/typosquat.py` `POPULAR_PACKAGES`) — flags a Levenshtein-distance-1/2 near-miss of a real, popular package name.

| Framework | NVD keyword | Typosquat (pip/pypi) | Typosquat (npm) | Advisory feed entries today |
|---|---|---|---|---|
| LlamaIndex | ✅ | — | — | ✅ |
| AutoGen (classic, `pyautogen`) | ✅ | ✅ `pyautogen` | — | none yet |
| smolagents | ✅ | ✅ `smolagents` | — | ✅ (sandbox escape) |
| Langfuse | ✅ | ✅ `langfuse` | ✅ `langfuse` | none yet |
| Haystack | ✅ | ✅ `haystack-ai` | — | none yet |
| LiteLLM | — (advisory feed only) | — | — | ✅ (SSRF) |
| Instructor | ✅ | ✅ `instructor` | — | none yet |
| DSPy | ✅ | ✅ `dspy` | — | none yet |
| Mirascope | ✅ | ✅ `mirascope` | — | none yet |
| Ollama | ✅ | ✅ `ollama` | — | none yet |
| Amazon Bedrock | ✅ | — (SDK surface, not a standalone package) | — | none yet |
| Flowise | ✅ | — | — | ✅ (cross-tenant secret exposure) |
| Langflow | ✅ | ✅ `langflow` | — | none yet |
| Dify | ✅ | — (typically self-hosted, not pip/npm installed) | — | ✅ (SSRF, RCE) |
| OpenWebUI | ✅ | — (typically self-hosted) | — | ✅ (SSRF) |
| Promptfoo | ✅ | ✅ `promptfoo` | — | none yet |
| LobeChat | ✅ | — (self-hosted app) | — | none yet |
| Vapi | ✅ | — (hosted platform, no installable package) | — | none yet |
| Inferable | ✅ | — | — | none yet |
| Gradio | ✅ | ✅ `gradio` | — | none yet |
| Goose | ✅ | — (ships as a binary, not pip/npm) | — | none yet |

CrewAI, LangChain, and Mastra also carry supply-chain coverage on top of their adapters (`crewai`, `langchain`, and note below on Mastra) — the two layers are independent and additive, not redundant.

**Deliberately not added:** `ai` (Vercel AI SDK's npm package name) and `@mastra/core` are **not** typosquat-protected. Both normalize to a 2–4 character comparison string (`ai`, `core`) after scope-stripping, and the distance-1 threshold used for short names would flag large numbers of unrelated legitimate packages. That trades a narrow, unproven threat for a broad false-positive source — revisit with a name-specific carve-out if a real incident targets either package.

---

## What changed in this pass

Before this pass, `pipeline/fetch_nvd_intel.py` tracked only `LangChain`, `LlamaIndex`, `OpenAI`, `Anthropic`, `CrewAI`, `AutoGPT`, `Vanna`; `typosquat.py` protected only `langchain` (pip/npm), `openai`, `anthropic` (pip). This pass:

- Added NVD keyword tracking for all 20 frameworks in the supply-chain-only table above that had none.
- Added typosquat protection for the subset with a real, installable pip package name and low false-positive risk (12 of the 20 — see table).
- Did **not** touch `adapters/` or `docs/frameworks-overview.md` — the 5 frameworks with real hook adapters already had that coverage before this pass; this pass only added the supply-chain layer where it was missing.

---

## Sources

- [docs/frameworks-overview.md](docs/frameworks-overview.md) — authoritative for runtime adapter coverage.
- `pipeline/fetch_nvd_intel.py` — NVD keyword list.
- `advisories/immunity-feed.json` — resulting CVE entries.
- `supplychain/scoring/typosquat.py` — `POPULAR_PACKAGES`.
- `supplychain/scoring/engine.py` — risk-scoring rules referencing specific incidents (e.g. LiteLLM backdoor comment).
