# Prismor Immunity — TODO

Items are ordered by priority. Each has a registry anchor where relevant.

---

## High priority

### ~~MCP proxy (`immunity mcp-proxy`)~~ — DONE as `prismor mcp-gateway`
Registry: `id: mcp-proxy` (flip to `status: available` in prismor-web is a follow-up)

Shipped in `prismor/runtime/mcp_gateway.py` + `tests/test_mcp_gateway.py`, with docs in
`docs/mcp-gateway.md`. Went beyond the sketch: full **aggregator** (one gateway fronts
all of the user's MCP servers from an `mcpServers`-shaped config, tools namespaced
`<server>__<tool>`), single-upstream shim mode (`--upstream`), stdio + streamable-HTTP/SSE
upstreams, and tool **results** are injection-scanned before the model sees them.
Deviation from the sketch: denials return an MCP tool result with `isError: true`
(the model can read the reason and adapt) — JSON-RPC `-32600` is reserved for protocol
failures. Events carry `tool_name = mcp__<server>__<tool>` with the *real* downstream
server name, so trifecta globs / org tool denies / control-plane matchers apply unchanged.

---

## Medium priority

### ~~Dashboard subject filter~~ — DONE
Data is already captured and tagged per-user in findings/events (field: `subject`). Exposed via:
- `?subject=user:alice` query param on `/api/findings` / `/api/events`
- A "User" column in the findings table
- A user dropdown filter in `dashboard.html`

### ~~Docs: framework docs~~ — DONE
All framework docs written: frameworks-openai-agents.md, frameworks-langchain.md, frameworks-crewai.md, frameworks-browser-use.md, frameworks-overview.md.

### Coding-agent adapters: Gemini CLI, Kiro, OpenCode
Registry entries exist (`status: roadmap`), hook surfaces documented. Need normalizers + `_merge_*`/`_normalize_*` functions in `prismor/runtime/hooks.py`, entries in `_SUPPORTED_AGENTS`. Gemini and Kiro use `exit-2` (same convention as Claude/Cursor); OpenCode uses `throw`.

---

## Low priority / nice-to-have

### `verify_registry.sh` in CI
Add `bash scripts/verify_registry.sh` to the CI workflow (`.github/workflows/`) alongside the existing test step. Catches registry drift and matrix out-of-sync.

### Per-user telemetry SIEM field
`prismor/runtime/enterprise/telemetry.py` `build_record()` already has `"subject"` field added. Verify that SIEM sinks (Splunk, Datadog, generic HTTP) forward it correctly, and document the field in the sink schema.

### `guard_agent` for LangChain/LangGraph
LangChain equivalent of OpenAI's `guard_agent(agent)` — accept a `RunnableSequence` or `AgentExecutor`, extract the bound tools, call `guard_tools`, return the same object. Currently callers must extract tools manually.

### Sweep-only agents: Aider, Trae, Kilocode
Registry entries exist (`status: sweep-only`). These have no programmable pre-tool hook; the only coverage is rules injection into their config files. Consider a `immunity sweep-inject <agent>` subcommand that writes Prismor guardrail rules into `.aider.conf.yml` / `.trae/rules/` / `.kilocode/rules/`.
