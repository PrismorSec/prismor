# AI Coding Agent Integrations

How Prismor integrates with each major AI coding agent — what ships today, what's planned, and what mechanism each agent exposes for runtime security monitoring.

_Last updated: 2026-07-30._

---

## Status at a glance

The coverage matrix below is generated from the integration registry
(`prismor/runtime/integrations/registry.yaml`) by `scripts/gen_integration_matrix.py`.
Per-agent capability details (sweep scan, skill scan, cloaking) live in the
sections further down.

<!-- BEGIN GENERATED: coverage-matrix (scripts/gen_integration_matrix.py) -->

_Generated from `prismor/runtime/integrations/registry.yaml` — do not edit by hand._

**Coding agents**

| Agent | Kind | Surface | Status | Blocking |
|---|---|---|---|---|
| Claude Code | coding-agent | hook-config | ✅ | `exit-2` |
| Cursor | coding-agent | hook-config | ✅ | `json-permission` |
| Windsurf (Codeium Cascade) | coding-agent | hook-config | ✅ | `json-permission` |
| OpenClaw | coding-agent | hook-config | ✅ | `throw` |
| Hermes (NousResearch gateway) | coding-agent | hook-config | ✅ | `throw` |
| Codex (OpenAI) | coding-agent | hook-config | ✅ | `exit-2` |
| GitHub Copilot CLI | coding-agent | hook-config | ✅ | `json-permission` |
| Grok Build (xAI) | coding-agent | hook-config | ✅ | `exit-2` |
| Kiro CLI (AWS) | coding-agent | hook-config | ✅ | `exit-2` |
| Crush (Charmbracelet) | coding-agent | hook-config | ✅ | `exit-2` |
| OpenHands | coding-agent | hook-config | ✅ | `exit-2` |
| Qwen Code (Alibaba) | coding-agent | hook-config | ✅ | `json-permission` |
| Continue CLI | coding-agent | hook-config | ✅ | `exit-2` |
| Goose (Agentic AI Foundation) | coding-agent | hook-config | ✅ | `exit-2` |
| Gemini CLI (Google) | coding-agent | hook-config | 🟡 | `exit-2` |
| OpenCode | coding-agent | sdk | ✅ | `throw` |
| Factory Droid | coding-agent | hook-config | 🟡 | `json-permission` |
| Pi Coding Agent | coding-agent | hook-config | 🟡 | `exit-2` |
| Amazon Q Developer CLI (AWS) | coding-agent | hook-config | 🟡 | `exit-2` |
| Amp (Sourcegraph spinoff) | coding-agent | sdk | 🟡 | `throw` |
| Auggie CLI (Augment Code) | coding-agent | hook-config | 🟡 | `exit-2` |
| Kimi Code (Moonshot AI) | coding-agent | hook-config | 🟡 | `exit-2` |
| Devin CLI (Cognition AI) | coding-agent | hook-config | 🟡 | `exit-2` |
| Google Antigravity | coding-agent | rules-only | — | — |
| Aider | coding-agent | rules-only | — | — |
| Trae / Trae CN (ByteDance) | coding-agent | rules-only | — | — |
| Warp (Agent Mode) | coding-agent | rules-only | — | — |
| Kilocode | coding-agent | rules-only | — | — |

**Production frameworks**

| Framework | Kind | Surface | Status | Blocking |
|---|---|---|---|---|
| OpenAI Agents SDK | framework | sdk | ✅ | `throw` |
| CrewAI | framework | sdk | ✅ | `throw` |
| LangChain / LangGraph | framework | sdk | ✅ | `throw` |
| browser-use | framework | sdk | ✅ | `throw` |
| Pydantic AI | framework | sdk | ✅ | `throw` |
| AutoGen (Microsoft) — Core runtime | framework | sdk | ✅ | `throw` |
| Agno | framework | sdk | ✅ | `throw` |
| Semantic Kernel (Microsoft) | framework | sdk | ✅ | `throw` |
| Google Agent Development Kit (ADK) | framework | sdk | ✅ | `throw` |
| Mastra (TypeScript) | framework | sdk | ✅ | `throw` |
| BeeAI Framework (IBM Research / Linux Foundation) | framework | sdk | ✅ | `throw` |
| Claude Code Agent SDK | framework | sdk | ✅ | `json-permission` |
| Vercel AI SDK | framework | http | ✅ | `throw` |
| HTTP Eval-Server (any language) | framework | http | ✅ | `client-side` |
| MCP Gateway (any MCP-speaking agent) | framework | mcp | ✅ | `proxy-deny` |
| Claude Inference Hooks (claude.ai · Claude Code · Cowork) | framework | http | ✅ | `proxy-deny` |

**Multiplexers**

| Tool | Kind | Surface | Status | Blocking |
|---|---|---|---|---|
| Herdr | multiplexer | pass-through | — | — |

Legend: ✅ shipped · 🟡 roadmap · — sweep-only / not applicable. Surfaces: `hook-config` (config-file hooks) · `sdk` (in-process adapter) · `mcp` (proxy) · `http` (eval-server sidecar) · `rules-only` (static guardrails) · `pass-through` (spawns other agents; no interception surface of its own).

<!-- END GENERATED: coverage-matrix -->

\* Codex requires `codex-cli` ≥ `0.141.0-alpha.1`. Earlier versions (including the `0.140.0` stable release) have an upstream bug where `codex exec` never dispatches any hook at all — see the Codex section below.

---

## Currently supported

### Claude Code (Anthropic)

- **Config:** `.claude/settings.json` (project) or `~/.claude/settings.json` (user).
- **Events hooked:** `UserPromptSubmit`, `PreToolUse`, `PostToolUse` with matcher `Bash|Read|Edit|MultiEdit|Write|WebFetch|WebSearch`.
- **Blocking:** exit 2 from hook → block; stderr → rejection reason.
- **Sweep target:** `~/.claude/`.
- **Cloaking:** `prismor/runtime/cloaking/` installs `PreToolUse:Bash` + `PostToolUse:mcp__.*` + `UserPromptSubmit` hooks for `@@SECRET:<name>@@` substitution and scrub-on-output.
- **Code:** `prismor/runtime/hooks.py` `_merge_claude()`, `_normalize_claude()`.

### Cursor

- **Config:** `.cursor/hooks.json` (schema-validated).
- **Events hooked:** `beforeSubmitPrompt`, `beforeShellCommand`, `afterShellCommand`, `beforeFileWrite`, `afterFileWrite`.
- **Sweep target:** `~/.config/Cursor/`.
- **Code:** `prismor/runtime/hooks.py` `_merge_cursor()`, `_normalize_cursor()`.

### Windsurf (Codeium Cascade)

- **Config:** `.windsurf/hooks.json` (project) or `~/.codeium/windsurf/hooks.json` (user).
- **Events hooked:** `pre_user_prompt`, `pre_read_code`, `post_read_code`, `pre_write_code`, `post_write_code`, `pre_run_command`, `post_run_command`, `pre_mcp_tool_use`, `post_mcp_tool_use`, `post_cascade_response`.
- **Sweep target:** `~/.codeium/`.
- **Code:** `prismor/runtime/hooks.py` `_merge_windsurf()`, `_normalize_windsurf()`.

### OpenClaw

- **Config:** `~/.openclaw/config.json` — registers a JS plugin scaffolded at `prismor/runtime/openclaw-plugin/`.
- **Plugin hooks:** `before_tool_call`, `message_sending`, plus an internal `message:received` hook at `~/.openclaw/hooks/prismor/`.
- **Blocking:** non-zero exit from the Prismor dispatcher → plugin returns `{block: true, reason}`.
- **Code:** `prismor/runtime/hooks.py` `_merge_openclaw()`, `_normalize_openclaw()`.

### Hermes (NousResearch gateway)

Prismor integrates with Hermes at two complementary layers:

**1. Runtime hooks** (for policy enforcement and session monitoring):
- **Config:** `~/.hermes/config.json` — registers a JS plugin scaffolded at `prismor/runtime/hermes-plugin/`.
- **Plugin hooks:** `before_tool_call`, `message_sending`, internal `message:received` hook at `~/.hermes/hooks/prismor/`.
- **Session ingest:** offline analysis of `~/.hermes/sessions/*.jsonl` via `prismor ingest --input <file> --agent hermes`, or `prismor ingest --discover --agent hermes` to sweep the whole store automatically. The Hermes transcript adapter is contract-tested but has not been verified against real Hermes session data — run it with `--strict` and report a zero-event sweep. See [Transcript Ingest](docs/transcript-ingest.md).
- **Code:** `prismor/runtime/hooks.py` `_merge_hermes()`, `_normalize_hermes()`.

**2. Secret cloaking** (for preventing secrets from entering model context):
- **Discovery:** pip-installed Hermes auto-discovers the plugin via the `hermes_agent.plugins` entry-point group in `pyproject.toml`. No filesystem setup needed.
- **Alternative install:** `prismor cloak install --agent hermes` copies the plugin to `~/.hermes/plugins/prismor-cloak/`.
- **Hooks installed:** `pre_tool_call` (decloak + secret guard), `post_tool_call` (audit), `transform_terminal_output` (scrub output), `transform_tool_result` (scrub tool results), `pre_gateway_dispatch` (paste guard).
- **Auto-vaulting:** pasted secrets are detected, vaulted under `auto_<hash>` names, and re-sent as `@@SECRET:auto_xxx@@` without the agent ever seeing the raw value.
- **Code:** `prismor/runtime/cloaking/hermes_installer.py`, `prismor/runtime/cloaking/hermes_plugin_entry.py`.
- **Docs:** [docs/hermes.md](docs/hermes.md).

### GitHub Copilot CLI

- **Config:** `~/.copilot/hooks/prismor.json` (user) or `.github/hooks/prismor.json` (project). Copilot loads only `*.json` files in those directories.
- **Events hooked:** `PreToolUse`, `PostToolUse`, `UserPromptSubmit`. With PascalCase event names Copilot sends Claude-shaped payloads.
- **Blocking:** hook emits `{"permissionDecision": "deny", "permissionDecisionReason": "..."}` on stdout. Exit-2 convention is not used — Copilot reads the JSON response instead.
- **Static layer:** `--allow-tool` / `--deny-tool` / `--allow-all-tools` CLI flags apply before the hook fires (deny beats allow). Useful as defense-in-depth.
- **Payload note:** arguments arrive in `tool_input` (PascalCase events) or `toolArgs` (camelCase events), as an object or as raw `apply_patch` text. File tools use Copilot's keys: `{path}`, `{path, file_text}`, `{path, old_str, new_str}`. Captured live on Copilot CLI 1.0.88; see `tests/test_copilot_normalizer.py`.
- **Code:** `prismor/runtime/hooks.py` `_merge_copilot()`, `_strip_copilot()`, `_normalize_copilot()`.

### Codex (OpenAI)

- **Config:** `~/.codex/hooks.json` (user) or `<repo>/.codex/hooks.json` (project). MCP/skill scan also reads `~/.codex/config.toml` and `<repo>/.codex/config.toml` — both `hooks.json` and inline `[[hooks.PreToolUse]]`-style TOML hook declarations work identically.
- **Events hooked:** `UserPromptSubmit`, `PreToolUse`, `PermissionRequest`, `PostToolUse`.
- **Matchers installed:** `Bash|apply_patch|mcp__.*`. Verified against a real `codex exec` session: `Bash` is the actual tool name Codex reports to `PreToolUse`/`PostToolUse`.
- **Blocking:** exit 2 from hook → block; stderr → rejection reason. Verified end to end — a policy-blocked command (`rm package-lock.json`, matched by the `lockfile-deletion` rule) was actually denied by Codex's tool router before execution, with the file left untouched.
- **Sweep target:** `~/.codex/`.
- **Minimum version: `codex-cli` ≥ `0.141.0-alpha.1`.** Earlier versions, including the `0.140.0` stable release, have an upstream bug ([openai/codex#26383](https://github.com/openai/codex/issues/26383), [#26452](https://github.com/openai/codex/issues/26452)) where `codex exec` never dispatches *any* hook — not because of config shape, matcher syntax, or hook trust, but because `--dangerously-bypass-hook-trust` silently failed to propagate to the exec thread, so hooks (which require persisted trust) were dropped before dispatch even without `exec` printing an error. Fixed in [openai/codex#26434](https://github.com/openai/codex/pull/26434), merged 2026-06-16, first shipped in `rust-v0.141.0-alpha.1`. As of this writing that fix has not yet reached a stable release tag — pin to an alpha ≥ that build if you need working Codex hooks today, and watch for the next `0.141.x` (or later) stable release.
- **Required feature flag:** Codex's hook dispatcher additionally requires `[features].hooks = true` (previously `codex_hooks`, deprecated in current stable) in the **user-level** `~/.codex/config.toml` — read from nowhere else, not even a project-scoped `.codex/config.toml`. Without it, hooks are silent no-ops: no error, no warning, every tool call passes straight through. `install_hooks()` now sets/migrates this automatically as of PrismorSec/prismor#149 (verified live against `codex-cli 0.142.5`: a destructive command that should have been blocked instead ran and deleted its target file before this fix).
- **Code:** `prismor/runtime/hooks.py` `_merge_codex()`, `_strip_codex()`, `_normalize_codex()`, `_ensure_codex_hooks_feature_enabled()`.

### Grok Build (xAI)

- **Config:** `~/.grok/hooks/prismor.json` (user) or `<repo>/.grok/hooks/prismor.json` (project). Grok reads a directory of independent hook files (`~/.grok/hooks/*.json` / `<repo>/.grok/hooks/*.json`), so Prismor owns a dedicated file instead of merging into a shared one.
- **Events hooked:** `UserPromptSubmit`, `PreToolUse`, `PostToolUse`. `PreToolUse` is Grok's only blocking event.
- **Matchers installed:** `Bash|Read|Edit|MultiEdit|Write|WebFetch|WebSearch|mcp__.*`, following Claude Code's tool-name taxonomy — Grok Build natively reads `.claude/settings.json` and `.cursor/hooks.json` as a convenience, which strongly implies (but does not itself confirm) that its own built-in tool names match Claude Code's.
- **Blocking:** exit 2 from hook → block; stdout `{"decision": "deny", "reason": "..."}` supplies the reason shown to the user. Exit 0 → allow. Any other exit code, a crash, or a timeout fails **open** on Grok's side (documented behavior, not a Prismor choice).
- **Sweep target:** `~/.grok/`.
- **Not yet verified against a live `grok` install.** This integration is built entirely from [docs.x.ai/build/features/hooks](https://docs.x.ai/build/features/hooks) and [docs.x.ai/build/overview](https://docs.x.ai/build/overview) — no `grok` binary was available to smoke-test against at implementation time. Before relying on this in `enforce` mode, run `grok inspect` to confirm the real built-in tool names, and verify a deliberately blocked command is actually denied end to end (the same live check done for Codex above).
- **Project-hook trust:** Grok requires trust before running project-level hooks (`/hooks-trust` or `--trust` inside `grok`, recorded in `~/.grok/trusted_folders.toml`). This is a one-time manual step Prismor does not automate.
- **Code:** `prismor/runtime/hooks.py` `_merge_grok()`, `_strip_grok()`, `_normalize_grok()`.

### Kiro CLI (AWS)

- **Config:** `~/.kiro/agents/kiro_default.json` (user) or `<repo>/.kiro/agents/kiro_default.json` (project). Unlike every other shipped agent, Kiro's hooks are not a dedicated hooks file — they're a `"hooks"` field inside a *named agent config*, and the one that runs by default (`kiro_default`) has no on-disk file until one is created.
- **Events hooked:** `userPromptSubmit`, `preToolUse`, `postToolUse` (lowerCamelCase — Kiro's own convention, distinct from every other agent's PascalCase event names). `preToolUse` is the only blocking event; a `stop` hook also exists (can block session termination via JSON) but is intentionally not wired, same precedent as skipping Claude's `Stop` hook.
- **Matcher:** entries omit the `matcher` field entirely, which Kiro documents as applying the hook to every tool — the broadest coverage, equivalent to the `"*"`/`mcp__.*` matchers used elsewhere.
- **Blocking:** exit 2 from the `preToolUse` hook blocks the tool call, with stderr surfaced back to the model as context. No structured stdout JSON response is required (unlike Grok/Copilot) — this fits the same fail-closed `else` branch already used for Cursor/Windsurf/Codex.
- **Self-contained install, not a hooks-only fragment.** Whether Kiro merges a partial `kiro_default.json` override with its built-in tool list, or replaces it outright, is undocumented — kiro.dev has no example of overriding the built-in default agent, only creating new named ones. To avoid silently stripping a user's default tools (`read`, `write`, `shell`, ...) the moment Prismor installs hooks, a *fresh* file is seeded with an explicit tools list (`_KIRO_DEFAULT_TOOLS`) alongside the hooks. An existing file — the user's own customized `kiro_default`, or a prior Prismor install — is left otherwise untouched; only `"hooks"` is merged into it.
- **Tool-name taxonomy:** canonical snake_case (`execute_bash`, `fs_read`, `fs_write`, `use_aws`) plus short aliases (`shell`, `read`, `write`, `aws`) — normalization matches on both forms. `fs_write`'s `tool_input` shape (`{"operations": [{"mode": ..., "path": ...}]}`) is not fully documented past the `path` field; content extraction from the first operation is best-effort with several fallback field names.
- **Sweep target:** `~/.kiro/`.
- **Not yet verified against a live `kiro-cli` binary.** Built from [kiro.dev/docs/cli/hooks](https://kiro.dev/docs/cli/hooks/), the [agent configuration reference](https://kiro.dev/docs/cli/custom-agents/configuration-reference/), and community documentation at [Ar9av/agent-manual](https://github.com/Ar9av/agent-manual/blob/main/tools/kiro/README.md). Before relying on this in `enforce` mode, confirm live whether a partial `kiro_default.json` is merged or replaces built-in defaults, and verify a deliberately blocked command is actually denied end to end.
- **Code:** `prismor/runtime/hooks.py` `_merge_kiro()`, `_strip_kiro()`, `_normalize_kiro()`.

### Crush (Charmbracelet)

- **Config:** `crush.json` (project root) or `~/.config/crush/crush.json` (user).
- **Events hooked:** `PreToolUse` only. Verified live (2026-07, crush v0.86.x): Crush's own SDK exposes a generic `HookConfig` schema, but no `PostToolUse`/`UserPromptSubmit` hook is actually dispatched at runtime — only `PreToolUse` fires.
- **Matcher:** an empty-string matcher (`""`) is used for full coverage — verified it fires for a non-bash tool, not just the shell tool.
- **Blocking:** exit 2 blocks the tool call, with the reason read from **stderr only**. A `{"decision":"block","reason":"..."}` stdout envelope — the convention several other agents in this table use — was tested live and silently ignored; do not copy that pattern here.
- **Tool-name taxonomy:** shell tool is `bash`. `view` reads a file; `write`/`edit`/`multiedit` write; `fetch`/`download`/`sourcegraph` are network.
- **Sweep target:** `~/.config/crush/`.
- **Code:** `prismor/runtime/hooks.py` `_merge_crush()`, `_strip_crush()`, `_normalize_crush()`.

### OpenHands

- **Config:** `<repo>/.openhands/hooks.json` (project). No documented global path; a "global"-scope install falls back to `~/.openhands/hooks.json` (unverified — matches where OpenHands' other global state lives, but no official doc confirms a global hooks.json is ever read).
- **Events hooked:** `PreToolUse`, `UserPromptSubmit`. Verified live (2026-07, openhands v1.21.0): a `PreToolUse` hook fires and a non-zero exit genuinely blocks the tool call (confirmed via the CLI's own `--headless` output).
- **Tool-name taxonomy:** shell tool is `terminal` — **not** `execute_bash`, which is the name used elsewhere in this codebase's own docs for other agents and is easy to copy by mistake.
- **Payload shape note:** the event-name field in the hook's stdin JSON is `event_type`, not `hook_event_name` like the Claude/Codex-family agents — a real schema difference between OpenHands and most of this table, not a typo.
- **Blocking:** exit 2 from the hook blocks the tool call; falls into the same fail-closed `else` branch as Cursor/Windsurf/Codex/Kiro.
- **Sweep target:** `~/.openhands/`.
- **Code:** `prismor/runtime/hooks.py` `_merge_openhands()`, `_strip_openhands()`, `_normalize_openhands()`.

### Qwen Code (Alibaba)

- **Config:** `.qwen/settings.json` (project) or `~/.qwen/settings.json` (user).
- **Events hooked:** `UserPromptSubmit`, `PreToolUse`, `PostToolUse`. Verified live (2026-07, qwen-code v0.20.1): a `PreToolUse` hook fires and genuinely blocks via a `hookSpecificOutput.permissionDecision: "deny"` stdout envelope.
- **Tool-name taxonomy:** hooks are Claude-Code-shaped (same field names, matcher syntax), but with Qwen's **own** tool ids — the shell tool is `run_shell_command`, not `Bash`. A matcher of `"Bash"` copied from the Claude integration silently never fires; `"*"` is used here instead for guaranteed coverage.
- **Blocking:** a **nested** stdout JSON envelope (`{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": "..."}}`), not the flat shape Copilot uses. This needed its own `cli.py` branch — it doesn't fit any existing blocking pattern in this table. Verified the deny is honored even without a non-zero exit code, so this dispatcher path intentionally does not `raise SystemExit(2)` afterward.
- **Non-interactive gotcha (not a hook bug, but easy to mistake for one):** running `qwen -p "..."` without `-y`/`--yolo` leaves shell-tool approval unable to proceed in a non-interactive session; a small/cheap model can then narrate a plausible-sounding fake "command succeeded" or "blocked by your hook" result without any tool call — or hook — actually running. Always pass `-y` when testing or scripting this integration, and don't trust the model's narration as proof a hook fired; check the hook's own side effects.
- **Sweep target:** `~/.qwen/`.
- **Code:** `prismor/runtime/hooks.py` `_merge_qwen()`, `_strip_qwen()`, `_normalize_qwen()`.

### Continue CLI

- **Config:** `.continue/settings.json` (project) or `~/.continue/settings.json` (user). Continue CLI also reads `.claude/settings.json`/`~/.claude/settings.json` for cross-compatibility, but this integration targets its own native path.
- **Events hooked:** `UserPromptSubmit`, `PreToolUse`, `PostToolUse` — schema is deliberately Claude-Code-compatible (same field names, same tool-name convention: `Bash`, `Read`, `Edit`, `MultiEdit`, `Write`).
- **Blocking:** exit 2, same as Claude/Codex/Kiro — falls into the generic fail-closed `else` branch.
- **⚠️ Known issue, not a Prismor bug:** verified live (2026-07, `cn` v1.5.47) that hooks configured exactly per this schema, in every documented config location (project/global, custom/default `--config` path), **did not fire at all in headless (`cn -p`) mode** — not just for `PreToolUse`, but for `UserPromptSubmit` too, which needs no tool call whatsoever to trigger. `runHeadlessMode()` in Continue's own source does call `initializeServices()` (which registers and eagerly initializes the hooks service) before running the prompt, so this isn't an obvious ordering bug — root cause not fully pinned down beyond that. **This integration is shipped anyway** because interactive-mode users may still be covered, and an installed-but-inert hook config does no harm — but **do not treat "hooks installed" as "hooks active" for Continue CLI** without testing your actual invocation mode first. Re-check this against newer `cn` releases before relying on it.
- **Sweep target:** `~/.continue/`.
- **Code:** `prismor/runtime/hooks.py` `_merge_continue()`, `_strip_continue()`, `_normalize_continue()`.

### Goose (Agentic AI Foundation, formerly Block)

- **Config:** a scaffolded plugin directory following goose's Open Plugins spec — `<repo>/.agents/plugins/prismor/hooks/hooks.json` (project) or `~/.agents/plugins/prismor/hooks/hooks.json` (user). Goose auto-discovers any directory under `.../plugins/<name>/` containing `hooks/hooks.json`; unlike OpenClaw/Hermes there's no central `"plugins": [...]` list to register — a static `plugin.json` manifest is scaffolded alongside the hooks file as a one-time side effect.
- **Events hooked:** `PreToolUse`, `UserPromptSubmit`.
- **Tool-name taxonomy:** the built-in shell tool's real name is `shell` — verified live (2026-07, goose v1.44.0) that this is **not** `developer__shell`, which is what goose's own official documentation example currently shows. A matcher copied straight from goose's docs would silently never fire; `".*"` is used here instead.
- **Payload shape note:** the event-name field is `event`, not `hook_event_name`.
- **Blocking:** exit 2 blocks (stderr reason), OR a `{"decision":"block","reason":"..."}` stdout envelope — both confirmed live. This fits the generic fail-closed `else` branch; no special-case needed in `cli.py`.
- **Sweep target:** `~/.config/goose/`.
- **Code:** `prismor/runtime/hooks.py` `_merge_goose()`, `_strip_goose()`, `_normalize_goose()`.

---

## Production frameworks — in-process SDK adapters

Framework agents deployed in production (not coding IDEs) expose no hook-config
files. The control point is an **in-process SDK adapter** that wraps tool
execution and calls the shared `prismor.runtime.runtime.evaluate_tool_call` pipeline — the
same policy, observe/enforce model, and session store the coding-agent hooks use.
These adapters are also the layer that carries **per-user** attribution: one
deployed agent serving many users tags each tool call with the calling
`Subject` (see [`prismor/runtime/principal.py`](prismor/runtime/principal.py)) so policy, IAM, and
telemetry scope to the end-user.

### OpenAI Agents SDK

- **Surface:** in-process tool wrapper / guardrail (`surface: sdk`).
- **Package:** [`adapters/openai-agents/`](adapters/openai-agents/), bundled in
  `pip install "prismor[openai-agents]"`. `from prismor.openai import prismor_guard`.
- **Blocking:** raises `PrismorBlocked` before the tool runs; `mode="observe"` is log-only.
- **Per-user:** `subject` → policy + IAM (`user:<id>` / `team:<id>` profiles) + telemetry.
- **Code:** `adapters/openai-agents/prismor_openai/__init__.py`,
  `prismor/runtime/runtime.py`, `prismor/runtime/principal.py`.
- **Docs:** [docs/frameworks-openai-agents.md](docs/frameworks-openai-agents.md).

### LangChain / LangGraph

- **Surface:** in-process tool wrapper + optional callback handler (`surface: sdk`).
- **Package:** [`adapters/langchain/`](adapters/langchain/), bundled in
  `pip install "prismor[langchain]"`. `from prismor.langchain import guard_tools`;
  or `PrismorCallbackHandler(...)` for capture.
- **Blocking:** wraps each tool's `func`/`coroutine`; denied call returns a denial
  string (or raises with `raise_on_block=True`). `mode="observe"` is log-only.
- **Verified:** live against a LangGraph `create_react_agent` — `rm -rf /` and
  `cat .env | curl` blocked before execution, `echo` allowed.
- **Code:** `adapters/langchain/prismor_langchain/__init__.py`.

### CrewAI

- **Surface:** in-process tool wrapper (`surface: sdk`).
- **Package:** [`adapters/crewai/`](adapters/crewai/), bundled in
  `pip install "prismor[crewai]"`. `from prismor.crewai import guard_tools`.
- **Blocking:** wraps each tool's `func`/`_run`/`run`; denied call returns a
  denial string (or raises). `mode="observe"` is log-only.
- **Verified:** live against a `Crew` with a shell tool — `rm -rf /` blocked
  before execution, `echo` allowed.
- **Code:** `adapters/crewai/prismor_crewai/__init__.py`.

### Pydantic AI

- **Surface:** in-process `WrapperToolset` (`surface: sdk`).
- **Package:** [`adapters/pydantic-ai/`](adapters/pydantic-ai/), bundled in
  `pip install "prismor[pydantic-ai]"`. `from prismor.pydantic_ai import guard_toolsets`.
- **Hook:** `PrismorToolset(WrapperToolset)` overrides `call_tool(name, tool_args, ctx, tool)` —
  the single choke point every tool call passes through (plain functions, MCP-server
  tools, or any composed toolset). Not calling `super().call_tool(...)` means the
  wrapped tool never runs.
- **Blocking:** raises `pydantic_ai.exceptions.ToolFailed` by default (a definitive
  failure the model sees and adapts to, without consuming `ModelRetry`'s retry
  budget — this is a policy denial, not a transient error); `raise_on_block=True`
  raises `PrismorBlocked` instead for a hard stop. `mode="observe"` is log-only.
- **Verified:** live against a real `Agent("openai:gpt-4o-mini")` with a genuine
  OpenAI API key — `sudo rm -rf /` denied before the tool's Python implementation
  ever ran, `echo hello` executed normally.
- **Code:** `adapters/pydantic-ai/prismor_pydantic_ai/__init__.py`.

### AutoGen (Microsoft) — Core runtime

- **Surface:** in-process `InterventionHandler` (`surface: sdk`).
- **Package:** [`adapters/autogen-core/`](adapters/autogen-core/), bundled in
  `pip install "prismor[autogen-core]"`. `from prismor.autogen_core import
  PrismorInterventionHandler`, passed to
  `SingleThreadedAgentRuntime(intervention_handlers=[...])`.
- **Hook:** overrides `on_send(message, *, message_context, recipient)` — the
  real per-message gate every `autogen-core` `AgentRuntime.send_message` call
  passes through. Tool calls reach a `ToolAgent` as individual `FunctionCall`
  messages via exactly this path.
- **Blocking:** raises `autogen_core.tool_agent.ToolException` by default —
  `tool_agent_caller_loop` specifically catches this exception type and
  converts it into a failed `FunctionExecutionResult` fed back to the model,
  so the conversation continues with the denial visible (same UX as the other
  adapters). `drop_instead_of_raise=True` returns `DropMessage` instead
  (silently cancels delivery, no result fed back). `mode="observe"` is log-only.
- **Scope caveat (unchanged from the roadmap entry):** this only covers the
  low-level `autogen-core` runtime — the high-level `AgentChat`
  `AssistantAgent`, what most AutoGen users actually build with, does not
  route tool execution through this same `send_message`/`ToolAgent` path.
- **Verified:** live against a real `SingleThreadedAgentRuntime` + `ToolAgent`
  + `tool_agent_caller_loop` calling `openai:gpt-4o-mini` with a genuine
  OpenAI API key — a destructive shell command was denied before the tool's
  Python implementation ever ran, a benign command executed normally.
- **Code:** `adapters/autogen-core/prismor_autogen_core/__init__.py`.

### Agno

- **Surface:** in-process `tool_hooks` chain (`surface: sdk`).
- **Package:** [`adapters/agno/`](adapters/agno/), bundled in
  `pip install "prismor[agno]"`. `from prismor.agno import prismor_tool_hook`;
  `Agent(tools=[...], tool_hooks=[prismor_tool_hook])`, or
  `make_tool_hook(subject="user:alice", mode="enforce")` to customize.
- **Hook:** `tool_hooks` list on `Agent`/`Team` — distinct from the singular
  `pre_hook`/`post_hook`. Agno introspects the hook's own signature and
  injects `function_name` / `function_call` / `args`/`arguments` by
  parameter name; `function_call` is the callable that continues the
  execution chain, not a data object.
- **Blocking:** raise inside the hook instead of calling
  `function_call(**arguments)` — confirmed against source that the
  `try/finally` wrapper around hook calls only isolates message-list state,
  it does not swallow exceptions. Raises plain `RuntimeError` by default
  (Agno surfaces it to the model as a tool error); `raise_on_block=True`
  (via `make_tool_hook`) raises `PrismorBlocked` instead. `mode="observe"`
  is log-only.
- **Verified:** live against a real `Agent(model=OpenAIChat(id="gpt-4o-mini"))`
  with a genuine OpenAI API key — `sudo rm -rf /` denied before the tool's
  Python implementation ever ran (model correctly reported the block),
  `echo hello` executed normally.
- **Code:** `adapters/agno/prismor_agno/__init__.py`.

### Semantic Kernel (Microsoft)

- **Surface:** in-process filter middleware (`surface: sdk`).
- **Package:** [`adapters/semantic-kernel/`](adapters/semantic-kernel/), bundled in
  `pip install "prismor[semantic-kernel]"`. `from prismor.semantic_kernel import make_filter`;
  `kernel.add_filter(FilterTypes.AUTO_FUNCTION_INVOCATION, make_filter(subject="user:alice", mode="enforce"))`.
- **Hook:** `filter_fn(context, next)` wraps the actual invocation — every
  registered filter composes into one middleware stack whose innermost link
  calls `context.function.invoke(...)`. The cleanest gate-then-continue
  semantics of any framework in this table: not calling `await next(context)`
  means the real tool never runs. (Python confirmed; the .NET
  `IAutoFunctionInvocationFilter` equivalent was not independently
  re-verified in this pass.)
- **Blocking:** deny by skipping `next(context)` and setting a synthetic
  `context.function_result` so the model still sees a coherent (denied) tool
  response. `raise_on_block=True` raises `PrismorBlocked` instead.
  `mode="observe"` is log-only.
- **Verified:** live against a real `Kernel` + `OpenAIChatCompletion(ai_model_id="gpt-4o-mini")`
  with a genuine OpenAI API key — a destructive shell command was denied
  before the tool's Python implementation ever ran, a benign command
  executed normally.
- **Code:** `adapters/semantic-kernel/prismor_semantic_kernel/__init__.py`.

### Google Agent Development Kit (ADK)

- **Surface:** in-process `before_tool_callback` (`surface: sdk`).
- **Package:** [`adapters/google-adk/`](adapters/google-adk/), bundled in
  `pip install "prismor[google-adk]"`. `from prismor.google_adk import make_before_tool_callback`;
  `LlmAgent(before_tool_callback=make_before_tool_callback(subject="user:alice", mode="enforce"))`.
- **Hook:** `before_tool_callback(tool, args, tool_context)` on `LlmAgent`
  (or as a `BasePlugin` method — plugin-level callbacks take precedence
  over agent-level ones).
- **Blocking:** deny-by-substitution by default, not exception: returning
  `None` proceeds with the real tool call; returning a `dict` **skips**
  tool execution and that dict becomes the result instead — the model
  never sees the tool actually run. `raise_on_block=True` raises
  `PrismorBlocked` instead. `mode="observe"` is log-only.
- **Verified:** live against a real `LlmAgent` using ADK's `LiteLlm` wrapper
  for `openai/gpt-4o-mini` (`pip install "google-adk[extensions]"`) with a
  genuine OpenAI API key — a destructive shell command was denied before
  the tool's Python implementation ever ran, a benign command executed
  normally.
- **Code:** `adapters/google-adk/prismor_google_adk/__init__.py`.

### Mastra (TypeScript)

- **Surface:** in-process tool wrapper, via the Prismor eval-server sidecar (`surface: sdk`).
- **Package:** [`adapters/mastra/`](adapters/mastra/) → `prismor-mastra` (npm).
  `prismorTool("run_shell", runShell, { mode: "enforce", subject: "user:alice" })`.
- **Hook:** wraps a tool's `execute` function directly — the same pattern
  the CrewAI/LangChain adapters use — calling the Prismor eval-server
  (`prismor eval-server --port 7071`) before the body runs.
- **⚠️ Corrected from the roadmap entry:** the originally-planned
  `processOutputStep` + `abort()` hook (Mastra's own documented "after LLM
  response, before tool execution" mechanism) was tried first and found
  **not reliable** when tested against a real agent run
  (`@mastra/core` v0.x, 2026-07): calling `abort()` throws a
  workflow-level error, but the tool's `execute` function runs anyway
  regardless — confirmed with timestamped logging showing `execute` firing
  *after* `abort()` was called. Direct `execute`-wrapping does reliably
  block, since the wrapped function is what Mastra actually calls.
- **Blocking:** a denied call throws `PrismorBlocked`; Mastra's
  tool-execution step catches it and feeds the error back to the model as
  the tool's result. `mode="observe"` is log-only; `failMode` controls
  eval-server-unreachable behavior (`"closed"` by default in enforce mode).
- **Verified:** live against a real Mastra `Agent` running `gpt-4o-mini`
  (via `@ai-sdk/openai`) with a genuine OpenAI API key and a local
  `prismor eval-server` — a destructive shell command was denied before
  the tool's JavaScript implementation ever ran, a benign command executed
  normally.
- **Code:** `adapters/mastra/src/index.ts`.

### BeeAI Framework (IBM Research / Linux Foundation)

- **Surface:** in-process tool wrapper (`surface: sdk`).
- **Package:** [`adapters/beeai/`](adapters/beeai/), bundled in
  `pip install "prismor[beeai]"`. `from prismor.beeai import guard_tool`;
  `guard_tool(tool, subject="user:alice", mode="enforce")` / `guard_tools([...])`.
- **Hook:** subscribes a blocking listener to a `Tool`'s `Emitter`
  `"start"` event — `emitter.on("start", handler, EmitterOptions(is_blocking=True))`
  — which `Tool.run()` awaits *before* calling `self._run(...)`.
- **Extra scrutiny applied:** after finding that Mastra's documented
  "before execution" hook did *not* actually block (above), the same
  source-reading discipline was applied here before writing any adapter
  code: `Emitter._invoke` runs listeners as tasks inside
  `asyncio.TaskGroup`, which always awaits every task and re-raises on
  failure before the surrounding block exits — so a listener that raises
  genuinely prevents `self._run(...)` from ever executing, confirmed
  against source rather than assumed from docs.
- **Blocking:** a denied call raises inside the listener (`RuntimeError`
  by default, or `PrismorBlocked` with `raise_on_block=True`); BeeAI's
  tool executor surfaces this as a tool error visible to the agent.
- **Verified:** live against a real `ReActAgent` running `gpt-4o-mini`
  (via `ChatModel.from_name("openai:gpt-4o-mini")`) with a genuine OpenAI
  API key — a destructive shell command was denied before the tool's
  `_run` ever executed, a benign command executed normally.
- **Code:** `adapters/beeai/prismor_beeai/__init__.py`.

### Claude Code Agent SDK

- **Surface:** in-process hooks (`surface: sdk`).
- **Package:** [`adapters/claude-agent-sdk/`](adapters/claude-agent-sdk/), bundled
  in `pip install "prismor[claude-agent-sdk]"`. `from prismor.claude_agent_sdk
  import prismor_hook_matcher`; `prismor_hook_matcher(mode="enforce",
  subject="user:alice")` passed into `ClaudeAgentOptions(hooks={"PreToolUse": [...]})`.
- **Hook:** the exact same `PreToolUse` hooks system the Claude Code CLI
  itself uses, exposed programmatically — `HookMatcher(matcher=None,
  hooks=[cb])` against a `PreToolUseHookInput` (`tool_name`, `tool_input`).
  `matcher` defaults to `None` (every tool call) rather than a fixed
  built-in-tool-name list, since custom tools registered via
  `create_sdk_mcp_server` arrive as `mcp__<server>__<tool>` — a narrower
  default would silently exempt every custom/MCP tool from policy.
- **Blocking:** deny via `hookSpecificOutput.permissionDecision: "deny"`,
  which overrides even `bypassPermissions` mode.
- **Verification methodology note:** unlike the OpenAI-key-backed
  adapters above, this one needs genuine Anthropic auth to run at all, so
  it was live-tested on a separate host with an authenticated Claude Code
  CLI session rather than the shared OpenAI key. Naive destructive
  commands (`rm -rf /`, cloud-metadata SSRF) turned out to be an
  unreliable test signal here — Claude's own alignment refuses those
  regardless of any hook (confirmed with a baseline run that had *zero*
  Prismor hooks installed and still refused). Switched to a discriminating
  case instead: a benign-framed write to `.claude/settings.json`
  (Prismor's own `agent-config-tampering` rule) that Claude readily
  executes with no hook installed, and that the adapter denies once
  installed — this is what actually isolates the adapter's effect from
  the model's own judgment, and it's also what caught a real bug (an
  earlier default `matcher` regex that never matched custom MCP tool
  names, so the hook silently never fired).
- **Code:** `adapters/claude-agent-sdk/prismor_claude_agent_sdk/__init__.py`.

### MCP proxy — roadmap

A `surface: mcp` shim in front of downstream MCP servers intercepts `tools/call`
and evaluates it, covering any MCP-speaking agent with no per-framework code.

---

## Roadmap — hook adapters planned

Each agent below exposes a blocking pre-tool hook. An adapter requires (1) config-merge in `prismor/runtime/hooks.py`, (2) `_normalize_*` function, (3) registration in `_SUPPORTED_AGENTS` and `prismor/runtime/store.py`, (4) sweep target in `prismor/runtime/sweep.py` if applicable.

### Gemini CLI (Google)

- **Status:** stable — launched as a core feature on the [Google Developers Blog](https://developers.googleblog.com/tailor-gemini-cli-to-your-workflow-with-hooks/). Cleanest drop-in of the roadmap set.
- **Config:** `.gemini/settings.json` (project) → `~/.gemini/settings.json` (user) → `/etc/gemini-cli/settings.json` (system), layered. `hooks.<Event>[].matcher` + `.hooks[]` with `{name, type: "command", command, timeout}`.
- **Events:** `BeforeTool`, `AfterTool`, `BeforeAgent`, `AfterAgent`, `BeforeModel`, `BeforeToolSelection`, `AfterModel`, `SessionStart`, `SessionEnd`, `Notification`, `PreCompress`.
- **Payload:** JSON on stdin — shared `session_id`, `transcript_path`, `cwd`, `hook_event_name`, `timestamp`, plus event-specific fields (`tool_name`, `prompt`, etc.).
- **Blocking:** exit 2 → "System Block" (stderr → rejection reason; for tool events blocks the call but agent continues; for agent/model events aborts the turn). Other non-zero exits → non-fatal warning.
- **Adapter work:** write hooks block into `~/.gemini/settings.json`, map `BeforeTool`→pre, `AfterTool`→post, `SessionStart`. Reuse Claude-shape normalizer.

### OpenCode

- **Config:** `.opencode/plugins/*.js` (project) or `~/.config/opencode/plugins/*.js` (global); npm-package plugins declared in `opencode.json` under `"plugin": [...]`.
- **Hooks:** `tool.execute.before`, `tool.execute.after`, plus `file.edited`, `file.watcher.updated`, `session.created|compacted|updated`, `message.updated|removed`, `shell.env`, `permission.asked|replied`.
- **Handler signature:** `export const name = async ({ project, client, $, directory, worktree }) => ({ "tool.execute.before": async (input, output) => { ... } })`. `input.tool` = tool name; `output.args` is mutable — supports input rewriting as well as blocking.
- **Blocking:** `throw new Error(reason)` inside `tool.execute.before`.
- **Adapter work:** ship `@prismor/opencode-plugin` (or a drop-in `prismor-plugin.js`) that translates the hook payload to Prismor's canonical event, calls the dispatcher, and `throw`s on deny. Different shape than OpenClaw/Hermes: in-process JS, not subprocess-per-call — the shim is the only agent-side code.

### Kiro (AWS)

- **Config:** `~/.kiro/` (global), `.kiro/` (workspace) with `hooks/`, `steering/`, `agents/`, `settings/mcp.json`.
- **Hooks:** `preToolUse`, `postToolUse` with a `matcher` field.
- **Blocking:** exit 2 → block execution, stderr returned to the LLM.
- **Adapter work:** shape is close to Claude Code — reuse dispatcher and normalizer. Scaffold the `.kiro/hooks/` entry.

### Factory Droid

- **Config:** `~/.factory/` (global); project `.factory-plugin/plugin.json` with sibling `hooks/hooks.json`.
- **Hooks:** `PreToolUse`, `PostToolUse` (Claude-Code-compatible JSON contract). Matchers like `Write|Edit` shown in plugin examples.
- **Blocking:** return `{permissionDecision: "deny", reason}`; `updatedInput` supports input rewriting before execution.
- **Adapter work:** the JSON-response contract differs from Claude's exit-2 convention — dispatcher needs to emit a response object, not just an exit code. Otherwise reuse normalizer.

### Pi Coding Agent

- **Config:** requires the community `pi-yaml-hooks` package (`pi install npm:pi-yaml-hooks`) — Pi has no built-in hooks.json. `.pi/hook/hooks.yaml` (project, requires trust) or `~/.pi/agent/hook/hooks.yaml` (user).
- **Events:** dot-notation (`tool.before.*`, `tool.after.*`, `session.created`, `file.changed`).
- **Blocking:** `exit 2` from a `tool.before.*` action's `bash:` script blocks the call — verified live (2026-07, pi-coding-agent v0.81.1), unconditional exit 2 genuinely blocked a tool call.
- **Blocker for a real adapter:** the documented way to read the triggering command inside a hook — a `$TOOL_INPUT` env var, and `{{tool_input}}`/`{{command}}` mustache templating — were both tested live and did **not** work (empty/unsubstituted). Without a confirmed way to read the command, a real integration could only implement blanket policy (block/allow an entire event type), not the command-aware policy Prismor ships for every other agent. Find the correct mechanism (likely requires reading pi-yaml-hooks' own source) before building this.

### Amazon Q Developer CLI (AWS)

- **Config:** hooks live inside a named per-agent JSON file — `.amazonq/cli-agents/*.json` (project) or `~/.aws/amazonq/cli-agents/*.json` (user) — same structural complexity as Kiro's `kiro_default.json`, not a dedicated hooks file.
- **Events:** `agentSpawn`, `userPromptSubmit`, `preToolUse` (only blocking event), `postToolUse`, `stop`.
- **Blocking:** exit 2 + stderr text. No structured JSON decision object (simpler than the Claude-family agents, but no ask/modify verdict support either).
- **Note:** AWS has marked the open-source Amazon Q Developer CLI unmaintained (critical-fixes-only), pointing users to the closed-source Kiro CLI instead — which Prismor already ships support for. Weigh this against the effort of a full adapter.

### Amp (Sourcegraph spinoff)

- **Config:** no declarative hooks.json — a TypeScript Plugin API (`.amp/plugins/*.ts` project, `~/.config/amp/plugins/*.ts` user). A plugin exports an async function receiving a context object and returning handlers keyed by event name (`tool.call`, `agent.start`, `agent.end`, ...).
- **Adapter work:** architecturally closer to OpenCode than to any JSON-hooks agent in this table — needs a scaffolded `.ts` plugin file (like the OpenClaw/Hermes JS scaffolds, or OpenCode's planned shim) that shells out to the Prismor dispatcher and returns/throws a reject action on deny, not a config-merge. Not yet verified against a live `amp` install.

### Auggie CLI (Augment Code)

- **Config:** `.augment/settings.json` (project) or `~/.augment/settings.json` (user) — JSON with a top-level `hooks` key, command-type handlers only.
- **Events:** `PreToolUse`, `PostToolUse`, `Stop`, `SessionStart`, `SessionEnd`.
- **Blocking:** documented as exit 2, same family as Claude/Codex/Kiro/OpenHands.
- **Adapter work:** shape looks like a straightforward reuse of the Claude/Codex merge pattern. Not yet verified against a live `auggie` install — confirm real tool-name matchers before shipping.

### Kimi Code (Moonshot AI)

- **Config:** TOML, not JSON — `.kimi-code/local.toml` (project) or `~/.kimi-code/config.toml` (user).
- **Events:** a rich set including `PreToolUse`, `PostToolUse`, `UserPromptSubmit`, `SessionStart`, `SessionEnd`, `Stop`, `SubagentStart`, `SubagentStop`.
- **Blocking:** exit 2, Claude-family convention.
- **Adapter work:** needs Codex's `config.toml` text-patch approach (`_ensure_codex_hooks_feature_enabled` is the template), not the JSON read/merge/write path most other agents use. Not yet verified against a live `kimi-code` install.

### Devin CLI (Cognition AI)

- **Config:** `.devin/hooks.v1.json` (project) or `~/.config/devin/hooks.v1.json` (user).
- **Events:** `SessionStart`, `SessionEnd`, `UserPromptSubmit`, `PreToolUse`, `PostToolUse`, `PermissionRequest`, `Stop`, `PostCompaction`.
- **Blocking:** exit 2, same family; Devin's own docs note the format explicitly mirrors Claude Code's, so hooks written for Claude Code projects reportedly work directly against Devin too.
- **Adapter work:** likely the smallest lift of this roadmap set — port `_merge_claude`/`_strip_claude`/`_normalize_claude` with path and minor field-name changes. Devin also requires new (non-managed) hooks to be interactively trusted before first execution, similar to Codex's hook-trust model — factor that into install UX. Not yet verified against a live `devin` install.

---

## Multiplexers / session wrappers — pass-through, no dedicated adapter

### Herdr

[Herdr](https://herdr.dev/) is a terminal multiplexer (Rust, single binary) that runs and
tracks multiple coding agents from one session, including over SSH — it spawns each agent
in a **real PTY pane**, not a sandboxed or proxied environment. It also ships a socket API
(`herdr` agents can spawn panes and coordinate with each other) and a community plugin
marketplace.

- **No dedicated adapter needed.** Herdr doesn't call tools itself and doesn't sit between
  an agent and its config files — it just launches the agent binary in a pane. An agent
  already integrated above (Claude Code, Codex, Cursor, etc.) keeps reading its own
  `~/.claude/settings.json` / `~/.codex/hooks.json` / etc. and firing Prismor's existing
  hooks identically whether it's run directly or inside a Herdr pane.

**Verified live** (Herdr `0.7.5`, `prismor` `1.32.1`, 2026-07-30): installed Claude Code
enforcement hooks (`prismor install-hooks --agent claude --mode enforce`) in a scratch git
repo, started a headless `herdr server`, created a workspace/pane over the socket API
(`herdr workspace create`), and drove a real Claude Code session inside that pane via
`herdr pane run` / `send-text` / `send-keys` — no direct terminal, purely through Herdr's
API.

- **Hook dispatch:** confirmed firing on every tool call from inside the Herdr pane.
  `prismor status` for the workspace showed the same `hook-dispatch` findings
  (`lethal_trifecta`, `dependency_risk` on a `package-lock.json` deletion) that the same
  prompts produce running Claude Code directly — dispatch, rule evaluation, and session
  logging are unaffected by running inside Herdr.
- **Cloaking:** installed `prismor cloak install --agent claude` in the same pane and had
  the agent run `echo "@@SECRET:DEMO_API_KEY@@"` (a non-sensitive test secret) via the Bash
  tool. The `PreToolUse:Bash` hook decloaked the placeholder to the real value to execute
  the command, and the `PostToolUse` scrub restored the placeholder before the result
  reached the model — the agent's own follow-up message confirmed it only ever saw
  `@@SECRET:DEMO_API_KEY@@`, never the raw value. This part of the pipeline is agent-side
  (same code path Prismor already uses outside Herdr) and worked identically inside a pane.
- **New finding — transient exposure in the pane, not Herdr-specific:** Claude Code's own
  permission-approval prompt renders the *post-decloak* command line (i.e., the real secret
  value) before the command runs, since approval happens after `PreToolUse` decloaks but
  before `PostToolUse` scrubs the result. That frame is visible in the PTY Herdr owns for
  that pane. In this test, `herdr pane read --source recent --lines 1000` afterward did
  **not** return that frame — Claude Code's TUI redraws over it rather than appending to
  scrollback, so it wasn't retrievable after the fact via the socket API in this test. This
  is a pre-existing Claude Code UI behavior (identical outside Herdr too), not something
  Herdr introduces — but Herdr's persistence and remote-attach/socket-read model (a pane can
  be watched live by another SSH-attached client, or its live frame captured with different
  `--source`/timing) mean the exposure window is reachable by more potential viewers than a
  single local terminal. **Not fully closed out:** whether Herdr persists a fuller raw
  scrollback/session recording to disk beyond what `pane read` exposed here was not checked.
  Recommend re-testing with `--source visible` immediately after the approval prompt renders
  (before advancing the pane) if cloaking is deployed on a shared/remote Herdr session.
- **Sweep target:** `~/.config/herdr/` — registered in `prismor/runtime/integrations/registry.yaml`
  (`id: herdr`) and `TOOL_DIRS` in `prismor/runtime/sweep.py`, so `prismor sweep` now scans
  it alongside every other agent's config dir. No secrets were found there in this test; the
  directory mainly held `config.toml` and logs, but registering it means a future auth
  token or socket credential Herdr starts persisting there gets swept automatically.
- **Registry:** `kind: multiplexer` / `surface: pass-through` are new enum values added to
  `registry.schema.json` and `registry.py`'s `KINDS`/`SURFACES` — the first entry that isn't
  a `coding-agent` or `framework`. `scripts/gen_integration_matrix.py` gained a third
  generated table ("Multiplexers") to render it; run `scripts/verify_registry.sh` after
  editing `registry.yaml` to confirm the schema and generated doc stay in sync.

---

## Sweep / rules-only — no runtime enforcement

These agents don't expose a programmable pre-tool hook. Integration is limited to:

- **Sweep** — scanning the agent's config directory for leaked secrets with `prismor sweep`.
- **Rules** — shipping `AGENTS.md` / rules-file content the agent loads on every turn (static guardrails, no runtime enforcement).

### Google Antigravity

- **Hooks:** none. Community requests open on the [Antigravity forum](https://discuss.ai.google.dev/t/hooks-in-antigravity/120458). Permission UI is interactive, not programmable.
- **Surface:** `AGENTS.md`, `GEMINI.md`, interactive permission prompts.
- **Config dir:** `~/.antigravity/` (already swept).

### Aider

- **Hooks:** none for agent tool calls. `--git-commit-verify` is a static toggle for git pre-commit only.
- **Surface:** `.aider.conf.yml` + `CONVENTIONS.md` (referenced via `read:`).
- **Config dir:** `~/.aider/`, repo-level `.aider.conf.yml`, `.aider.tags.cache.v*/`.

### Trae / Trae CN (ByteDance)

- **Hooks:** none. MCP is the only dynamic surface — wrapping Prismor as an MCP proxy is feasible but out of scope.
- **Surface:** `.trae/rules/` markdown + MCP server registration.
- **Config dir:** `~/.trae/` (scanned by `prismor sweep`), workspace `.trae/rules/` and `.trae/agents/`.

### Kilocode

- **Hooks:** soft only. `session.chat.before` can inject a guardrail prompt into chat params but cannot veto a tool call. Tool filtering is permission/approval UI, not programmable.
- **Surface:** `AGENTS.md`, `.kilocode/rules/`, `kilo.jsonc`; plugin can inject prompt-level policy.
- **Config dir:** `~/.kilocode/` (scanned by `prismor sweep`), workspace `.kilocode/rules/`.

### Warp (Agent Mode)

- **Hooks:** none. Warp's own docs describe Agent Profiles/Permissions and command/MCP allow-deny lists, not a lifecycle-event hook system.
- **Surface:** primarily a GUI terminal app, not an install-anywhere CLI (it does ship a separate `oz` CLI for headless/cloud use, not evaluated here). `WARP.md`/`AGENTS.md` rules files, `.warp/.mcp.json` MCP config.
- **Config dir:** `~/.warp/` (scanned by `prismor sweep`), workspace `.warp/`.

---

## Adding a new agent

When a new AI coding agent ships a pre-tool hook API, the checklist is:

1. Add the agent name to `_SUPPORTED_AGENTS` in `prismor/runtime/hooks.py`.
2. Add a `_config_path(...)` branch returning the right project/user path.
3. Write `_merge_<agent>(config, command, ...)` producing the hook config.
4. Write `_strip_<agent>(config, marker)` for clean uninstall.
5. Write `_normalize_<agent>(payload, session_id)` mapping the agent's payload to Prismor's canonical `{type, session_id, agent, agent_event, ...}` shape.
6. Add the config directory to `TOOL_DIRS` in `prismor/runtime/sweep.py` if sweep applies.
7. Add MCP/skill config locations to `prismor scan` discovery.
8. Update this file.

---

## Sources (verified 2026-04-21)

Internal code is authoritative for the five supported agents.

**Hooks-capable roadmap agents:**

- Codex — [Hooks](https://developers.openai.com/codex/hooks) · [Advanced config](https://developers.openai.com/codex/config-advanced) · [Issue #16732 — `apply_patch` not hooked](https://github.com/openai/codex/issues/16732)
- Gemini CLI — [Hooks reference](https://geminicli.com/docs/hooks/reference/) · [Overview](https://geminicli.com/docs/hooks/) · [Google Developers Blog launch](https://developers.googleblog.com/tailor-gemini-cli-to-your-workflow-with-hooks/)
- OpenCode — [Plugins](https://opencode.ai/docs/plugins/)
- Kiro — [CLI hooks](https://kiro.dev/docs/cli/hooks/)
- Factory Droid — [Plugins](https://docs.factory.ai/cli/configuration/plugins) · [Hooks reference](https://docs.factory.ai/reference/hooks-reference)
- GitHub Copilot CLI — [Hooks configuration](https://docs.github.com/en/copilot/reference/hooks-configuration) · [Allow/deny tools](https://docs.github.com/en/copilot/how-tos/copilot-cli/allowing-tools)
- VS Code Copilot Chat — [Agent hooks](https://code.visualstudio.com/docs/copilot/customization/hooks)

**Rules-only / sweep-only:**

- [Antigravity — hooks request forum thread](https://discuss.ai.google.dev/t/hooks-in-antigravity/120458)
- [Aider — options](https://aider.chat/docs/config/options.html)
- [Trae — rules docs](https://docs.trae.ai/ide/rules?_lang=en)
- [Kilocode — tool filtering & permissions (DeepWiki)](https://deepwiki.com/Kilo-Org/kilocode/6.3-tool-filtering-and-permissions)

**Multiplexers:**

- Herdr — [herdr.dev](https://herdr.dev/) · pass-through behavior and cloaking scrub verified live against a real Claude Code session run entirely through Herdr's socket API (`herdr` `0.7.5`, `prismor` `1.32.1`), 2026-07-30. Not from docs alone — see the Herdr section above for the test setup.
