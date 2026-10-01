# Claude Code Agent SDK integration

Prismor adapter for the **Claude Agent SDK** (Python). Source lives at
[`adapters/claude-agent-sdk/`](../adapters/claude-agent-sdk/), bundled
into the main `prismor` package (no separate PyPI package).
Registry entry: `id: claude-agent-sdk` in
[`prismor/runtime/integrations/registry.yaml`](../prismor/runtime/integrations/registry.yaml).

## Install

```bash
pip install "prismor[claude-agent-sdk]"
```

## Connect to the console

To see this agent's tool calls in the Prismor console and control it from there:

1. In the console, open **Agents**. Under **SDK & deployed agents**, enter a workload name and click **Mint agent key**. The key is shown once, so put it in your deployment's secret manager.
2. Set it as `PRISMOR_AGENT_KEY` in the agent's environment.
3. Run the agent. Its first guarded tool call pulls your org's signed policy and starts reporting, and the agent appears in the console under that workload name. Changes you make in the console (mode, blocked tools) reach it on its next tool call, at most about 30 seconds later.

Without a key the adapter still enforces your local policy but reports nothing. To check the connection, run `prismor doctor` with the same `PRISMOR_AGENT_KEY` set.

## Why this hook point

This is the exact same hooks system the Claude Code CLI itself uses (and
that this repo's own `prismor/runtime/hooks.py` `_merge_claude()` /
`_normalize_claude()` already install into `.claude/settings.json`),
exposed programmatically instead of via config file: `hooks` on
`ClaudeAgentOptions`, matched with `HookMatcher(matcher=..., hooks=[cb])`
against a `PreToolUseHookInput` (`tool_name`, `tool_input`). Returning
`hookSpecificOutput.permissionDecision: "deny"` blocks the tool call
before it runs — this overrides even `bypassPermissions` permission mode.

## Use

```python
from claude_agent_sdk import ClaudeAgentOptions, ClaudeSDKClient
from prismor.claude_agent_sdk import prismor_hook_matcher

options = ClaudeAgentOptions(
    hooks={"PreToolUse": [prismor_hook_matcher(mode="enforce", subject="user:alice")]},
)

async with ClaudeSDKClient(options=options) as client:
    ...
```

`prismor_hook_matcher`'s `matcher` defaults to `None` (every tool call),
not a fixed built-in-tool-name list — custom tools registered via
`create_sdk_mcp_server` arrive as `mcp__<server>__<tool>`, and a narrower
default would silently exempt every custom/MCP tool from policy. A denied
call returns `hookSpecificOutput.permissionDecision: "deny"` with a
human-readable reason (or raises `PrismorBlocked` if
`raise_on_block=True`), which Claude surfaces as a permission denial
instead of running the tool.

## Per-user control

`subject` (a `Subject`, `"user:alice"`-style string, or `None`) scopes
policy, IAM profile selection, and telemetry to the end-user — the same
generic mechanism every adapter uses.

## ⚠️ Verification methodology note

Unlike the other adapters on this page, this one can't be live-tested with
an OpenAI key — the Claude Agent SDK requires genuine Anthropic/Claude Code
authentication to run at all. It was instead live-tested on a separate
host with an authenticated Claude Code CLI session (`claude-agent-sdk`
shells out to the installed `claude` binary).

Naive destructive test commands (`rm -rf /`, cloud-metadata SSRF) turned
out to be an **unreliable** way to verify this particular adapter: Claude
refuses those on its own, hook or no hook — confirmed with a baseline run
that had *zero* Prismor hooks installed and still refused. The test that
actually isolates the adapter's effect is a benign-framed write to
`.claude/settings.json` (Prismor's own `agent-config-tampering` rule):
Claude executes it readily with no hook installed, and the adapter denies
it once installed. This discriminating test is also what caught a real
bug during development — an earlier default `matcher` regex
(`"Bash|Read|Edit|MultiEdit|Write|WebFetch|WebSearch"`) never matched
custom MCP tool names (`mcp__<server>__<tool>`), so the hook silently
never fired for anything but Claude's built-in tools.

## See also

- [Framework adapters overview](frameworks-overview.md)
- [IAM](iam.md) — per-user permission profiles
