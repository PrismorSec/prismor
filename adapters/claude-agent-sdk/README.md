# prismor-claude-agent-sdk

Prismor adapter for the **Claude Agent SDK** (Python). Every `PreToolUse`
hook call is routed through Prismor's policy engine before Claude is
allowed to run the tool — same observe/enforce model and per-user
attribution as the other adapters.

## Why this hook point

This is the exact same hooks system the Claude Code CLI itself uses
(and that this repo's own `prismor/runtime/hooks.py` `_merge_claude()` /
`_normalize_claude()` already install into `.claude/settings.json`),
exposed programmatically instead of via config file: `hooks` on
`ClaudeAgentOptions`, matched with `HookMatcher(matcher=..., hooks=[cb])`
against a `PreToolUseHookInput` (`tool_name`, `tool_input`). Returning
`hookSpecificOutput.permissionDecision: "deny"` blocks the tool call
before it runs — this overrides even `bypassPermissions` permission mode.

## Verified

Live-tested with an `ANTHROPIC_API_KEY` on `claude-sonnet-5-5` (the SDK's
bundled `claude` CLI authenticates with it), each request run with and
without the hook. Use requests Claude runs on its own: obvious attacks
(`rm -rf /`, posting `/etc/passwd` to an unknown host) are refused with no
hook at all. A `.claude/settings.json` write (`agent-config-tampering`) and a
`curl -X POST ... -d` through a custom MCP tool (`network-exfil-tool`) both
run without the hook and are denied with it. `matcher` defaults to `None`
because a built-in-names regex never matched custom MCP tools
(`mcp__<server>__<tool>`) and silently exempted them. Full table in
[docs/frameworks-claude-agent-sdk.md](../../docs/frameworks-claude-agent-sdk.md).

## Install

```bash
pip install "prismor[claude-agent-sdk]"      # Prismor runtime + adapter + claude-agent-sdk
```

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

A denied call returns `hookSpecificOutput.permissionDecision: "deny"`
with a human-readable reason (or raises `PrismorBlocked` if
`raise_on_block=True`), which Claude surfaces as a permission denial
instead of running the tool.
