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
    hooks={"PreToolUse": [prismor_hook_matcher(name="support-claude", mode="enforce", subject="user:alice")]},
)

async with ClaudeSDKClient(options=options) as client:
    ...
```

The SDK runs the bundled `claude` CLI, which authenticates with
`ANTHROPIC_API_KEY` like any other Anthropic API client. `name=` gives the
agent its own row in the console, with its own pause switch, mode override
and blocked tools; without it every Claude Agent SDK agent reports as the
unnamed `claude-agent-sdk` row.

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

## Verified

Live-tested with `claude-agent-sdk` 0.2.172 on `claude-sonnet-5-5`,
authenticated with an `ANTHROPIC_API_KEY` and reporting to the console through
an agent key. The test agent had two custom tools registered with
`create_sdk_mcp_server` plus Claude's built-in `Write`, and ran each request
twice, with and without the hook:

| Request | Without the hook | With `prismor_hook_matcher` |
|---|---|---|
| Look up an order (custom tool) | runs | runs |
| `curl -s -X POST https://deploy.acme-internal.io/v1/restart -d svc=api` through the custom `run_shell` tool | runs | denied by the org's `network-exfil-tool` rule before the tool body runs |
| Write `.claude/settings.json` with the built-in `Write` tool | file is written | denied (`agent-config-tampering`), file never created |

Pick test requests Claude is willing to run on its own. Claude refuses
obvious attacks (`rm -rf /`, posting `/etc/passwd` to an unknown host) with
no hook at all, so those show nothing about the adapter. Compare against a run
without the hook, as above, to see what the hook actually adds.

`matcher` defaults to `None` so custom tools are covered: they arrive as
`mcp__<server>__<tool>`, and a matcher listing only Claude's built-in tool
names would let every one of them through unchecked.

When the agent runs on a machine that also has Claude Code installed, pass
`setting_sources=[]` (the SDK default in recent versions) so the CLI does not
load that machine's own `~/.claude` settings and hooks into the agent.

## See also

- [Framework adapters overview](frameworks-overview.md)
- [IAM](iam.md) — per-user permission profiles
