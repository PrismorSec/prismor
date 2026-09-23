"""Prismor adapter for the Claude Agent SDK (Python).

Routes every ``PreToolUse`` hook call through
``prismor.runtime.runtime.evaluate_tool_call`` before Claude is allowed to
run the tool — the same policy engine, observe/enforce model, and
per-user attribution as the other adapters.

This is the exact same hooks system the Claude Code CLI itself uses,
exposed programmatically: ``hooks`` on ``ClaudeAgentOptions``, matched via
``HookMatcher(matcher=..., hooks=[cb])`` against a ``PreToolUseHookInput``
(``tool_name``, ``tool_input``). A callback returns a
``SyncHookJSONOutput``/``AsyncHookJSONOutput`` dict; setting
``hookSpecificOutput.permissionDecision`` to ``"deny"`` blocks the tool
call before it runs (overrides even ``bypassPermissions`` permission
mode), mirroring this repo's own CLI-level ``_merge_claude()`` /
``_normalize_claude()`` hook-config dispatch, just invoked in-process
instead of via subprocess.

VERIFICATION NOTE: unlike every other adapter in this repo, this one
cannot be live-verified against an OpenAI-backed agent — the Claude Agent
SDK requires real Anthropic/Claude Code authentication to run at all. It
was instead live-tested on a separate host with an authenticated Claude
Code CLI session. A naive destructive test command (``rm -rf /``, cloud
metadata SSRF) is an unreliable signal here: Claude refuses those on its
own regardless of any hook (confirmed via a zero-hooks baseline run that
also refused). The discriminating test that actually isolates this
adapter's effect is a benign-framed write to ``.claude/settings.json``
(this repo's own ``agent-config-tampering`` policy rule) — Claude
executes it readily with no hook installed, and this adapter denies it
once installed. That test also caught a real bug: an earlier default
``matcher`` regex never matched custom MCP tool names
(``mcp__<server>__<tool>``), so the hook silently never fired for
anything but Claude's own built-in tools — ``matcher`` now defaults to
``None`` (every tool call) for exactly this reason.

RESULT REDACTION: not available here, and not for want of trying — this is
a PreToolUse hook, which is handed the request and answers with a permission
decision. It never carries the tool's output, so unlike the wrapper-style
adapters it cannot repair one (see contract.SURFACES["sdk-adapter"]).

Use::

    from claude_agent_sdk import ClaudeAgentOptions, ClaudeSDKClient
    from prismor.claude_agent_sdk import prismor_hook_matcher

    options = ClaudeAgentOptions(
        hooks={
            "PreToolUse": [prismor_hook_matcher(mode="enforce", subject="user:alice")],
            # optional: the operator's prompt guardrails, added to context
            "UserPromptSubmit": [prismor_prompt_hook_matcher()],
        },
    )
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Union

from prismor.runtime.principal import Subject, resolve_subject
from prismor.runtime.runtime import Decision, evaluate_tool_call

__all__ = ["prismor_hook_matcher", "prismor_pre_tool_use_hook", "prismor_prompt_hook_matcher", "PrismorBlocked"]


class PrismorBlocked(Exception):
    def __init__(self, reason: str, decision: Optional[Decision] = None) -> None:
        super().__init__(reason or "blocked by Prismor policy")
        self.decision = decision


def _normalize(tool_name: str, tool_input: dict) -> dict:
    """Mirrors prismor/runtime/hooks.py::_normalize_claude's tool_name -> event_type mapping."""
    if tool_name == "Bash":
        return {"type": "shell", "command": tool_input.get("command", "")}
    if tool_name == "Read":
        return {"type": "file_read", "path": tool_input.get("file_path") or tool_input.get("path", "")}
    if tool_name in {"Edit", "MultiEdit", "Write"}:
        return {
            "type": "file_write",
            "path": tool_input.get("file_path") or tool_input.get("path", ""),
            "content": tool_input.get("content", "") or tool_input.get("new_string", ""),
        }
    if tool_name in {"WebFetch", "WebSearch"}:
        return {"type": "network", "url": tool_input.get("url", "")}
    # Custom SDK tools (registered via create_sdk_mcp_server / @tool) arrive
    # as "mcp__<server>__<tool>" — Claude's own built-in tool names never
    # collide with that prefix, so a "command" argument on one of these is
    # the same shell-execution intent as the native Bash tool.
    if "command" in tool_input:
        return {"type": "shell", "command": tool_input.get("command", "")}
    return {"type": "tool_result", "response": str(tool_input)}


def prismor_pre_tool_use_hook(
    *,
    subject: Optional[Union[str, Subject]] = None,
    workspace: Optional[Union[str, Path]] = None,
    mode: str = "enforce",
    session_id: Optional[str] = None,
    raise_on_block: bool = False,
):
    """Build a HookCallback for the PreToolUse event.

    Returned callable matches the SDK's HookCallback signature:
    ``async def callback(input_data, tool_use_id, context) -> HookJSONOutput``.
    """
    ws = Path(workspace) if workspace else Path.cwd()
    sid = session_id or f"claude-agent-sdk-{os.getpid()}"

    async def callback(input_data: dict, tool_use_id: Optional[str], context: dict) -> dict:
        tool_name = input_data.get("tool_name", "")
        tool_input = input_data.get("tool_input", {})
        event = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "session_id": sid,
            "agent": "claude-agent-sdk",
            "agent_event": "PreToolUse",
            "metadata": {"tool_name": tool_name, "tool_use_id": tool_use_id, "raw_input": tool_input},
            **_normalize(tool_name, tool_input),
        }
        decision: Decision = evaluate_tool_call(
            event=event, workspace=ws, agent="claude-agent-sdk", mode=mode,
            session_id=sid, subject=resolve_subject(subject),
        )
        if not decision.allow:
            reason = decision.reason or "policy violation"
            if raise_on_block:
                raise PrismorBlocked(reason, decision)
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": f"⛔ Prismor blocked this tool call: {reason}",
                }
            }
        return {}

    return callback


def prismor_hook_matcher(*, matcher: Optional[str] = None, **opts: Any):
    """Convenience: builds a HookMatcher wrapping prismor_pre_tool_use_hook.

    matcher=None (the default) matches every tool call, including custom
    tools registered via create_sdk_mcp_server (which arrive as
    "mcp__<server>__<tool>", not one of Claude's built-in names) — a
    narrower matcher like "Bash|Read|Edit" would silently exempt every
    custom/MCP tool from policy, which defeats the point of a security
    gate. Pass an explicit matcher to scope the hook to specific tools.

    Import-guarded: claude_agent_sdk.HookMatcher is only needed at call
    time so this module itself has no hard dependency on the SDK.
    """
    from claude_agent_sdk import HookMatcher

    return HookMatcher(matcher=matcher, hooks=[prismor_pre_tool_use_hook(**opts)])


def prismor_prompt_hook_matcher(*, workspace: Optional[Union[str, Path]] = None,
                                session_id: Optional[str] = None,
                                agent: str = "claude-agent-sdk"):
    """HookMatcher for UserPromptSubmit that adds the operator's prompt
    guardrails to Claude's context: on the first prompt, and again only when
    they change (a console edit reaches the next prompt). Same contract as the
    Claude Code hook: hookSpecificOutput.additionalContext.
    """
    from claude_agent_sdk import HookMatcher

    ws = Path(workspace) if workspace else Path.cwd()

    async def callback(input_data: dict, tool_use_id: Optional[str], context: dict) -> dict:
        try:
            from prismor.runtime import guardrails
            sid = session_id or str(input_data.get("session_id") or f"claude-agent-sdk-{os.getpid()}")
            text = guardrails.context_for(guardrails.block_now(ws), agent=agent,
                                          session_id=sid, agent_event="UserPromptSubmit")
        except Exception:
            text = None
        if not text:
            return {}
        return {"hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "additionalContext": text}}

    return HookMatcher(matcher=None, hooks=[callback])
