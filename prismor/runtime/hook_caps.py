"""Which model-facing hook outputs each agent's protocol accepts, and in what shape.

The hook dispatcher has three ways to talk to the model rather than just
allow/deny a call: add context at session start, add context next to a tool's
output (post-tool), add context to a prompt, and rewrite a tool call's input
before it runs. These used to be gated on ``agent == "claude"`` in a dozen
places. This table says, per agent, which of them the agent's hook protocol
verifiably supports and how the JSON must look. An agent missing from a column
keeps the old behaviour: findings go to stderr and the audit log only, and a
MODIFY verdict fails closed to DENY.

Only protocol support verified against the agent's own docs or source is
listed (sources in the comments). "Registered" is a separate question: some
agents support an event here that ``install-hooks`` does not yet register for
them (Codex/Qwen/Copilot SessionStart, Gemini BeforeAgent). The entry is then
dormant until the installer starts registering it, never wrong.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import os
from typing import Any, Dict, Mapping, Optional

# Context output shapes.
NESTED = "nested"  # {"hookSpecificOutput": {"hookEventName": <ev>, "additionalContext": ...}}
FLAT = "flat"      # {"additionalContext": ...}

# Input-rewrite output shapes.
REWRITE_CLAUDE = "claude"  # hookSpecificOutput.updatedInput, no decision needed
REWRITE_ALLOW = "allow"    # same, but only honoured next to permissionDecision "allow"
REWRITE_GEMINI = "gemini"  # hookSpecificOutput.tool_input, merged into the call's args

_CANONICAL = ("SessionStart", "PreToolUse", "PostToolUse", "UserPromptSubmit")


@dataclass(frozen=True)
class HookCaps:
    session_context: Optional[str] = None
    post_context: Optional[str] = None
    prompt_context: Optional[str] = None
    input_rewrite: Optional[str] = None
    # Native event name -> canonical name, for agents that don't use Claude's.
    event_aliases: Mapping[str, str] = field(default_factory=dict)
    # Canonical name -> the hookEventName this agent expects back.
    output_names: Mapping[str, str] = field(default_factory=dict)


CAPS: Dict[str, HookCaps] = {
    # https://code.claude.com/docs/en/hooks
    "claude": HookCaps(
        session_context=NESTED, post_context=NESTED, prompt_context=NESTED,
        input_rewrite=REWRITE_CLAUDE,
    ),
    # https://learn.chatgpt.com/docs/hooks and openai/codex
    # codex-rs/hooks/src/engine/output_parser.rs: updatedInput is applied only
    # with permissionDecision "allow" (any other shape is reported as an error,
    # not silently ignored), and a Bash rewrite must carry a string `command`.
    "codex": HookCaps(
        session_context=NESTED, post_context=NESTED, prompt_context=NESTED,
        input_rewrite=REWRITE_ALLOW,
    ),
    # QwenLM/qwen-code docs/users/features/hooks.md: Claude-shaped, but
    # updatedInput replaces the whole input and needs permissionDecision
    # (+ permissionDecisionReason) on PreToolUse output.
    "qwen": HookCaps(
        session_context=NESTED, post_context=NESTED, prompt_context=NESTED,
        input_rewrite=REWRITE_ALLOW,
    ),
    # google-gemini/gemini-cli docs/hooks/reference.md and
    # packages/core/src/hooks/types.ts, core/coreToolHookTriggers.ts:
    # AfterTool additionalContext is appended to the tool result; BeforeTool
    # hookSpecificOutput.tool_input is Object.assign'd over the args and the
    # call is rebuilt (a rewrite that fails validation errors the call).
    "gemini": HookCaps(
        session_context=NESTED, post_context=NESTED, prompt_context=NESTED,
        input_rewrite=REWRITE_GEMINI,
        event_aliases={"BeforeTool": "PreToolUse", "AfterTool": "PostToolUse",
                       "BeforeAgent": "UserPromptSubmit"},
        output_names={"PreToolUse": "BeforeTool", "PostToolUse": "AfterTool",
                      "UserPromptSubmit": "BeforeAgent"},
    ),
    # https://docs.github.com/en/copilot/reference/hooks-configuration:
    # postToolUse/sessionStart take a top-level additionalContext;
    # userPromptSubmitted output is dropped for command hooks. preToolUse
    # documents `modifiedArgs`, but not whether it needs a permissionDecision
    # or applies to the PascalCase events Prismor registers, and an ignored
    # rewrite would let the unmodified call run, so rewrite stays off.
    "copilot": HookCaps(
        session_context=FLAT, post_context=FLAT,
        event_aliases={"preToolUse": "PreToolUse", "postToolUse": "PostToolUse",
                       "sessionStart": "SessionStart"},
    ),
    # xai-org/grok-build crates/codegen/xai-grok-pager/docs/user-guide/10-hooks.md:
    # PostToolUse additionalContext and PreToolUse updatedInput (no decision
    # needed; a rewrite failing the tool schema blocks the call). SessionStart
    # stdout is ignored and an allowing UserPromptSubmit hook's
    # additionalContext is discarded. The camelCase hookEventName key carries
    # grok's snake_case event name.
    "grok": HookCaps(
        post_context=NESTED, input_rewrite=REWRITE_CLAUDE,
        event_aliases={"pre_tool_use": "PreToolUse", "post_tool_use": "PostToolUse",
                       "session_start": "SessionStart",
                       "user_prompt_submit": "UserPromptSubmit"},
    ),
    # Prismor's own OpenCode plugin (hooks._OPENCODE_PLUGIN_JS) reads a
    # top-level additionalContext from the dispatcher's stdout and appends it
    # to the tool's output, which tool.execute.after may mutate
    # (packages/plugin/src/index.ts, session/tools.ts in sst/opencode).
    "opencode": HookCaps(post_context=FLAT),
}

_NONE = HookCaps()


def caps_for(agent: str) -> HookCaps:
    return CAPS.get(str(agent or ""), _NONE)


def canonical_event(agent: str, native: Any) -> str:
    """Claude's name for this agent's hook event ("AfterTool" -> "PostToolUse")."""
    name = str(native or "")
    return caps_for(agent).event_aliases.get(name, name)


_CONTEXT_KIND = {
    "SessionStart": "session_context",
    "PostToolUse": "post_context",
    "UserPromptSubmit": "prompt_context",
}


def supports_context(agent: str, canonical: str) -> bool:
    kind = _CONTEXT_KIND.get(canonical)
    return bool(kind and getattr(caps_for(agent), kind))


def context_output(agent: str, canonical: str, text: str) -> Optional[Dict[str, Any]]:
    """The JSON object that adds ``text`` to the model's context, or None."""
    kind = _CONTEXT_KIND.get(canonical)
    caps = caps_for(agent)
    shape = getattr(caps, kind) if kind else None
    if not shape or not text:
        return None
    if shape == FLAT:
        return {"additionalContext": text}
    return {"hookSpecificOutput": {
        "hookEventName": caps.output_names.get(canonical, canonical),
        "additionalContext": text,
    }}


# Agents that show a hook's top-level ``systemMessage`` to the PERSON in the
# chat (as opposed to additionalContext, which only the model reads).
_USER_MESSAGE_AGENTS = frozenset({"claude"})


def add_user_message(agent: str, output: Optional[Dict[str, Any]], message: str) -> Optional[Dict[str, Any]]:
    """Attach a short human-facing line to a hook output, where the agent can
    show one. Agent context alone left people unaware Prismor had acted."""
    if not message or agent not in _USER_MESSAGE_AGENTS:
        return output
    out = dict(output or {})
    out["systemMessage"] = message
    return out


def _rewrite_mode(caps: "HookCaps") -> Optional[str]:
    # REWRITE_ALLOW agents only take a rewrite next to permissionDecision
    # "allow", which also skips the agent's own approval prompt for the call.
    # Keep that opt-in; by default MODIFY fails closed to DENY on them.
    if caps.input_rewrite == REWRITE_ALLOW and os.environ.get("PRISMOR_REWRITE_AUTO_APPROVE") != "1":
        return None
    return caps.input_rewrite


def supports_rewrite(agent: str) -> bool:
    return bool(_rewrite_mode(caps_for(agent)))


def rewrite_output(agent: str, claude_update: Optional[Dict[str, Any]],
                   reason: str = "") -> Optional[Dict[str, Any]]:
    """Translate a transform's Claude-shaped ``updatedInput`` output for ``agent``.

    Transforms (and the sandbox) return Claude hook JSON. Returns None when the
    agent cannot rewrite input or the transform declined, so the caller fails
    closed exactly as before.
    """
    caps = caps_for(agent)
    mode = _rewrite_mode(caps)
    if not mode or not isinstance(claude_update, dict):
        return None
    hso = claude_update.get("hookSpecificOutput") or {}
    new_input = hso.get("updatedInput")
    if not isinstance(new_input, dict):
        return None
    if mode == REWRITE_CLAUDE:
        return claude_update
    if mode == REWRITE_GEMINI:
        return {"hookSpecificOutput": {
            "hookEventName": caps.output_names.get("PreToolUse", "PreToolUse"),
            "tool_input": new_input,
        }}
    return {"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "allow",
        "permissionDecisionReason": reason or "Rewritten by Prismor policy",
        "updatedInput": new_input,
    }}


def transform_payload(agent: str, payload: Dict[str, Any], event: Dict[str, Any]) -> Dict[str, Any]:
    """The hook payload in the Claude shape the transforms are written against.

    Transforms read ``tool_input`` and the sandbox only wraps ``tool_name ==
    "Bash"``. Other agents name their shell tool differently
    (``run_shell_command``, ``run_terminal_command``) or send ``toolInput``;
    the normalizer has already decided this event is a shell call, so present
    it as one. Claude's payload is returned untouched.
    """
    if agent == "claude":
        return payload
    out = dict(payload)
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        tool_input = payload.get("toolInput")
    if isinstance(tool_input, dict):
        out["tool_input"] = tool_input
    if event.get("type") == "shell" and isinstance((out.get("tool_input") or {}).get("command"), str):
        out["tool_name"] = "Bash"
    return out
