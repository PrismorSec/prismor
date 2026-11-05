"""What the model said back: one ``assistant_response`` event per turn.

Every hooked agent already hands its hooks the final reply of a turn (Claude
and Codex ``Stop.last_assistant_message``, Cursor ``afterAgentResponse.text``,
Gemini ``AfterAgent.prompt_response``, Windsurf ``post_cascade_response``), but
Prismor recorded prompts and tool calls only, so a session trail showed what
the agent did and never what it told the person. Copilot CLI is the exception:
no hook carries the reply, so it is read from the session's ``events.jsonl``.

Reasoning is best effort. Only Cursor sends it on a hook
(``afterAgentThought``); for Claude, Codex and Copilot it is read from the tail
of the agent's own transcript, from the turn's start to its end.

Replies are recorded in observe mode and never answered: a non-zero exit or a
decision on Claude ``Stop`` or Gemini ``AfterAgent`` makes the agent keep
going, which is the opposite of recording what it said.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

#: Characters of reply (same cap as tool output) and of reasoning kept per
#: event. Together they stay under the console's 16 KB detail limit, past which
#: the whole detail is dropped (prismor-web lib/telemetry-scrub.ts).
_TEXT_LIMIT = 8000
_REASONING_LIMIT = 4000
#: Bytes of transcript read back from the end to find this turn's reasoning.
# ponytail: tail window, so reasoning older than the last 512 KB of a very long
# turn is dropped; keeping a read offset per session lifts that.
_TAIL_BYTES = 512_000

#: The hook event that carries the turn's reply, per agent.
REPLY_EVENTS: Dict[str, frozenset] = {
    "claude": frozenset({"Stop", "StopFailure"}),
    "codex": frozenset({"Stop"}),
    "cursor": frozenset({"afterAgentResponse", "afterAgentThought"}),
    "gemini": frozenset({"AfterAgent"}),
    "windsurf": frozenset({"post_cascade_response"}),
    # PascalCase Stop is Claude-shaped (hook_event_name, transcript_path to
    # events.jsonl) but has no reply text; camelCase agentStop names no event.
    "copilot": frozenset({"Stop"}),
}


def _event_name(agent: str, payload: Dict[str, Any]) -> str:
    if agent == "windsurf":
        return str(payload.get("agent_action_name") or "")
    return str(payload.get("hook_event_name") or payload.get("hookEventName") or "")


def is_reply(agent: str, payload: Dict[str, Any]) -> bool:
    return _event_name(agent, payload) in REPLY_EVENTS.get(agent, ())


def _tail_rows(path: str) -> List[Dict[str, Any]]:
    """The JSON rows in the last ``_TAIL_BYTES`` of a JSONL file; [] on any error."""
    try:
        p = Path(os.path.expanduser(path))
        size = p.stat().st_size
        with p.open("rb") as fh:
            fh.seek(max(0, size - _TAIL_BYTES))
            chunk = fh.read()
    except (OSError, TypeError, ValueError):
        return []
    lines = chunk.decode("utf-8", errors="replace").split("\n")
    if size > _TAIL_BYTES:
        lines = lines[1:]  # first line is cut mid-row
    rows = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


def _after_last(rows: List[Dict[str, Any]], is_start) -> List[Dict[str, Any]]:
    """Rows after the last one ``is_start`` matches (all rows when none does)."""
    for i in range(len(rows) - 1, -1, -1):
        if is_start(rows[i]):
            return rows[i + 1:]
    return rows


def _claude_turn_start(row: Dict[str, Any]) -> bool:
    # A person's prompt, not a tool result (also a "user" row) or harness meta.
    # Hook feedback is meta but still starts a turn (attribution.stop_hook_trigger).
    if row.get("type") != "user" or row.get("toolUseResult") is not None:
        return False
    if row.get("isMeta"):
        from prismor.runtime.attribution import stop_hook_trigger
        return stop_hook_trigger([row]) is not None
    content = (row.get("message") or {}).get("content")
    if isinstance(content, str):
        return bool(content.strip())
    return isinstance(content, list) and any(
        isinstance(b, dict) and b.get("type") == "text" for b in content)


def _claude_reasoning(rows: List[Dict[str, Any]]) -> Iterable[str]:
    for row in _after_last(rows, _claude_turn_start):
        if row.get("type") != "assistant" or row.get("isSidechain"):
            continue
        for block in (row.get("message") or {}).get("content") or []:
            # Claude Code often keeps only the signature; an empty block is skipped.
            if isinstance(block, dict) and block.get("type") == "thinking":
                yield str(block.get("thinking") or "")


def _codex_reasoning(rows: List[Dict[str, Any]]) -> Iterable[str]:
    def start(row: Dict[str, Any]) -> bool:
        return row.get("type") == "event_msg" and (row.get("payload") or {}).get("type") == "task_started"

    for row in _after_last(rows, start):
        p = row.get("payload") or {}
        if row.get("type") == "response_item" and p.get("type") == "reasoning":
            # The readable half is the summary; encrypted_content is not.
            for part in p.get("summary") or []:
                if isinstance(part, dict):
                    yield str(part.get("text") or "")


def _copilot_events(payload: Dict[str, Any], session_id: str) -> str:
    path = payload.get("transcriptPath") or payload.get("transcript_path")
    if path:
        return str(path)
    home = Path(os.environ.get("COPILOT_HOME") or Path.home() / ".copilot")
    return str(home / "session-state" / session_id / "events.jsonl")


def _copilot_turn(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Reply, reasoning and output tokens of the last turn in a Copilot events.jsonl."""
    reply, reasoning, tokens, model = "", [], 0, ""
    for row in _after_last(rows, lambda r: r.get("type") == "user.message"):
        data = row.get("data") if isinstance(row.get("data"), dict) else {}
        if row.get("type") == "assistant.message":
            # One message per model call; the last one with text is the answer.
            if str(data.get("content") or "").strip():
                reply = str(data["content"])
            reasoning.append(str(data.get("reasoningText") or ""))
            if isinstance(data.get("outputTokens"), int):
                tokens += data["outputTokens"]
            if data.get("model"):  # 1.0.90+; older builds name it on tool rows only
                model = str(data["model"])
        elif row.get("type") == "tool.execution_complete" and data.get("model") and not model:
            model = str(data["model"])
    return {"reply": reply, "reasoning": reasoning, "output_tokens": tokens, "model": model}


def _join(parts: Iterable[str]) -> str:
    return "\n\n".join(p.strip() for p in parts if p and p.strip())


def reply_event(agent: str, payload: Dict[str, Any], session_id: str) -> Dict[str, Any]:
    """The ``assistant_response`` event for a reply hook payload."""
    name = _event_name(agent, payload)
    transcript = str(payload.get("transcript_path") or "")
    meta: Dict[str, Any] = {}
    reply, reasoning = "", ""

    if agent in ("claude", "codex"):
        reply = str(payload.get("last_assistant_message") or "")
        rows = _tail_rows(transcript) if transcript else []
        reasoning = _join(_claude_reasoning(rows) if agent == "claude" else _codex_reasoning(rows))
        # A Stop hook that exited 2 started this turn; nobody typed a prompt.
        if agent == "claude" and payload.get("stop_hook_active"):
            from prismor.runtime.attribution import stop_hook_trigger
            meta["triggered_by"] = stop_hook_trigger(rows) or {"event": "Stop", "hook": ""}
        if name == "StopFailure":
            meta["error"] = True  # the field holds the API error text, not a reply
    elif agent == "cursor":
        if name == "afterAgentThought":
            reasoning = str(payload.get("text") or "")
            if payload.get("duration_ms") is not None:
                meta["duration_ms"] = payload.get("duration_ms")
        else:
            reply = str(payload.get("text") or "")
        meta["generation_id"] = payload.get("generation_id")
    elif agent == "gemini":
        reply = str(payload.get("prompt_response") or "")
    elif agent == "windsurf":
        info = payload.get("tool_info") if isinstance(payload.get("tool_info"), dict) else {}
        reply = str(info.get("response") or "")
        meta["execution_id"] = payload.get("execution_id")
    elif agent == "copilot":
        reply = str(payload.get("last_assistant_message") or "")
        turn = _copilot_turn(_tail_rows(_copilot_events(payload, session_id)))
        reply = reply or turn["reply"]
        reasoning = _join(turn["reasoning"])
        if turn["output_tokens"]:
            meta["output_tokens"] = turn["output_tokens"]
        if turn["model"]:
            meta["model"] = turn["model"]

    model = payload.get("model_id") or payload.get("model")
    if isinstance(model, str) and model:
        meta["model"] = model
    meta.update({
        "response_chars": len(reply),
        "reasoning_chars": len(reasoning),
        "truncated": len(reply) > _TEXT_LIMIT or len(reasoning) > _REASONING_LIMIT,
        "cwd": payload.get("cwd"),
        "raw": {k: v for k, v in payload.items()
                if k not in ("last_assistant_message", "prompt_response", "text", "tool_info")},
    })
    event: Dict[str, Any] = {
        "ts": payload.get("timestamp") or datetime.now(timezone.utc).isoformat(),
        "session_id": session_id,
        "agent": agent,
        "agent_event": name,
        "type": "assistant_response",
        "response": reply[:_TEXT_LIMIT],
        "metadata": {k: v for k, v in meta.items() if v not in (None, "")},
    }
    if reasoning:
        event["reasoning"] = reasoning[:_REASONING_LIMIT]
    return event
