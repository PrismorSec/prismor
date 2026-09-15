"""Best-effort token-usage accounting, fed by data already in the hook payload.

Two independent signals, since neither alone answers "where are my tokens
going":

- Real per-turn usage (input/output/cache tokens) is only available for
  Claude Code, via the ``transcript_path`` every hook payload carries — the
  transcript JSONL records the Anthropic API's ``usage`` object per assistant
  turn. This gives exact totals and a cache-hit rate. Other agents' hook
  payloads carry no pointer to their transcript, so no real usage for them.
- Tool-output size is a proxy for context cost that works for every agent
  (claude, codex, copilot, cursor, ...), because the tool result is already
  sitting in the normalized event with no extra data source needed. This
  answers "which tool call / file / command is actually bloating the
  conversation." Recorded on post events only — pre events carry the same
  content (e.g. the text of a Write) and would double-count it.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from prismor.runtime import store
from prismor.runtime.hooks import _is_pre_action
from prismor.runtime.pricing import cost_usd, normalize_model

_TAIL_BYTES = 32_000
_LABEL_MAX = 200


def _tail_lines(path: str, tail_bytes: int = _TAIL_BYTES) -> List[str]:
    """Read the last ``tail_bytes`` of a file as lines.

    Transcripts grow unbounded over a long session; the usage entry we want
    is always near the end, so tailing avoids re-reading the whole file on
    every tool call.
    """
    try:
        with open(path, "rb") as fh:
            fh.seek(0, 2)
            size = fh.tell()
            fh.seek(max(0, size - tail_bytes))
            chunk = fh.read()
    except OSError:
        return []
    return chunk.decode("utf-8", errors="ignore").splitlines()


def _claude_usage(entry: Any) -> Optional[Dict[str, Any]]:
    """One transcript line -> usage row, or None when the line carries none."""
    message = entry.get("message") if isinstance(entry, dict) else None
    if not isinstance(message, dict):
        return None
    usage = message.get("usage")
    if not isinstance(usage, dict):
        return None
    creation = usage.get("cache_creation") or {}
    if not any(usage.get(k) for k in ("input_tokens", "output_tokens", "cache_read_input_tokens", "cache_creation_input_tokens")):
        return None  # Claude Code's "<synthetic>" placeholder turns carry zero usage
    return {
        "message_id": message.get("id") or "",
        "model": message.get("model") or "",
        "ts": entry.get("timestamp") or "",
        "input_tokens": usage.get("input_tokens") or 0,
        "output_tokens": usage.get("output_tokens") or 0,
        "cache_read_tokens": usage.get("cache_read_input_tokens") or 0,
        "cache_creation_tokens": usage.get("cache_creation_input_tokens") or 0,
        "cache_1h_tokens": creation.get("ephemeral_1h_input_tokens") or 0,
    }


def _last_usage(transcript_path: str) -> Optional[Dict[str, Any]]:
    """Return the most recent assistant turn's real token usage, or None."""
    for line in reversed(_tail_lines(transcript_path)):
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        usage = _claude_usage(entry)
        if usage:
            usage.pop("ts")
            return usage
    return None


def _iter_codex_usage(path: Path, session_id: str) -> Iterator[Dict[str, Any]]:
    """Codex rollouts log cumulative ``token_count`` envelopes; yield per-turn
    deltas (``last_token_usage`` when the total advanced, else total - previous),
    the way ccusage reads them. The model comes from the preceding turn_context."""
    model, previous = "", None
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for n, line in enumerate(fh):
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            payload = rec.get("payload") if isinstance(rec, dict) else None
            if not isinstance(payload, dict):
                continue
            if rec.get("type") == "turn_context" and payload.get("model"):
                model = payload["model"]
                continue
            if rec.get("type") != "event_msg" or payload.get("type") != "token_count":
                continue
            info = payload.get("info") or {}
            total, last = info.get("total_token_usage"), info.get("last_token_usage")
            if not isinstance(total, dict) or total == previous:
                continue
            delta = last if isinstance(last, dict) else {
                k: int(total.get(k) or 0) - int((previous or {}).get(k) or 0) for k in total
            }
            previous = total
            cached = int(delta.get("cached_input_tokens") or 0)
            row = {
                "message_id": f"{session_id}:{n}",
                "model": model,
                "ts": rec.get("timestamp") or "",
                # Codex counts cached tokens inside input_tokens; Claude's shape keeps them apart.
                "input_tokens": max(0, int(delta.get("input_tokens") or 0) - cached),
                "output_tokens": int(delta.get("output_tokens") or 0),
                "cache_read_tokens": cached,
                "cache_creation_tokens": int(delta.get("cache_write_input_tokens") or 0),
                "cache_1h_tokens": 0,
            }
            if any(row[k] for k in ("input_tokens", "output_tokens", "cache_read_tokens", "cache_creation_tokens")):
                yield row


def _iter_claude_usage(path: Path) -> Iterator[Dict[str, Any]]:
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            try:
                usage = _claude_usage(json.loads(line))
            except ValueError:
                continue
            if usage and usage["message_id"]:
                yield usage


def _provider(model: str) -> str:
    m = normalize_model(model)
    if m.startswith("claude"):
        return "anthropic"
    if m.startswith(("gpt", "o1", "o3", "o4", "codex")):
        return "openai"
    if m.startswith("gemini"):
        return "google"
    return "unknown"


def _record(workspace: Path, session_id: str, agent: str, row: Dict[str, Any]) -> None:
    """Store one turn; when new and the device is enrolled, also spool an
    ``llm_usage`` telemetry record (same shape the LLM gateway lane emits) so
    the control plane can show tokens and spend per session. It rides the
    heartbeat's next flush, never a request of its own."""
    if not store.record_token_usage(workspace=workspace, session_id=session_id, **row):
        return
    try:
        from prismor.runtime.enterprise import identity as _identity, telemetry_spool as _spool
        if not _identity.is_enrolled():
            return
        cache_5m = row["cache_creation_tokens"] - row["cache_1h_tokens"]
        tokens = {"input": row["input_tokens"], "output": row["output_tokens"], "cache_read": row["cache_read_tokens"],
                  "cache_5m": cache_5m, "cache_1h": row["cache_1h_tokens"]}
        provider = _provider(row["model"])
        _spool.append([{
            "schema": "prismor.runtime.telemetry.v1",
            "event_id": "evt_usage_" + row["message_id"].replace(":", "_"),  # deterministic: safe to resend
            "ts": row.get("ts") or "",
            "type": "llm_usage",
            "verdict": "observed",
            "title": "Model turn metered",
            "agent": agent,
            "session_id": session_id,
            "provider": provider,
            "model": row["model"],
            "tool_name": f"llm__{provider}__{row['model'] or 'unknown'}",
            "usage": {
                "model": row["model"], "input_tokens": row["input_tokens"], "output_tokens": row["output_tokens"],
                "cache_read_tokens": row["cache_read_tokens"], "cache_write_tokens": row["cache_creation_tokens"],
                "cache_1h_tokens": row["cache_1h_tokens"],
            },
            "cost_usd": cost_usd(tokens, row["model"], fetch=False),
            "redacted": True,
        }])
    except Exception:
        pass


def find_transcript(session_id: str) -> Optional[Path]:
    """Claude Code names the transcript after the session id; Codex puts it at
    the end of the rollout filename. Both ids are what the hooks hand us."""
    if not session_id or "/" in session_id:
        return None
    claude = Path.home() / ".claude" / "projects"
    codex = Path(os.environ.get("CODEX_HOME") or Path.home() / ".codex") / "sessions"
    for root, pattern in ((claude, f"*/{session_id}.jsonl"), (codex, f"**/rollout-*-{session_id}.jsonl")):
        try:
            return next(root.glob(pattern))
        except (StopIteration, OSError):
            continue
    return None


def backfill_session(workspace: Path, session_id: str, transcript_path: Optional[str] = None, agent: str = "") -> bool:
    """Scan the whole transcript once and store every turn (INSERT OR IGNORE
    dedupes on message id). Returns False when no transcript is on this
    machine. This is how turns after the last tool call get counted: Claude
    Code has no Stop hook installed (see hooks.py)."""
    path = Path(transcript_path) if transcript_path else find_transcript(session_id)
    if path is None or not path.is_file():
        return False
    codex = path.name.startswith("rollout-")
    rows = _iter_codex_usage(path, session_id) if codex else _iter_claude_usage(path)
    try:
        for row in rows:
            _record(workspace, session_id, agent or ("codex" if codex else "claude"), row)
    except OSError:
        return False
    return True


def sessions_cost(workspace: Path, session_ids: List[str], backfill: bool = True) -> Dict[str, Dict[str, Any]]:
    """{session_id: {known, priced, usd, tokens, by_model, unpriced, turns}}.

    ``known`` False = no usage rows and no transcript (agent we can't meter);
    ``priced`` False = usage exists but no model matched the price table.
    Never conflate either with $0.00."""
    if backfill:
        for sid in session_ids:
            backfill_session(workspace, sid)
    usage = store.get_sessions_token_usage(session_ids)
    out: Dict[str, Dict[str, Any]] = {}
    for sid in session_ids:
        entry = usage.get(sid)
        if not entry:
            out[sid] = {"known": False, "priced": False, "usd": None}
            continue
        total, unpriced, tokens = 0.0, [], {"input": 0, "output": 0, "cache_read": 0, "cache_5m": 0, "cache_1h": 0}
        for model, t in entry["by_model"].items():
            for k in tokens:
                tokens[k] += t[k]
            usd = cost_usd(t, model)
            if usd is None:
                unpriced.append(model)
            else:
                total += usd
        priced = len(unpriced) < len(entry["by_model"])
        out[sid] = {
            "known": True, "priced": priced, "usd": total if priced else None,
            "tokens": tokens, "by_model": entry["by_model"], "unpriced": unpriced, "turns": entry["turns"],
        }
    return out


def session_cost(workspace: Path, session_id: str) -> Dict[str, Any]:
    return sessions_cost(workspace, [session_id])[session_id]


def _output_size(event: Dict[str, Any]) -> int:
    raw = (event.get("metadata") or {}).get("raw") or {}
    # Response key varies by agent: claude/codex use tool_response, copilot
    # toolResult, cursor output/stdout. Typed-event fields are the fallback.
    payload = (
        raw.get("tool_response") or raw.get("toolResult") or raw.get("tool_result")
        or raw.get("response") or raw.get("output") or raw.get("stdout")
        or event.get("response") or event.get("stdout") or event.get("content") or ""
    )
    if not isinstance(payload, str):
        try:
            payload = json.dumps(payload)
        except (TypeError, ValueError):
            payload = str(payload)
    return len(payload)


def record_from_event(*, workspace: Path, session_id: str, agent: str, event: Dict[str, Any]) -> None:
    """Called on every hook dispatch. Never raises — callers treat this as
    best-effort."""
    agent_event = str(event.get("agent_event", ""))
    metadata = event.get("metadata") or {}
    ts = event.get("ts") or ""

    transcript_path = (metadata.get("raw") or {}).get("transcript_path")
    if transcript_path and agent_event == "PostToolUse" and agent == "claude":
        usage = _last_usage(transcript_path)
        if usage:
            _record(workspace, session_id, agent, {"ts": ts, **usage})
    elif transcript_path and agent_event == "SessionStart":
        # A resumed session's transcript may hold turns no hook ever saw.
        backfill_session(workspace, session_id, transcript_path, agent=agent)

    if _is_pre_action(agent_event):
        return
    # Cursor's normalizer has no tool_name; its event type (shell/file_write/…)
    # is the closest equivalent. Prompt and memory events aren't tool output.
    tool_name = metadata.get("tool_name") or event.get("type") or ""
    if tool_name in ("", "prompt", "memory"):
        return
    size = _output_size(event)
    if size > 0:
        store.record_tool_output_size(
            workspace=workspace,
            session_id=session_id,
            ts=ts,
            agent=agent,
            tool_name=tool_name,
            label=str(event.get("path") or event.get("command") or event.get("url") or "")[:_LABEL_MAX],
            size_chars=size,
        )
