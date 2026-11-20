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
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from prismor.runtime import store
from prismor.runtime.hooks import _is_pre_action
from prismor.runtime.pricing import cost_usd, normalize_model, price_for, request_cost

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
                # Already inside output_tokens; reported, never billed twice.
                "reasoning_tokens": int(delta.get("reasoning_output_tokens") or 0),
            }
            if any(row[k] for k in ("input_tokens", "output_tokens", "cache_read_tokens", "cache_creation_tokens")):
                yield row


_BUCKETS = ("input_tokens", "output_tokens", "cache_read_tokens", "cache_creation_tokens", "cache_1h_tokens")


def _iter_claude_usage(path: Path) -> Iterator[Dict[str, Any]]:
    """One row per message id. A response spans one line per content block;
    in subagent transcripts output_tokens keeps growing across those lines,
    so take each bucket's max rather than the first line."""
    turns: Dict[str, Dict[str, Any]] = {}
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            try:
                usage = _claude_usage(json.loads(line))
            except ValueError:
                continue
            if not usage or not usage["message_id"]:
                continue
            seen = turns.setdefault(usage["message_id"], usage)
            for k in _BUCKETS:
                seen[k] = max(seen[k], usage[k])
    yield from turns.values()


def _provider(model: str) -> str:
    m = normalize_model(model)
    if m.startswith("claude"):
        return "anthropic"
    if m.startswith(("gpt", "o1", "o3", "o4", "codex")):
        return "openai"
    if m.startswith("gemini"):
        return "google"
    return "unknown"


def _record(workspace: Path, session_id: str, agent: str, row: Dict[str, Any],
            agent_name: str = "") -> None:
    _record_many(workspace, session_id, agent, [row], agent_name)


def _record_many(workspace: Path, session_id: str, agent: str, rows: List[Dict[str, Any]],
                 agent_name: str = "") -> None:
    """Store turns in one write; for each new or grown one, when the device is
    enrolled, also spool an ``llm_usage`` telemetry record (same shape the LLM
    gateway lane emits) so the control plane can show tokens and spend per
    session. It rides the heartbeat's next flush, never a request of its own."""
    reasoning = [int(r.get("reasoning_tokens") or 0) for r in rows]
    # not a store column; `agent` attributes the turn for per-agent budgets
    rows = [{**{k: v for k, v in r.items() if k != "reasoning_tokens"},
             "agent": r.get("agent") or agent_name or agent} for r in rows]
    changed = store.record_token_usages(workspace, session_id, rows)
    last_new = max((i for i, new in enumerate(changed) if new), default=-1)
    for i, (row, r_tokens, new) in enumerate(zip(rows, reasoning, changed)):
        if new:
            _spool_usage(session_id, agent, row, r_tokens, agent_name, with_context=i == last_new)
    if last_new >= 0:
        # Usage only reaches the spool; the heartbeat tick is what uploads it,
        # and runtime.py runs that tick for managed workspaces only. Without
        # this, an unmanaged workspace's usage sat in the spool until it hit
        # the cap and dropped. Debounced to once a minute; no-op unenrolled.
        try:
            from prismor.runtime.enterprise import heartbeat
            heartbeat.maybe_flush()
        except Exception:
            pass


_CONTEXT_EVERY_S = 60


def _wire_context(session_id: str) -> Optional[Dict[str, Any]]:
    """The session's context breakdown for the control plane, at most once a
    minute per session: part totals and the names of the largest items, never
    their content (no prompt text, commands or tool output)."""
    try:
        stamp = store.prismor_home() / "context-sent" / session_id
        if "/" in session_id or (stamp.exists() and datetime.now().timestamp() - stamp.stat().st_mtime < _CONTEXT_EVERY_S):
            return None
        ctx = session_context(session_id)
        if not ctx.get("known"):
            return None
        stamp.parent.mkdir(parents=True, exist_ok=True)
        stamp.touch()
        home = str(Path.home())
        name = lambda n: "~" + n[len(home):] if n.startswith(home + "/") else n
        return {**{k: ctx.get(k) for k in ("used", "limit", "limit_source", "compact_at", "first", "turns",
                                           "estimated", "model", "models", "compactions")},
                # Subagents by id, type and size: their task description is model-written content, so it stays local.
                "subagents": [{k: sa.get(k) for k in ("id", "type", "model", "used", "peak", "limit", "turns")}
                              for sa in (ctx.get("subagents") or [])[:20]],
                "parts": [{"key": p["key"], "label": p["label"], "tokens": p["tokens"], "count": p.get("count", 0),
                           "items": [{"name": name(i["name"])[:120], "tokens": i["tokens"]} for i in (p.get("items") or [])[:10]]}
                          for p in ctx["parts"]]}
    except Exception:
        return None


def _spool_usage(session_id: str, agent: str, row: Dict[str, Any], reasoning: int,
                 agent_name: str = "", with_context: bool = False) -> None:
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
            # The instance label (proxy --agent-name): without it every metered
            # turn surfaced in the console as a second, unnamed agent (#543).
            "agent_name": agent_name or None,
            "session_id": session_id,
            "provider": provider,
            "model": row["model"],
            "tool_name": f"llm__{provider}__{row['model'] or 'unknown'}",
            "usage": {
                "model": row["model"], "input_tokens": row["input_tokens"], "output_tokens": row["output_tokens"],
                "cache_read_tokens": row["cache_read_tokens"], "cache_write_tokens": row["cache_creation_tokens"],
                "cache_1h_tokens": row["cache_1h_tokens"], "reasoning_tokens": reasoning,
            },
            "cost_usd": (row["reported_cost_usd"] if row.get("reported_cost_usd") is not None
                         else cost_usd(tokens, row["model"], fetch=False)),
            "redacted": True,
            **({"context": ctx} if with_context and (ctx := _wire_context(session_id)) else {}),
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
    # Claude Code writes each subagent's turns to <session>/subagents/agent-*.jsonl,
    # never to the main transcript: a quarter of a subagent-heavy session's tokens.
    files = [path] if codex else [path, *sorted(path.with_suffix("").glob("subagents/agent-*.jsonl"))]
    try:
        for f in files:
            st = f.stat()
            stamp = (st.st_mtime_ns, st.st_size)
            if _scanned.get(f) == stamp:
                continue  # unchanged since the last scan in this process
            rows = _iter_codex_usage(f, session_id) if codex else _iter_claude_usage(f)
            _record_many(workspace, session_id, agent or ("codex" if codex else "claude"), list(rows))
            _scanned[f] = stamp
    except OSError:
        return False
    return True


# ponytail: per-process memo, so a long-running dashboard rescans only files that changed.
_scanned: Dict[Path, tuple] = {}


def _price_requests(model: str, requests: List[Dict[str, Any]]) -> tuple:
    """(usd or None, source). A provider-reported cost (OpenRouter's
    ``usage.cost``) is what was charged and wins; other requests are priced at
    the model's list rate, each at its own long-context tier. ``source`` is
    reported, openrouter, litellm, override, snapshot, or mixed."""
    rate = price_for(model)
    usd, sources = 0.0, set()
    for r in requests:
        if r.get("reported") is not None:
            usd += float(r["reported"])
            sources.add("reported")
        elif rate is not None:
            usd += request_cost(r, rate)
            sources.add(rate.get("source") or "list")
    if not sources:
        return None, None
    return usd, sources.pop() if len(sources) == 1 else "mixed"


def token_stats(workspace: Optional[Path] = None, hours: int = 24) -> Dict[str, Any]:
    """``store.get_token_stats`` after backfilling every session active in the
    window. Hooks record only the turn before each tool call, so without this
    the totals run 10-20% behind the transcripts and miss subagents entirely."""
    for sid, ws in store.get_active_sessions(hours):
        backfill_session(Path(ws) if ws else (workspace or Path.cwd()), sid)
    stats = store.get_token_stats(workspace, hours=hours)
    by_model, total, unpriced = [], 0.0, []
    for model, requests in store.get_window_token_requests(hours, workspace).items():
        usd, source = _price_requests(model, requests)
        if usd is None:
            unpriced.append(model)
        else:
            total += usd
        sums = {k: sum(r[k] for r in requests) for k in ("input", "output", "cache_read", "cache_5m", "cache_1h")}
        by_model.append({"model": model, "turns": len(requests), "usd": usd, "source": source, **sums})
    by_model.sort(key=lambda m: -(m["usd"] or 0))
    # None, not $0, when nothing could be priced: "unknown" must not read as free.
    stats.update(byModel=by_model, unpriced=unpriced,
                 usd=total if len(unpriced) < len(by_model) else None,
                 turns=sum(m["turns"] for m in by_model))
    return stats


def sessions_cost(workspace: Path, session_ids: List[str], backfill: bool = True) -> Dict[str, Dict[str, Any]]:
    """{session_id: {known, priced, usd, tokens, by_model, cost_by_model, unpriced, turns}}.

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
        total, unpriced, cost_by_model, sources = 0.0, [], {}, set()
        tokens = {"input": 0, "output": 0, "cache_read": 0, "cache_5m": 0, "cache_1h": 0}
        for model, t in entry["by_model"].items():
            for k in tokens:
                tokens[k] += t[k]
            # Priced per request at today's rates: long-context tiers depend on
            # each request's size, and a price refresh corrects history too.
            usd, source = _price_requests(model, entry["requests"][model])
            cost_by_model[model] = usd
            if source:
                sources.add(source)
            if usd is None:
                unpriced.append(model)
            else:
                total += usd
        priced = len(unpriced) < len(entry["by_model"])
        out[sid] = {
            "known": True, "priced": priced, "usd": total if priced else None,
            "tokens": tokens, "by_model": entry["by_model"], "cost_by_model": cost_by_model,
            "unpriced": unpriced, "turns": entry["turns"],
            "source": (sources.pop() if len(sources) == 1 else "mixed") if sources else None,
        }
    return out


def session_cost(workspace: Path, session_id: str) -> Dict[str, Any]:
    return sessions_cost(workspace, [session_id])[session_id]


# ponytail: 4 chars/token for the overhead split, then capped to the measured
# first-turn size; a real tokenizer would only move the estimated rows.
_CHARS_PER_TOKEN = 4
_CONTEXT_LABELS = {  # display order
    "messages": "Messages", "mcp_tools": "MCP tools", "system_tools": "System tools",
    "system_prompt": "System prompt", "skills": "Skills", "memory": "Memory files",
    "mcp_instructions": "MCP server instructions", "agents": "Custom agents", "overhead": "Fixed overhead",
}


_DEFAULT_WINDOW = 200_000
_TIERS = (200_000, 272_000, 400_000, 1_000_000, 2_000_000)


def _context_window(model: str, peak: int, compact_at: int = 0) -> tuple:
    """(limit, source) for the model the session runs now, most authoritative
    first: what the agent itself compacts at (the limit its own panel shows);
    the model's input window from the price feed; a ``[1m]`` id; and never
    below a size a turn already reached (the window must have held it)."""
    if compact_at:
        return compact_at, "agent setting"
    window, source = 0, ""
    if "[1m]" in model:
        window, source = 1_000_000, "model id"
    else:
        try:
            rate = price_for(model, fetch=False) or {}
            window, source = int(rate.get("max_input_tokens") or 0), "model card"
        except Exception:
            window = 0
    if not window:
        window, source = _DEFAULT_WINDOW, "default"
    if peak > window:  # the turn fit, so the window is at least the next tier up
        window, source = next((t for t in _TIERS if t >= peak), peak), "observed"
    return window, source


def _claude_compact_at(model: str) -> int:
    """Claude Code's ``autoCompactWindow`` user setting (per model under
    ``modelSettings``, else top level): the size it compacts at, and the limit
    its own context panel shows. 0 when unset."""
    home = Path(os.environ.get("CLAUDE_CONFIG_DIR") or Path.home() / ".claude")
    try:
        cfg = json.loads((home / "settings.json").read_text(encoding="utf-8"))
        per_model = (cfg.get("modelSettings") or {}).get(model) or {}
        return int(per_model.get("autoCompactWindow") or cfg.get("autoCompactWindow") or 0)
    except (OSError, ValueError, TypeError, AttributeError):
        return 0


_ITEMS_MAX = 40


def _short(text: Any, n: int = 80) -> str:
    text = " ".join(str(text or "").split())
    return text if len(text) <= n else text[: n - 1] + "…"


_IMAGE_CHARS = 1600 * _CHARS_PER_TOKEN  # ponytail: a typical screenshot's tokens, not its base64 length


def _block_chars(block: Any) -> int:
    if isinstance(block, str):
        return len(block)
    if isinstance(block, list):
        return sum(_block_chars(b) for b in block)
    if isinstance(block, dict) and block.get("type") == "image":
        return _IMAGE_CHARS
    if isinstance(block, dict) and block.get("type") == "text":
        return len(block.get("text") or "")
    return len(json.dumps(block, ensure_ascii=False))


def _claude_context(path: Path, sidechain: bool = False) -> Dict[str, Any]:
    """Live context of a Claude Code session. used/limit/messages are measured
    (the API's own input token counts); the overhead split is sized from the
    system prompt, tool schemas, memory files and skill list the transcript
    records, and scaled so the parts add up to the measured first turn.
    Each part also lists what it holds (``items``), largest first."""
    first = last = peak = 0
    calib = 0          # first turn after the latest system prompt / tool set
    compactions = 0
    model, turns, seen = "", 0, set()
    models: List[Dict[str, Any]] = []   # one segment per model run, in order
    items: Dict[str, List[tuple]] = {}   # part -> [(name, detail, chars)]
    messages: List[tuple] = []
    tool_names: Dict[str, tuple] = {}
    agent_types: Dict[str, str] = {}   # Agent/Task tool_use id -> subagent_type
    listed: Dict[str, Dict[str, int]] = {"mcp_instructions": {}, "agents": {}}
    subagents: Dict[str, Dict[str, Any]] = {}  # agentId -> what the main thread asked for
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            if not isinstance(entry, dict) or (entry.get("isSidechain") and not sidechain):
                continue
            tur = entry.get("toolUseResult")
            if isinstance(tur, dict) and tur.get("agentId"):
                content = (entry.get("message") or {}).get("content")
                use_id = next((b.get("tool_use_id") for b in content if isinstance(b, dict) and b.get("tool_use_id")), "") \
                    if isinstance(content, list) else ""
                subagents[str(tur["agentId"])] = {"description": _short(tur.get("description"), 80),
                                                  "type": agent_types.get(use_id, "")}
            if entry.get("type") == "system" and entry.get("subtype") == "compact_boundary":
                messages = []  # the summary replaces everything before it
                compactions += 1
                continue
            usage = _claude_usage(entry)
            if usage:
                size = usage["input_tokens"] + usage["cache_read_tokens"] + usage["cache_creation_tokens"]
                if usage["model"] and usage["model"] != model:
                    model, peak = usage["model"], 0   # a switch: the new model's window, its own peak
                    models.append({"model": model, "from_turn": turns + 1, "turns": 0, "peak": 0})
                first, calib, last = first or size, calib or size, size
                peak = max(peak, size)
                if usage["message_id"] not in seen:
                    seen.add(usage["message_id"])
                    turns += 1
                    if models:
                        models[-1]["turns"] += 1
                if models:
                    models[-1]["peak"] = max(models[-1]["peak"], size)
            message = entry.get("message")
            if entry.get("type") in ("user", "assistant") and isinstance(message, dict):
                content = message.get("content")
                for block in content if isinstance(content, list) else [content]:
                    kind = block.get("type") if isinstance(block, dict) else "text"
                    if kind == "tool_use":
                        detail = _short(next(iter((block.get("input") or {}).values()), ""), 60) if isinstance(block.get("input"), dict) else ""
                        name = block.get("name") or "tool"
                        if name in ("Agent", "Task") and isinstance(block.get("input"), dict):
                            name, detail = "Subagent", _short(block["input"].get("description") or detail, 60)
                            agent_types[block.get("id", "")] = str(block["input"].get("subagent_type") or "")[:60]
                        tool_names[block.get("id", "")] = (name, detail)
                        messages.append((f"{name} call", detail, _block_chars(block.get("input"))))
                    elif kind == "tool_result":
                        name, detail = tool_names.get(block.get("tool_use_id", ""), ("tool", ""))
                        messages.append((f"{name} result", detail, _block_chars(block.get("content"))))
                    elif kind == "text":
                        text = block.get("text") if isinstance(block, dict) else block
                        if text:
                            who = "Reply" if entry["type"] == "assistant" else "Prompt"
                            messages.append((who, _short(text, 60), len(text)))
                continue
            att = entry.get("attachment")
            kind = att.get("type") if isinstance(att, dict) else None
            if kind == "prompt_snapshot" and isinstance(att.get("tools"), list):
                calib = 0  # the overhead changed; recalibrate on the next measured turn
                items["system_prompt"] = [(_short(s.strip().splitlines()[0] if s.strip() else "", 60) or "Section", "", len(s))
                                          for s in att.get("systemPrompt") or [] if isinstance(s, str) and len(s) > 40]
                items["system_tools"], items["mcp_tools"] = [], []
                for tool in att["tools"]:
                    if not isinstance(tool, dict):
                        continue
                    server = tool.get("server")
                    items["mcp_tools" if server else "system_tools"].append(
                        (tool.get("name") or "?", server or "", _block_chars(tool)))
            elif kind == "instructions":
                items["memory"] = [(f.get("path", ""), f.get("type", ""), len(f.get("content") or ""))
                                   for f in att.get("files") or [] if isinstance(f, dict)]
            elif kind == "skill_listing" and att.get("isInitial", True):
                items["skills"] = [(ln[2:].split(": ", 1)[0], "", len(ln))
                                   for ln in (att.get("content") or "").splitlines() if ln.startswith("- ")]
            elif kind in ("mcp_instructions_delta", "agent_listing_delta"):
                # Deltas re-announce the whole set after a compaction or resume and
                # remove names when a server disconnects: keep the current set by name.
                mcp = kind == "mcp_instructions_delta"
                live = listed["mcp_instructions" if mcp else "agents"]
                for name in att.get("removedNames" if mcp else "removedTypes") or []:
                    live.pop(str(name), None)
                for b in att.get("addedBlocks" if mcp else "addedLines") or []:
                    if isinstance(b, str) and b:
                        name = b.splitlines()[0].lstrip("# ") if mcp else b.lstrip("- ").split(": ", 1)[0]
                        live[name] = len(b)
            elif kind in ("hook_success", "hook_additional_context") and att.get("content"):
                c = att["content"]
                c = "\n".join(c) if isinstance(c, list) else str(c)
                messages.append((f"Hook: {att.get('hookName') or 'context'}", _short(c, 60), len(c)))
    if not last:
        return {"known": False}
    for key, live in listed.items():
        if live:
            items[key] = [(name, "", n) for name, n in live.items()]
    est = {k: sum(i[2] for i in v) // _CHARS_PER_TOKEN for k, v in items.items() if v}
    est = {k: v for k, v in est.items() if v}
    cap = calib or first
    scale = min(1.0, cap / sum(est.values())) if est else 1.0
    parts = {k: int(v * scale) for k, v in est.items()} or {"overhead": min(cap, last)}
    overhead = sum(parts.values())
    parts["messages"] = max(0, last - overhead)
    parts = {k: parts[k] for k in _CONTEXT_LABELS if k in parts}
    items["messages"] = messages

    def listing(key: str) -> Dict[str, Any]:
        rows = sorted(items.get(key) or [], key=lambda i: -i[2])
        f = 1.0 if key == "messages" else scale
        return {"items": [{"name": n, "detail": d, "tokens": int(c / _CHARS_PER_TOKEN * f)} for n, d, c in rows[:_ITEMS_MAX]],
                "count": len(rows)}

    compact_at = _claude_compact_at(model)
    limit, source = _context_window(model, peak, compact_at)
    return {
        "known": True, "agent": "claude", "model": model, "used": last,
        "limit": limit, "limit_source": source, "compact_at": compact_at or None,
        "first": first, "turns": turns, "estimated": bool(est), "models": models, "compactions": compactions,
        "parts": [{"key": k, "label": _CONTEXT_LABELS[k], "tokens": v, **listing(k)} for k, v in parts.items()],
        "_subagent_links": subagents,
    }


def _subagent_contexts(path: Path, links: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Each subagent runs in its own window (``<session>/subagents/agent-<id>.jsonl``):
    its peak, final size and limit, never added to the main window's total.
    What it handed back to the main thread is already a Messages item there."""
    out = []
    for f in sorted((path.parent / path.stem / "subagents").glob("agent-*.jsonl")):
        try:
            ctx = _claude_context(f, sidechain=True)
        except OSError:
            continue
        if not ctx.get("known"):
            continue
        agent_id = f.stem[len("agent-"):]
        link = links.get(agent_id) or {}
        out.append({
            "id": agent_id, "type": link.get("type") or "", "description": link.get("description") or "", "model": ctx["model"],
            "used": ctx["used"], "peak": max((m["peak"] for m in ctx["models"]), default=ctx["used"]),
            "limit": ctx["limit"], "limit_source": ctx["limit_source"], "turns": ctx["turns"],
        })
    return sorted(out, key=lambda s: -s["peak"])


def _codex_context(path: Path) -> Dict[str, Any]:
    """Codex logs the window and each turn's context size in token_count."""
    first = last = limit = turns = 0
    model = ""
    models: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            payload = rec.get("payload") if isinstance(rec, dict) else None
            if not isinstance(payload, dict):
                continue
            if rec.get("type") == "turn_context" and payload.get("model"):
                if payload["model"] != model:
                    models.append({"model": payload["model"], "from_turn": turns + 1, "turns": 0, "peak": 0})
                model = payload["model"]
            if rec.get("type") != "event_msg" or payload.get("type") != "token_count":
                continue
            info = payload.get("info") or {}
            lt = info.get("last_token_usage")
            if not isinstance(lt, dict):
                continue
            size = int(lt.get("total_tokens") or 0) or int(lt.get("input_tokens") or 0) + int(lt.get("output_tokens") or 0)
            if size and size != last:
                first, last, turns = first or size, size, turns + 1
                if models:
                    models[-1]["turns"] += 1
                    models[-1]["peak"] = max(models[-1]["peak"], size)
            limit = int(info.get("model_context_window") or limit)
    if not last:
        return {"known": False}
    window, source = (limit, "agent") if limit else _context_window(model, last)
    return {
        "known": True, "agent": "codex", "model": model, "used": last, "limit": window, "limit_source": source,
        "compact_at": None, "first": first, "turns": turns, "estimated": False, "models": models, "subagents": [],
        "parts": [{"key": "overhead", "label": _CONTEXT_LABELS["overhead"], "tokens": min(first, last)},
                  {"key": "messages", "label": _CONTEXT_LABELS["messages"], "tokens": max(0, last - first)}],
    }


def session_context(session_id: str, transcript_path: Optional[str] = None) -> Dict[str, Any]:
    """What fills the session's context window right now (main thread only;
    subagents have their own windows). ``known`` False = no transcript here."""
    path = Path(transcript_path) if transcript_path else find_transcript(session_id)
    if path is None or not path.is_file():
        return {"known": False}
    try:
        if path.name.startswith("rollout-"):
            return _codex_context(path)
        ctx = _claude_context(path)
        if ctx.get("known"):
            ctx["subagents"] = _subagent_contexts(path, ctx.pop("_subagent_links"))
        return ctx
    except OSError:
        return {"known": False}


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


def record_llm_usage(*, workspace: Path, session_id: str, agent: str,
                     model: str, usage: Dict[str, Any], message_id: str,
                     ts: str = "", agent_name: str = "", subject: str = "",
                     latency_ms: Optional[int] = None) -> None:
    """Record a provider ``usage`` block seen on the proxy lane.

    Normalizes the providers' differing field names so the LLM lane populates
    the same ``token_usage`` store the Claude Code transcript path does:
    Anthropic ``input_tokens``/``output_tokens``/``cache_read_input_tokens``,
    OpenAI chat ``prompt_tokens``/``completion_tokens`` (+
    ``prompt_tokens_details.cached_tokens``), OpenAI Responses
    ``input_tokens``/``output_tokens`` (+ ``input_tokens_details``), and Gemini
    ``promptTokenCount``/``candidatesTokenCount``/``cachedContentTokenCount``.

    Buckets are made disjoint before pricing: OpenAI and Gemini count cached
    tokens INSIDE the prompt total (Anthropic keeps them apart), so the cached
    share is subtracted from input or it would be billed twice. Reasoning is
    reported separately: OpenAI's is already inside output_tokens, Gemini's
    ``thoughtsTokenCount`` is not and is billed as output.
    Deduped on ``message_id``; an empty usage block or missing id records
    nothing. Best-effort — never raises."""
    if not isinstance(usage, dict) or not usage or not message_id:
        return

    def pick(*names: str) -> int:
        for name in names:
            value = usage.get(name)
            if isinstance(value, bool):
                continue
            if isinstance(value, (int, float)):
                return int(value)
        return 0

    def sub(key: str, name: str) -> int:
        block = usage.get(key)
        value = block.get(name) if isinstance(block, dict) else None
        return int(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else 0

    # Cached tokens that the provider counts inside the prompt total.
    included = (sub("prompt_tokens_details", "cached_tokens") or sub("input_tokens_details", "cached_tokens")
                or pick("cachedContentTokenCount"))
    cost = usage.get("cost")
    thoughts = pick("thoughtsTokenCount")  # Gemini: separate from candidates, billed as output
    reasoning = (sub("completion_tokens_details", "reasoning_tokens")
                 or sub("output_tokens_details", "reasoning_tokens") or thoughts)
    try:
        _record(workspace, session_id, agent, {
            # An empty ts falls outside every time-windowed cost query.
            "ts": ts or datetime.now(timezone.utc).isoformat(),
            "message_id": message_id,
            "model": model,
            "input_tokens": max(0, pick("input_tokens", "prompt_tokens", "promptTokenCount") - included),
            "output_tokens": pick("output_tokens", "completion_tokens", "candidatesTokenCount") + thoughts,
            "cache_read_tokens": pick("cache_read_input_tokens") or included,
            "cache_creation_tokens": pick("cache_creation_input_tokens"),
            "cache_1h_tokens": sub("cache_creation", "ephemeral_1h_input_tokens"),
            "reasoning_tokens": reasoning,
            # OpenRouter puts the charge on every response (credits are USD).
            "reported_cost_usd": float(cost) if isinstance(cost, (int, float)) and not isinstance(cost, bool) else None,
            "subject": subject or None,
            "latency_ms": latency_ms,
        }, agent_name=agent_name)
    except Exception:
        pass


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
