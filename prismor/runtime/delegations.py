"""Delegation records: which subagents an agent launched, in what order, when.

One append-only JSONL file per session (for an SDK subagent, the session of
the main agent's call it runs under; see subagent_context.tree_session), next
to the subagent ledger. Two kinds of line:

- ``spawn``: the main agent's call that launches a subagent (Claude Code's
  Agent/Task tool, a ``subagent_spawn`` event). The subagent has no id yet.
- ``start``: a subagent's first call (every SDK adapter, Codex, and Claude
  Code's subagent once it runs). Its timestamp is the subagent's start.

From these, a call reads ``subagent.number`` (which of its parent's subagents
it is, 1 = first; on a spawn, the number the launched subagent gets) and
``subagent.age`` (seconds since the subagent started). A rule then caps how
many subagents an agent launches (``subagent.number > 5``) or how long one
may run (``subagent.age > 900``).

The number is reserved, under a lock, at the moment it is read, so launches
running in parallel (Claude Code starts several subagents at once) each get
their own. If the call is then blocked, a ``cancel`` line releases it: a
launch a rule refused does not use up the cap.
"""
from __future__ import annotations

import json
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional


def _path(session_id: str) -> Path:
    from prismor.runtime.store import prismor_home

    safe = "".join(c for c in str(session_id) if c.isalnum() or c in "-_")[:80] or "unknown"
    return prismor_home() / "subagents" / f"{safe}.delegations.jsonl"


def records(session_id: str) -> List[Dict[str, Any]]:
    """The session's live delegation records, oldest first (cancelled ones dropped)."""
    try:
        lines = _path(session_id).read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    out = []
    for line in lines:
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    cancelled = {r.get("rid") for r in out if r.get("kind") == "cancel"}
    return [r for r in out if r.get("kind") != "cancel" and r.get("rid") not in cancelled]


def _is_spawn(event: Dict[str, Any]) -> bool:
    return str(event.get("type") or "") == "subagent_spawn"


def _counts(event: Dict[str, Any]) -> bool:
    """Only a call about to run counts: not its PostToolUse, not a stop."""
    return str(event.get("agent_event") or "PreToolUse") == "PreToolUse"


def _spawn_key(event: Dict[str, Any]) -> Optional[str]:
    """The host's id for a launch call, so the global and project installs of
    one agent (both screen every call) reserve it once."""
    meta = event.get("metadata") or {}
    raw = meta.get("raw") if isinstance(meta.get("raw"), dict) else {}
    key = meta.get("tool_use_id") or raw.get("tool_use_id") or raw.get("toolUseId")
    return str(key) if key else None


def _number(recs: List[Dict[str, Any]], kind: str, parent: str) -> int:
    return 1 + sum(r.get("kind") == kind and r.get("parent") == parent for r in recs)


def stamp(event: Dict[str, Any], agent_name: str, session_id: str, *, reserve: bool = True) -> None:
    """Set ``metadata.subagent_number``/``subagent_age``, reserving the number
    of a new launch or subagent. ``reserve=False`` (a dry run, or the second
    install of one agent) only reads. Never raises."""
    meta = event.setdefault("metadata", {})
    sub_id = meta.get("subagent_id")
    if not (sub_id or _is_spawn(event)) or not session_id or not _counts(event):
        return
    try:
        from prismor.runtime.store import file_lock

        path = _path(session_id)
        with file_lock(path):
            recs = records(session_id)
            now = time.time()
            if sub_id:
                parent = str(meta.get("parent_agent_name") or agent_name)
                mine = next((r for r in recs if r.get("kind") == "start" and r.get("id") == sub_id), None)
                if mine is not None:
                    meta.setdefault("subagent_number", mine.get("number", 1))
                    meta.setdefault("subagent_age", max(0, int(now - float(mine.get("ts", now)))))
                    return
                line = {"kind": "start", "id": str(sub_id), "type": meta.get("subagent_type"), "parent": parent,
                        "chain": meta.get("subagent_chain") or [], "number": _number(recs, "start", parent)}
                meta.setdefault("subagent_age", 0)
            else:
                key = _spawn_key(event)
                mine = next((r for r in recs if key and r.get("kind") == "spawn" and r.get("key") == key), None)
                if mine is not None:
                    meta.setdefault("subagent_number", mine.get("number", 1))
                    return
                line = {"kind": "spawn", "key": key, "type": str(event.get("subagent_type") or ""),
                        "parent": agent_name, "number": _number(recs, "spawn", agent_name)}
            meta.setdefault("subagent_number", line["number"])
            if not reserve:
                return
            line.update(ts=now, rid=uuid.uuid4().hex[:16])
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(line) + "\n")
            meta["_delegation_rid"] = line["rid"]
    except Exception:
        pass


def release(event: Dict[str, Any], session_id: str) -> None:
    """Cancel the number ``stamp`` reserved for a call that was then blocked."""
    rid = (event.get("metadata") or {}).pop("_delegation_rid", None)
    if not rid or not session_id:
        return
    try:
        from prismor.runtime.store import file_lock

        path = _path(session_id)
        with file_lock(path):
            with path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps({"kind": "cancel", "rid": rid, "ts": time.time()}) + "\n")
    except Exception:
        pass
