"""Delegation records: which subagents an agent launched, in what order, when.

One append-only JSONL file per session (for an SDK subagent, the session of
the main agent's call it runs under; see subagent_context.tree_session), next to the subagent ledger. A line
is written when a launch is allowed:

- ``spawn``: the main agent's call that launches a subagent (Claude Code's
  Agent/Task tool, a ``subagent_spawn`` event). The subagent has no id yet.
- ``start``: a subagent's first allowed call (every SDK adapter, Codex, and
  Claude Code's subagent once it runs). Its timestamp is the subagent's start.

From these, a call reads ``subagent.number`` (which of its parent's subagents
it is, 1 = first; on a spawn, the number the launched subagent gets) and
``subagent.age`` (seconds since the subagent started). A rule then caps how
many subagents an agent launches (``subagent.number > 5``) or how long one
may run (``subagent.age > 900``). Blocked calls write nothing, so a launch a
rule refused does not use up the cap.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, List


def _path(session_id: str) -> Path:
    from prismor.runtime.store import prismor_home

    safe = "".join(c for c in str(session_id) if c.isalnum() or c in "-_")[:80] or "unknown"
    return prismor_home() / "subagents" / f"{safe}.delegations.jsonl"


def records(session_id: str) -> List[Dict[str, Any]]:
    """Every delegation record of a session, oldest first."""
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
    return out


def _is_spawn(event: Dict[str, Any]) -> bool:
    return str(event.get("type") or "") == "subagent_spawn"


def _counts(event: Dict[str, Any]) -> bool:
    """Only a call about to run counts: not its PostToolUse, not a stop."""
    return str(event.get("agent_event") or "PreToolUse") == "PreToolUse"


def stamp(event: Dict[str, Any], agent_name: str, session_id: str) -> None:
    """Set ``metadata.subagent_number``/``subagent_age`` from the records."""
    meta = event.setdefault("metadata", {})
    sub_id = meta.get("subagent_id")
    if not (sub_id or _is_spawn(event)) or not session_id or not _counts(event):
        return
    recs = records(session_id)
    if not sub_id:  # a launch: the number the new subagent will get
        meta.setdefault("subagent_number",
                        1 + sum(r.get("kind") == "spawn" and r.get("parent") == agent_name for r in recs))
        return
    parent = meta.get("parent_agent_name") or agent_name
    mine = next((r for r in recs if r.get("kind") == "start" and r.get("id") == sub_id), None)
    if mine is not None:
        meta.setdefault("subagent_number", mine.get("number", 1))
        meta.setdefault("subagent_age", max(0, int(time.time() - float(mine.get("ts", time.time())))))
    else:
        meta.setdefault("subagent_number",
                        1 + sum(r.get("kind") == "start" and r.get("parent") == parent for r in recs))
        meta.setdefault("subagent_age", 0)


def record(event: Dict[str, Any], agent_name: str, session_id: str) -> None:
    """Write the record for an allowed launch or subagent start. Never raises."""
    meta = event.get("metadata") or {}
    sub_id = meta.get("subagent_id")
    if not (sub_id or _is_spawn(event)) or not session_id or not _counts(event):
        return
    try:
        path = _path(session_id)
        # ponytail: the number was read before evaluation, so parallel launches
        # in that window can share one and overshoot a cap by the concurrency.
        from prismor.runtime.store import file_lock

        with file_lock(path):
            recs = records(session_id)
            if sub_id:
                if any(r.get("kind") == "start" and r.get("id") == sub_id for r in recs):
                    return
                parent = meta.get("parent_agent_name") or agent_name
                line = {"kind": "start", "id": str(sub_id), "type": meta.get("subagent_type"),
                        "parent": parent, "chain": meta.get("subagent_chain") or [],
                        "number": 1 + sum(r.get("kind") == "start" and r.get("parent") == parent for r in recs)}
            else:
                line = {"kind": "spawn", "type": str(event.get("subagent_type") or ""), "parent": agent_name,
                        "number": 1 + sum(r.get("kind") == "spawn" and r.get("parent") == agent_name for r in recs)}
            line["ts"] = time.time()
            with path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(line) + "\n")
    except Exception:
        pass
