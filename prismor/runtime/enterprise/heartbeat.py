"""Per-tool-call volume heartbeat — makes "tool calls inspected" a real number.

Findings-only telemetry tells the org what was *flagged*; it says nothing about
how much the agent actually did. This module counts every hook-dispatched tool
call locally and, at most once per ``FLUSH_INTERVAL`` seconds, uploads one
``agent_activity`` record *per agent instance* carrying the accumulated count.
The control plane sums the ``count`` column for the "tool calls inspected" KPI.

Counts are keyed per agent instance (``<framework>|<name>``) so a fleet of many
agents on the same framework reports separate volume — "checkout-bot did 400
calls, support-bot did 30" — instead of one indistinguishable device total. An
unnamed agent uses the empty name (key ``<framework>|``).

Privacy: the heartbeat carries *only* a number plus the same metadata enums as
any redacted record (agent id, agent name, session id). No commands, paths, or
content — it is volume, not activity detail.

Cost: one lock-guarded JSON read/write per tool call (sub-millisecond) and one
HTTP POST per minute at most, with the same short-timeout + offline-spool
semantics as finding telemetry (prismor/runtime/sinks.upload_telemetry). Failures never
raise into the hook path.
"""
from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from prismor.runtime.enterprise import identity as _identity

FLUSH_INTERVAL = 60.0

# Bound the counter file + flush fan-out. A single device running >64 distinct
# agent instances is not a real topology (instances spread across a fleet of
# devices); overflow folds into the framework-level key so volume is never lost,
# only its per-instance attribution past the cap.
MAX_COUNTER_KEYS = 64


def _counter_path() -> Path:
    return _identity.prismor_home() / "heartbeat.json"


def _counter_key(agent: Optional[str], agent_name: Optional[str]) -> str:
    return f"{agent or ''}|{agent_name or ''}"


def _load(path: Path) -> Dict[str, Any]:
    """Load the counter file, migrating the v1 flat shape to v2 keyed counters.

    v1: {"count": N, "agent": a, "session_id": s, "last_flush": t}
    v2: {"v": 2, "last_flush": t, "counters": {"<framework>|<name>": {count, session_id}}}
    """
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"v": 2, "last_flush": time.time(), "counters": {}}
    if not isinstance(data, dict):
        return {"v": 2, "last_flush": time.time(), "counters": {}}
    if data.get("v") == 2 and isinstance(data.get("counters"), dict):
        return data
    # Migrate v1 → v2: fold the flat counter into a single framework-level key.
    counters: Dict[str, Any] = {}
    count = int(data.get("count", 0) or 0)
    if count > 0:
        key = _counter_key(data.get("agent"), "")
        counters[key] = {"count": count, "session_id": data.get("session_id")}
    return {"v": 2, "last_flush": float(data.get("last_flush", time.time())), "counters": counters}


def record_call(
    agent: Optional[str] = None,
    session_id: Optional[str] = None,
    agent_name: Optional[str] = None,
) -> None:
    """Count one inspected tool call for one agent instance. Never raises; no-op
    when not enrolled."""
    if not _identity.is_enrolled():
        return
    path = _counter_path()
    try:
        from prismor.runtime.store import file_lock
        path.parent.mkdir(parents=True, exist_ok=True)
        with file_lock(path):
            data = _load(path)
            counters: Dict[str, Any] = data.setdefault("counters", {})
            key = _counter_key(agent, agent_name)
            # Cap: an instance past the limit folds into the framework key so
            # its volume still counts, bounding file size and flush fan-out.
            if key not in counters and len(counters) >= MAX_COUNTER_KEYS:
                key = _counter_key(agent, "")
            slot = counters.setdefault(key, {"count": 0, "session_id": None})
            slot["count"] = int(slot.get("count", 0)) + 1
            if session_id:
                slot["session_id"] = session_id
            data.setdefault("last_flush", time.time())
            data["v"] = 2
            path.write_text(json.dumps(data), encoding="utf-8")
            try:  # audit #18: keep session metadata 0600, not world-readable
                path.chmod(0o600)
            except OSError:
                pass
    except OSError:
        pass


def maybe_flush(now: Optional[float] = None) -> bool:
    """Upload the accumulated counts as one agent_activity record *per agent
    instance*, at most once per FLUSH_INTERVAL. Returns True if a flush was
    attempted. Never raises.

    Counters are reset *before* the upload; on failure the records land in the
    offline spool (see sinks.upload_telemetry), so counts are never lost and
    never double-sent. All per-instance records ship in one batched upload.
    """
    ident = _identity.load_identity()
    if not ident or _identity.revoked_backoff_active():
        return False

    path = _counter_path()
    records: list = []
    try:
        from prismor.runtime.store import file_lock
        if not path.exists():
            return False
        with file_lock(path):
            data = _load(path)
            counters: Dict[str, Any] = data.get("counters", {}) or {}
            last = float(data.get("last_flush", 0))
            t = time.time() if now is None else now
            if (t - last) < FLUSH_INTERVAL:
                return False
            import uuid
            for key, slot in counters.items():
                count = int(slot.get("count", 0))
                if count <= 0:
                    continue
                agent, _, agent_name = key.partition("|")
                rec = {
                    "schema": "prismor.runtime.telemetry.v1",
                    "event_id": "evt_" + uuid.uuid4().hex,
                    "ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                    "type": "agent_activity",
                    "verdict": "observed",
                    "title": "Agent activity heartbeat",
                    "agent": agent or None,
                    "session_id": slot.get("session_id"),
                    "count": count,
                    "redacted": True,
                }
                if agent_name:
                    rec["agent_name"] = agent_name
                records.append(rec)
            # Reset all counters, keep the flush timestamp.
            path.write_text(
                json.dumps({"v": 2, "last_flush": t, "counters": {}}), encoding="utf-8"
            )
            try:  # audit #18
                path.chmod(0o600)
            except OSError:
                pass
    except (OSError, ValueError):
        return False

    # Always call through, even with no counts of our own: upload_telemetry
    # drains the telemetry spool, and findings now ride that spool instead of
    # one POST each. This tick is what ships them.
    try:
        from prismor.runtime.sinks import upload_telemetry
        upload_telemetry(records)
    except Exception as exc:  # spooled by upload_telemetry; just note it
        sys.stderr.write(f"[prismor] heartbeat upload deferred: {exc}\n")
    return True
