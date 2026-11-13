"""Atomic, workspace-scoped sliding-window admissions in the runtime store.

Only live action gates reserve slots. Policy evaluation and status are pure
readers of the result; neither replay nor supplied event metadata can reserve
or manufacture an admission. Denied retries do not grow the ledger.
"""
from __future__ import annotations

import hashlib
import json
import math
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

WINDOW_SECONDS = 60.0
DATABASE_TIMEOUT = 0.1

DDL = """
CREATE TABLE IF NOT EXISTS rate_limit_admissions (
    workspace TEXT NOT NULL,
    identity TEXT NOT NULL,
    ts REAL NOT NULL,
    call_id TEXT,
    UNIQUE (workspace, identity, call_id)
);
CREATE INDEX IF NOT EXISTS idx_rate_identity_time
    ON rate_limit_admissions(workspace, identity, ts);
CREATE INDEX IF NOT EXISTS idx_rate_expiry ON rate_limit_admissions(ts);
CREATE TABLE IF NOT EXISTS rate_limit_clock (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    ts REAL NOT NULL
);
"""


def validate_settings(raw: Any) -> List[str]:
    if not isinstance(raw, dict):
        return ["settings.rate_limit must be a mapping"]
    errors = []
    for key, minimum in (("requests_per_minute", 1), ("max_burst", 0)):
        value = raw.get(key, 0 if key == "max_burst" else None)
        if type(value) is not int or value < minimum:
            errors.append(f"settings.rate_limit.{key} must be an integer >= {minimum}")
    for key in raw.keys() - {"requests_per_minute", "max_burst"}:
        errors.append(f"settings.rate_limit: unknown setting {key!r}")
    return errors


@dataclass(frozen=True)
class Scope:
    """Host-owned accounting context, never decoded from a request body.

    HTTP integrations pin workspace and agent here. Only a local hook may set
    call_id: arbitrary client idempotency keys cannot waive accounting.
    """

    workspace: Path
    agent: str
    call_id: Optional[str] = None
    authoritative: bool = False


def validate_repeat_limits(raw: Any) -> List[str]:
    """Exact MCP server -> tool -> identical calls allowed per rolling minute."""
    prefix = "settings.mcp_tool_repeat_limits"
    if not isinstance(raw, dict):
        return [f"{prefix}: must be a mapping of server names to tool limits"]
    errors = []
    for server, tools in raw.items():
        if not isinstance(server, str) or not server.strip() or not isinstance(tools, dict):
            errors.append(f"{prefix}: each server must have a name and a tool mapping")
            continue
        for tool, limit in tools.items():
            if (not isinstance(tool, str) or not tool.strip()
                    or isinstance(limit, bool) or not isinstance(limit, int) or limit < 1):
                errors.append(f"{prefix}: each tool must have a name and a positive integer limit")
    return errors


def repeat_key(session: str, server: str, tool: str, arguments: Any) -> str:
    # Canonical JSON ignores object-key order, but preserves array order and
    # value types. Request IDs are deliberately absent: retries still count.
    return "mcp-repeat:" + _digest([session, server, tool, arguments if arguments is not None else {}])


def identity_key(subject: Any, agent: str, surface: str = "") -> str:
    from prismor.runtime.principal import is_verified

    principal = None
    if is_verified(subject, surface):
        principal = [subject.org_id, subject.user_id, subject.claims.get("iss")]
    # Unverified labels never partition a principal's quota. The agent here is
    # configured by the host; HTTP integrations supply a fixed integration id.
    return _digest([principal, agent])


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()


def hook_call_id(payload: Dict[str, Any], agent: str, session: str) -> Optional[str]:
    call_id = payload.get("tool_use_id") or payload.get("toolUseId")
    if not call_id:
        return None
    # Bind to the input too: a changed payload under a reused id is a new
    # attempt. Only the digest, never arguments or commands, reaches SQLite.
    bound = {k: v for k, v in payload.items()
             if k not in {"hook_event_name", "hookEventName", "timestamp", "ts"}}
    return _digest([agent, session, call_id, bound])


def _clock(connection: sqlite3.Connection, now: float) -> float:
    row = connection.execute("SELECT ts FROM rate_limit_clock WHERE singleton=1").fetchone()
    # Clock rollback cannot free reservations. Forward wall-clock adjustments
    # expire rows normally; all processes share this admission high-water mark.
    previous = float(row[0]) if row else now
    if not math.isfinite(now) or not math.isfinite(previous):
        raise ValueError("invalid rate-limit clock")
    return max(now, previous)


def _retry_after(connection: sqlite3.Connection, workspace: str, identity: str,
                 used: int, limit: int, now: float) -> float:
    if used < limit:
        return 0.0
    # If policy lowered the limit below current usage, enough slots must age
    # out, not merely the oldest one. The same query drives CLI and verdicts.
    row = connection.execute(
        "SELECT ts FROM rate_limit_admissions WHERE workspace=? AND identity=? AND ts > ? "
        "ORDER BY ts LIMIT 1 OFFSET ?",
        (workspace, identity, now - WINDOW_SECONDS, used - limit)).fetchone()
    if not row:
        return 0.0
    stamp = float(row[0])
    if not math.isfinite(stamp):
        raise ValueError("invalid admission timestamp")
    return max(0.0, stamp + WINDOW_SECONDS - now)


def admit(workspace: Path, identity: str, settings: Dict[str, int], *,
          call_id: Optional[str] = None, now: Optional[float] = None) -> Dict[str, Any]:
    """Reserve at most one slot; all count/check/write operations serialize.

    `count` is the attempted ordinal for YAML's comparison with `limit`.
    `used` is the number of stored reservations. A duplicate still undergoes
    policy evaluation and can be denied by a newly tightened limit.
    """
    from prismor.runtime import store

    limit = settings["requests_per_minute"] + settings.get("max_burst", 0)
    result: Dict[str, Any] = {"limit": limit, "count": 0, "used": 0,
                              "remaining": 0, "retry_after": 0.0,
                              "identity": identity, "error": None}
    connection = None
    try:
        stamp = time.time() if now is None else now
        db_path = store.get_db_path(workspace)
        db_path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(db_path, timeout=DATABASE_TIMEOUT)
        # Match the shared store's WAL mode even when a live proxy is the
        # first user of a fresh database (it does its own session persistence).
        connection.execute("PRAGMA journal_mode=WAL")
        connection.executescript(DDL)
        connection.execute("BEGIN IMMEDIATE")
        stamp = _clock(connection, stamp)
        connection.execute("DELETE FROM rate_limit_admissions WHERE ts <= ?",
                           (stamp - WINDOW_SECONDS,))
        scope = store.canonical_workspace_path(workspace)
        used = connection.execute(
            "SELECT COUNT(*) FROM rate_limit_admissions "
            "WHERE workspace=? AND identity=? AND ts > ?",
            (scope, identity, stamp - WINDOW_SECONDS)).fetchone()[0]
        duplicate = bool(call_id and connection.execute(
            "SELECT 1 FROM rate_limit_admissions WHERE workspace=? AND identity=? AND call_id=?",
            (scope, identity, call_id)).fetchone())
        count = used if duplicate else used + 1
        if not duplicate and count <= limit:
            connection.execute("INSERT OR REPLACE INTO rate_limit_clock VALUES (1, ?)", (stamp,))
            connection.execute("INSERT INTO rate_limit_admissions VALUES (?, ?, ?, ?)",
                               (scope, identity, stamp, call_id))
            used += 1
        result.update(count=count, used=used, remaining=max(0, limit - used),
                      retry_after=_retry_after(connection, scope, identity, used, limit, stamp))
        connection.commit()
    except (sqlite3.Error, OSError, ValueError, TypeError, OverflowError) as exc:
        # No raw database exception: it can contain filesystem paths or SQL.
        result["error"] = exc.__class__.__name__
        if connection is not None:
            try:
                connection.rollback()
            except (sqlite3.Error, OSError):
                pass  # Closing also rolls back; retain the original unavailable result.
    finally:
        if connection is not None:
            try:
                connection.close()
            except (sqlite3.Error, OSError) as exc:
                result["error"] = exc.__class__.__name__
    return result


def status(workspace: Path, settings: Optional[Dict[str, int]], *,
           now: Optional[float] = None) -> Dict[str, Any]:
    """Read existing accounting only; never create directories/schema or prune."""
    from prismor.runtime import store

    result: Dict[str, Any] = {"configured": settings is not None,
                              "window_seconds": WINDOW_SECONDS, "identities": [],
                              "error": None}
    if settings is None:
        return result
    limit = settings["requests_per_minute"] + settings.get("max_burst", 0)
    result.update(settings, limit=limit)
    try:
        path = store.existing_db_path()
        if path is None:
            return result
        connection = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=DATABASE_TIMEOUT)
        try:
            connection.execute("BEGIN")  # one consistent read snapshot during concurrent admissions
            if not connection.execute("SELECT 1 FROM sqlite_master WHERE name='rate_limit_admissions'").fetchone():
                return result
            stamp = _clock(connection, time.time() if now is None else now)
            rows = connection.execute(
                "SELECT identity, COUNT(*) FROM rate_limit_admissions "
                "WHERE workspace=? AND ts > ? AND identity NOT LIKE 'mcp-repeat:%' "
                "GROUP BY identity ORDER BY identity",
                (store.canonical_workspace_path(workspace), stamp - WINDOW_SECONDS)).fetchall()
            result["identities"] = [
                {"identity": key, "used": count, "remaining": max(0, limit - count),
                 "retry_after": _retry_after(connection, store.canonical_workspace_path(workspace),
                                             key, count, limit, stamp)}
                for key, count in rows]
        finally:
            connection.close()
    except (sqlite3.Error, OSError, ValueError, TypeError, OverflowError) as exc:
        result["error"] = exc.__class__.__name__
    return result
