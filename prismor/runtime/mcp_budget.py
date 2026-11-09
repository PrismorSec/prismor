"""Per-session MCP spending reservations in the shared SQLite store.

Costs are operator estimates, not provider billing. Reserve before forwarding:
an upstream error can still represent billable work, so reservations are not
refunded. No arguments, request IDs or credentials enter this ledger.
"""
from __future__ import annotations

import sqlite3
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

from prismor.runtime.ratelimit import DATABASE_TIMEOUT

DDL = """
CREATE TABLE IF NOT EXISTS mcp_tool_spend (
    workspace TEXT NOT NULL,
    session TEXT NOT NULL,
    server TEXT NOT NULL,
    tool TEXT NOT NULL,
    used_microusd INTEGER NOT NULL CHECK (used_microusd >= 0),
    PRIMARY KEY (workspace, session, server, tool)
);
"""


def _microusd(value: Any) -> int:
    if type(value) not in (int, float):
        raise ValueError("must be a number")
    amount = Decimal(str(value))
    if not amount.is_finite() or not 0 <= amount <= 1_000_000_000:
        raise ValueError("must be between 0 and 1000000000 USD")
    micros = amount * 1_000_000
    if micros != micros.to_integral_value():
        raise ValueError("must have at most six decimal places")
    return int(micros)


def validate_settings(raw: Any) -> list[str]:
    prefix = "settings.mcp_tool_budgets"
    if not isinstance(raw, dict):
        return [f"{prefix} must map server names to tool budgets"]
    errors = []
    for server, tools in raw.items():
        if not isinstance(server, str) or not server or not isinstance(tools, dict):
            errors.append(f"{prefix}: each server must have a tool mapping")
            continue
        for tool, budget in tools.items():
            if not isinstance(tool, str) or not tool or not isinstance(budget, dict):
                errors.append(f"{prefix}: each tool must have a budget mapping")
                continue
            try:
                if set(budget) != {"cost_usd", "limit_usd"}:
                    raise ValueError("requires exactly cost_usd and limit_usd")
                if _microusd(budget["cost_usd"]) == 0:
                    raise ValueError("cost_usd must be positive")
                _microusd(budget["limit_usd"])
            except (ValueError, InvalidOperation) as exc:
                errors.append(f"{prefix}.{server}.{tool}: {exc}")
    return errors


def reserve(workspace: Path, session: str, server: str, tool: str,
            budget: dict[str, Any]) -> dict[str, Any]:
    """Atomically check and reserve a fixed cost, including across processes."""
    from prismor.runtime import store

    result = {"exceeded": False, "error": None, "used_usd": 0,
              "cost_usd": budget.get("cost_usd"), "limit_usd": budget.get("limit_usd")}
    connection = None
    try:
        cost, limit = _microusd(budget["cost_usd"]), _microusd(budget["limit_usd"])
        if cost <= 0 or not session:
            raise ValueError("invalid budget scope")
        path = store.get_db_path(workspace)
        path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(path, timeout=DATABASE_TIMEOUT)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.executescript(DDL)
        connection.execute("BEGIN IMMEDIATE")
        scope = (store.canonical_workspace_path(workspace), session, server, tool)
        row = connection.execute(
            "SELECT used_microusd FROM mcp_tool_spend "
            "WHERE workspace=? AND session=? AND server=? AND tool=?", scope).fetchone()
        used = row[0] if row else 0
        if type(used) is not int or used < 0:
            raise ValueError("invalid stored spend")
        result["exceeded"] = used + cost > limit
        if not result["exceeded"]:
            used += cost
            connection.execute("INSERT OR REPLACE INTO mcp_tool_spend VALUES (?, ?, ?, ?, ?)",
                               (*scope, used))
        result["used_usd"] = used / 1_000_000
        connection.commit()
    except (sqlite3.Error, OSError, ValueError, InvalidOperation, OverflowError) as exc:
        # Database errors can contain paths or SQL; report only their class.
        result["error"] = type(exc).__name__
    finally:
        if connection is not None:
            connection.close()  # also rolls back an unfinished reservation
    return result
