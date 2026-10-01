"""`prismor query` — read-only SQL over the local session store.

The store is one SQLite file (see ``docs/query-your-data.md`` for the schema).
Humans and agents both want to ask it questions: what was blocked this week,
which rule fires most, what did one session do. This is the one sanctioned
door: the connection is opened read-only at the URI level *and* with
``PRAGMA query_only``, only SELECT/WITH/EXPLAIN statements are accepted, and
every string cell is passed through the cloak/data-boundary redactor before
it is printed — event rows carry raw command and content text, and a wide
SELECT would otherwise hand an agent whatever the first pass of redaction
missed.
"""
from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional

_ALLOWED = re.compile(r"^\s*(select|with|explain)\b", re.IGNORECASE)


class QueryError(ValueError):
    pass


def resolve_db_path(workspace: Optional[Path] = None) -> Path:
    from prismor.runtime.store import get_db_path, prismor_home

    if workspace is not None:
        return get_db_path(Path(workspace))
    return prismor_home() / "prismor.db"


def schema(db_path: Path) -> Dict[str, List[str]]:
    """``{table: [column, ...]}`` for every user table in the store."""
    if not db_path.exists():
        raise QueryError(f"no store at {db_path} — run an agent through Prismor first")
    conn = _connect(db_path)
    try:
        out: Dict[str, List[str]] = {}
        for (name,) in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        ):
            out[name] = [r[1] for r in conn.execute(f'PRAGMA table_info("{name}")')]
        return out
    finally:
        conn.close()


def run_query(
    sql: str,
    db_path: Path,
    *,
    limit: int = 200,
    workspace: Optional[Path] = None,
    redact: bool = True,
) -> List[Dict[str, Any]]:
    """Run one read-only statement and return rows as dicts.

    Rejects anything that is not SELECT/WITH/EXPLAIN, or that chains a second
    statement after a semicolon. ``limit`` caps rows; pass 0 for no cap.
    """
    stmt = sql.strip().rstrip(";").strip()
    if not _ALLOWED.match(stmt):
        raise QueryError("only SELECT / WITH / EXPLAIN statements are allowed (the store is read-only)")
    if ";" in stmt:
        raise QueryError("one statement per query")
    if not db_path.exists():
        raise QueryError(f"no store at {db_path} — run an agent through Prismor first")
    conn = _connect(db_path)
    try:
        try:
            cur = conn.execute(stmt)
        except sqlite3.Error as exc:
            raise QueryError(str(exc)) from exc
        cols = [d[0] for d in cur.description or []]
        rows = cur.fetchmany(limit) if limit > 0 else cur.fetchall()
    finally:
        conn.close()
    out = [dict(zip(cols, r)) for r in rows]
    if redact:
        _redact_rows(out, workspace)
    return out


def _connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.execute("PRAGMA query_only = 1")
    return conn


def _redact_rows(rows: List[Dict[str, Any]], workspace: Optional[Path]) -> None:
    """Registered secrets and data-boundary values (redact_text), then the
    secret-shaped pattern list the telemetry sinks use in full-capture mode —
    the same two passes a forwarded record gets."""
    from prismor.runtime.redaction import redact_text
    from prismor.runtime.enterprise.telemetry import _compile_scrubbers, scrub

    try:
        from prismor.runtime.cloaking.patterns import all_patterns
        scrubbers = _compile_scrubbers(all_patterns())
    except Exception:
        scrubbers = []
    for row in rows:
        for k, v in row.items():
            if isinstance(v, str) and v:
                text, _ = redact_text(v, workspace=workspace)
                row[k] = scrub(text, scrubbers)


def format_rows(rows: List[Dict[str, Any]], fmt: str = "json") -> str:
    if fmt == "json":
        return json.dumps(rows, indent=2, default=str)
    if fmt == "jsonl":
        return "\n".join(json.dumps(r, default=str) for r in rows)
    if not rows:
        return "(no rows)"
    cols = list(rows[0].keys())
    cells = [[_cell(r.get(c)) for c in cols] for r in rows]
    widths = [max(len(c), *(row[i].__len__() for row in cells)) for i, c in enumerate(cols)]

    def line(parts: List[str]) -> str:
        return "  ".join(p.ljust(w) for p, w in zip(parts, widths))

    return "\n".join([line(cols), line(["-" * w for w in widths]), *(line(r) for r in cells)])


def _cell(v: Any, width: int = 60) -> str:
    s = "" if v is None else str(v).replace("\n", " ")
    return s if len(s) <= width else s[: width - 1] + "…"


def agent_prompt(db_path: Path) -> str:
    """The prompt the dashboard offers to copy into an agent."""
    return (
        "Prismor (the AI-agent security runtime on this machine) keeps a local SQLite audit "
        f"store of every governed tool call at {db_path}.\n"
        "Read it with `prismor query \"<SELECT …>\"` — it is read-only (writes are refused by the "
        "command and blocked by policy) and output is redacted. `prismor query --schema` lists "
        "the tables; `prismor docs query-your-data` has the schema and example queries, including "
        "how to turn a finding into a policy rule or exemption.\n"
        "Then answer: <what I want to know>"
    )
