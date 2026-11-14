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

Redacting result cells alone is not enough: ``hex(command_text)`` or
``substr()`` reshapes a secret so the redactor no longer recognises it. So the
query runs against TEMP views (same names, shadowing the tables) whose text
columns are redacted *before* any SQL function sees them, and an authorizer
refuses direct reads of ``main.<table>`` that do not go through a view.
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
    conn = _connect(db_path, query_only=not redact)
    try:
        if redact:
            _install_redacted_views(conn, _redactor(workspace))
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


def _connect(db_path: Path, query_only: bool = True) -> sqlite3.Connection:
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    if query_only:
        conn.execute("PRAGMA query_only = 1")
    return conn


# Columns that are keys or timestamps stay raw, so WHERE/JOIN on them keeps
# using indexes. ponytail: name heuristic; a secret in a session id is not redacted.
_KEY_COLUMN_RE = re.compile(r"^(id|ts|.*_id|.*_at)$")


def _install_redacted_views(conn: sqlite3.Connection, redact: Any) -> None:
    conn.create_function("_prismor_redact", 1,
                         lambda v: redact(v) if isinstance(v, str) and v else v, deterministic=True)
    tables = [r[0] for r in conn.execute(
        "SELECT name FROM main.sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
    for name in tables:
        cols = []
        qn = '"' + name.replace('"', '""') + '"'
        for _, col, ctype, *_ in conn.execute(f"PRAGMA main.table_info({qn})"):  # nosec B608 - quoted identifier from sqlite_master
            qc = '"' + col.replace('"', '""') + '"'
            text = "INT" not in (ctype or "").upper() and "REAL" not in (ctype or "").upper()
            cols.append(f"_prismor_redact({qc}) AS {qc}" if text and not _KEY_COLUMN_RE.match(col) else qc)
        # Identifiers come from sqlite_master/table_info and are double-quote escaped.
        conn.execute(f"CREATE TEMP VIEW {qn} AS SELECT {', '.join(cols)} FROM main.{qn}")  # nosec B608
    conn.execute("PRAGMA query_only = 1")
    wrapped = frozenset(tables)

    def authorize(action, arg1, arg2, db, view):
        # A read of a real table must come from one of the views above.
        if action == sqlite3.SQLITE_READ and db == "main" and view is None and arg1 in wrapped:
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK
    conn.set_authorizer(authorize)


def _redactor(workspace: Optional[Path]) -> Any:
    """Registered secrets and data-boundary values (redact_text), then the
    secret-shaped pattern list the telemetry sinks use in full-capture mode —
    the same two passes a forwarded record gets."""
    from functools import lru_cache
    from prismor.runtime.redaction import redact_text
    from prismor.runtime.enterprise.telemetry import _compile_scrubbers, scrub

    try:
        from prismor.runtime.cloaking.patterns import all_patterns
        scrubbers = _compile_scrubbers(all_patterns())
    except Exception:
        scrubbers = []

    @lru_cache(maxsize=4096)
    def redact(v: str) -> str:
        text, _ = redact_text(v, workspace=workspace)
        return scrub(text, scrubbers)
    return redact


def _redact_rows(rows: List[Dict[str, Any]], workspace: Optional[Path]) -> None:
    redact = _redactor(workspace)
    for row in rows:
        for k, v in row.items():
            if isinstance(v, str) and v:
                row[k] = redact(v)


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
