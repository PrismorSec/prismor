"""Schema-migration tests: simulate a v1.5.8 DB and verify v1.6.0 self-heals."""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from prismor.runtime import store


# A v1.5.8-shaped schema: missing supply_chain_events.session_id /
# recommended_version (the columns whose absence caused the crash).
V158_SCHEMA = """
CREATE TABLE sessions (
    session_id TEXT PRIMARY KEY, agent TEXT, source TEXT,
    workspace_path TEXT, repo_url TEXT, started_at TEXT, updated_at TEXT,
    risk_score INTEGER, findings_count INTEGER, summary_json TEXT
);
CREATE TABLE events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT NOT NULL,
    ts TEXT, type TEXT, agent_event TEXT,
    command_text TEXT, path_text TEXT, url_text TEXT,
    content_text TEXT, raw_json TEXT NOT NULL
);
CREATE TABLE findings (
    finding_id TEXT PRIMARY KEY, session_id TEXT NOT NULL,
    event_index INTEGER, severity TEXT, category TEXT,
    title TEXT, evidence TEXT, enrichment_json TEXT
);
CREATE TABLE supply_chain_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL,
    workspace_path TEXT, ecosystem TEXT, package_name TEXT,
    package_version TEXT, install_cmd TEXT, verdict TEXT, score INTEGER,
    signals_json TEXT, ioc_id TEXT
);
"""


@pytest.fixture
def v158_workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "ws"
    (ws / ".prismor").mkdir(parents=True)
    db = ws / ".prismor" / "prismor.db"
    conn = sqlite3.connect(db)
    conn.executescript(V158_SCHEMA)
    conn.commit()
    conn.close()
    return ws


def _columns(db: Path, table: str) -> set:
    conn = sqlite3.connect(db)
    try:
        return {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
    finally:
        conn.close()


def test_initialize_database_adds_missing_columns(v158_workspace: Path) -> None:
    db = store.initialize_database(v158_workspace)
    cols = _columns(db, "supply_chain_events")
    assert "session_id" in cols
    assert "recommended_version" in cols


def test_connect_ro_self_heals(v158_workspace: Path) -> None:
    """A read path must heal a stale DB, not just crash-proof itself.

    The upgrade sequence this reproduces: a v1.5.8 install kept its DB in the
    workspace, ``get_data_dir`` relocates it to $PRISMOR_HOME on first touch,
    and the schema is still v1.5.8 until something migrates it. Dashboard reads
    go through ``_connect_ro``, which is where that migration has to happen.

    Note the read paths query $PRISMOR_HOME only (``_state_query_workspaces``),
    so the DB has to be relocated there before the read for this to test
    anything — it is not enough to leave it in the workspace.
    """
    store._MIGRATED_PATHS.clear()
    db = store.get_db_path(v158_workspace)      # relocates ws/.prismor -> $PRISMOR_HOME
    assert "session_id" not in _columns(db, "supply_chain_events")

    # Pre-migration DB: read paths must not crash on the missing session_id col.
    stats = store.get_supply_chain_stats(24)
    assert "kpis" in stats
    assert "session_id" in _columns(db, "supply_chain_events")


def test_migrate_schema_idempotent(v158_workspace: Path) -> None:
    db = store.initialize_database(v158_workspace)
    before = _columns(db, "supply_chain_events")
    store.initialize_database(v158_workspace)
    after = _columns(db, "supply_chain_events")
    assert before == after
