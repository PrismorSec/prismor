"""`prismor query`: read-only, redacted access to the session store."""
from __future__ import annotations

import sqlite3

import pytest

from prismor.runtime.query import QueryError, agent_prompt, format_rows, run_query, schema


KEY = "sk_live_" + "abcdefghij" * 4  # secret-shaped, never a real value


@pytest.fixture
def db(tmp_path):
    path = tmp_path / "prismor.db"
    conn = sqlite3.connect(path)
    conn.executescript(
        f"""
        CREATE TABLE findings (finding_id TEXT PRIMARY KEY, session_id TEXT, severity TEXT,
                               evidence TEXT, enrichment_json TEXT);
        INSERT INTO findings VALUES ('f1', 's1', 'HIGH', 'curl -H "Authorization: Bearer {KEY}"',
                                     '{{"ruleId": "secret-exfiltration", "action": "block", "mode": "enforce"}}');
        INSERT INTO findings VALUES ('f2', 's1', 'LOW', 'ls -la', '{{"ruleId": "x", "action": "warn", "mode": "observe"}}');
        """
    )
    conn.commit()
    conn.close()
    return path


def test_select_returns_rows_and_json_extract_works(db):
    rows = run_query(
        "SELECT json_extract(enrichment_json, '$.ruleId') AS rule_id FROM findings WHERE severity = 'HIGH'",
        db, redact=False,
    )
    assert rows == [{"rule_id": "secret-exfiltration"}]


@pytest.mark.parametrize("sql", [
    "DELETE FROM findings",
    "UPDATE findings SET severity = 'LOW'",
    "DROP TABLE findings",
    "INSERT INTO findings VALUES ('x','s','LOW','','{}')",
    "PRAGMA journal_mode = DELETE",
    "SELECT 1; DELETE FROM findings",
])
def test_writes_are_refused_before_touching_the_file(db, sql):
    with pytest.raises(QueryError):
        run_query(sql, db)
    conn = sqlite3.connect(db)
    assert conn.execute("SELECT count(*) FROM findings").fetchone()[0] == 2
    conn.close()


def test_with_cte_allowed_but_sqlite_error_is_a_query_error(db):
    assert run_query("WITH t AS (SELECT 1 AS one) SELECT one FROM t", db) == [{"one": 1}]
    with pytest.raises(QueryError):
        run_query("SELECT nope FROM findings", db)


def test_limit_caps_rows(db):
    assert len(run_query("SELECT * FROM findings", db, limit=1)) == 1
    assert len(run_query("SELECT * FROM findings", db, limit=0)) == 2


def test_string_cells_are_redacted(db):
    rows = run_query("SELECT evidence FROM findings WHERE finding_id = 'f1'", db)
    assert KEY not in rows[0]["evidence"]
    assert run_query("SELECT evidence FROM findings WHERE finding_id = 'f2'", db)[0]["evidence"] == "ls -la"


def test_schema_and_missing_store(db, tmp_path):
    assert schema(db) == {"findings": ["finding_id", "session_id", "severity", "evidence", "enrichment_json"]}
    with pytest.raises(QueryError):
        run_query("SELECT 1", tmp_path / "nope.db")


def test_format_table_and_prompt(db):
    out = format_rows([{"a": 1, "b": None}], "table")
    assert out.splitlines()[0].split() == ["a", "b"]
    assert format_rows([], "table") == "(no rows)"
    assert str(db) in agent_prompt(db) and "prismor query" in agent_prompt(db)
