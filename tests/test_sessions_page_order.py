"""The dashboard sessions list must reach the newest rows however many exist.

INSERT OR REPLACE gives a re-saved session a new, higher rowid, so a capped
unordered SELECT dropped exactly the most recent sessions (dashboard showed
"last active 23d ago" with ~6k sessions stored).
"""
from __future__ import annotations

import sqlite3

from prismor.runtime import store


def test_newest_session_survives_large_store(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path))
    db = store.initialize_database(tmp_path)
    conn = sqlite3.connect(db)
    conn.executemany(
        "INSERT INTO sessions (session_id, agent, updated_at) VALUES (?, 'claude', ?)",
        [(f"old-{i}", "2026-01-01T00:00:00+00:00") for i in range(5001)]
        + [("newest", "2026-10-16T00:00:00+00:00")],
    )
    conn.commit()
    conn.close()

    page = store.get_sessions_page(page=1, limit=5)
    assert page["items"][0]["sessionId"] == "newest"
    assert page["total"] == 5002


def test_search_matches_any_prompt_not_just_the_first(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path))
    db = store.initialize_database(tmp_path)
    conn = sqlite3.connect(db)
    conn.executemany(
        "INSERT INTO sessions (session_id, agent, updated_at) VALUES (?, 'claude', ?)",
        [("s1", "2026-10-16T00:00:00+00:00"), ("s2", "2026-10-16T00:00:00+00:00")],
    )
    conn.executemany(
        "INSERT INTO events (session_id, type, content_text, raw_json) VALUES (?, 'prompt', ?, '{}')",
        [("s1", f"warm-up prompt {i}") for i in range(10)] + [("s1", "Fix the Login bug"), ("s2", "other")],
    )
    conn.commit()
    conn.close()

    assert [r["sessionId"] for r in store.get_sessions_page(search="login bug")["items"]] == ["s1"]
