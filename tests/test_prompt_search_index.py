"""The Sessions search reads prompts through a partial index, not every event."""
import sqlite3

from prismor.runtime import store


def test_prompt_search_uses_partial_index(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path))
    conn = sqlite3.connect(tmp_path / "prismor.db")
    conn.execute("CREATE TABLE events (id INTEGER PRIMARY KEY, session_id TEXT, ts TEXT, "
                 "type TEXT, content_text TEXT)")
    conn.execute("CREATE INDEX idx_events_session_id ON events(session_id)")
    conn.executemany("INSERT INTO events (session_id, ts, type, content_text) VALUES (?, ?, ?, ?)",
                     [("s1", "t", "prompt", "I added in secrets"), ("s2", "t", "tool", "x")])
    conn.commit()
    conn.close()

    store.ensure_read_indexes()

    conn = sqlite3.connect(tmp_path / "prismor.db")
    plan = " ".join(r[-1] for r in conn.execute(
        "EXPLAIN QUERY PLAN SELECT DISTINCT session_id FROM events WHERE type = 'prompt' "
        "AND instr(lower(content_text), ?) > 0", ("added",)))
    conn.close()
    assert "idx_events_prompt" in plan
    assert store._sessions_with_prompt("added in", [tmp_path]) == {"s1"}
