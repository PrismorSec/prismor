"""Logs page backend: one outcome per event, and facet counts that ignore
their own filter (so a ticked box never hides its siblings)."""
from datetime import datetime, timezone

from prismor.runtime import logs


def _f(action, mode):
    return ("HIGH", "cat", "title", action, mode, "rule")


def test_status_mapping():
    assert logs._status([]) == "allowed"
    assert logs._status([_f("block", "enforce")]) == "blocked"
    assert logs._status([_f("block", None)]) == "blocked"
    assert logs._status([_f("block", "observe")]) == "flagged"
    assert logs._status([_f("warn", "enforce"), _f("step_up", "enforce")]) == "asked"
    assert logs._status([_f(None, None)]) == "flagged"


def test_facets_ignore_their_own_filter(monkeypatch):
    now = datetime.now(timezone.utc).isoformat()
    # (ws, (id, ts, session, type, agent_event, tool, server, detail, rn, agent), status, findings, result)
    rows = [
        (0, (1, now, "s1", "shell", "PreToolUse", "Bash", "", "rm -rf x", 0, "claude"), "blocked", [_f("block", "enforce")], None),
        (0, (2, now, "s1", "file_read", "PreToolUse", "Read", "", "/a", 1, "claude"), "allowed", [], None),
        (0, (3, now, "s2", "tool_result", "PreToolUse", "mcp__gh__issue", "gh", "{}", 0, "codex"), "allowed", [], None),
    ]
    monkeypatch.setattr(logs, "_all_rows", lambda days: rows)
    d = logs.query_logs({"status": "blocked"}, days=7)
    assert d["total"] == 1 and d["stats"]["blocked"] == 1
    assert {f["value"]: f["count"] for f in d["facets"]["status"]} == {"blocked": 1, "allowed": 2}
    assert {f["value"] for f in d["facets"]["tool"]} == {"Bash"}
    d = logs.query_logs({"server": "gh"}, days=7)
    assert [i["tool"] for i in d["items"]] == ["mcp__gh__issue"]
    assert logs.query_logs({"q": "rm -rf"}, days=7)["total"] == 1
    assert sum(sum(b[s] for s in logs.STATUSES) for b in d["histogram"]) == 1


def test_result_folds_into_its_call(monkeypatch, tmp_path):
    import sqlite3
    db = tmp_path / "s.db"
    c = sqlite3.connect(db)
    c.executescript("""
        CREATE TABLE events (id INTEGER PRIMARY KEY, session_id TEXT, ts TEXT, type TEXT, agent_event TEXT,
            command_text TEXT, path_text TEXT, url_text TEXT, content_text TEXT, raw_json TEXT);
        CREATE INDEX idx_events_ts ON events(ts DESC);
        CREATE TABLE findings (finding_id TEXT, session_id TEXT, event_index INTEGER, severity TEXT,
            category TEXT, title TEXT, evidence TEXT, enrichment_json TEXT);
        CREATE TABLE sessions (session_id TEXT, agent TEXT);
    """)
    now = datetime.now(timezone.utc)
    ev = lambda i, kind, tool, use: (i, "s", (now.replace(microsecond=i * 1000)).isoformat(), "shell", kind, "ls", "", "", "",
                                     '{"metadata": {"tool_name": "%s", "raw": {"tool_use_id": %s}}}' % (tool, use))
    rows = [ev(1, "PreToolUse", "Bash", '"a"'), ev(2, "PreToolUse", "Bash", '"b"'),
            ev(3, "PostToolUse", "Bash", '"b"'), ev(4, "PostToolUse", "Bash", '"a"'),
            ev(5, "PreToolUse", "Read", "null"), ev(6, "PostToolUse", "Read", "null")]
    c.executemany("INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?)", rows)
    # A finding on the result of call "b" (event index 2) blocks that call's row.
    c.execute("INSERT INTO findings VALUES ('f','s',2,'HIGH','x','t','', '{\"action\": \"block\", \"mode\": \"enforce\"}')")
    c.commit(); c.close()
    monkeypatch.setattr(logs, "_IDX", {})
    monkeypatch.setattr(logs, "_state_query_workspaces", lambda: ["ws"])
    monkeypatch.setattr(logs, "get_db_path", lambda ws: db)
    monkeypatch.setattr(logs, "_connect_ro", lambda p: (lambda k: (setattr(k, "row_factory", sqlite3.Row), k)[1])(sqlite3.connect(p)))
    d = logs.query_logs({}, days=1)
    by = {i["id"]: i for i in d["items"]}
    assert set(by) == {"0:1", "0:2", "0:5"}
    assert by["0:1"]["post"] == "0:4" and by["0:2"]["post"] == "0:3" and by["0:5"]["post"] == "0:6"
    assert by["0:2"]["status"] == "blocked" and by["0:1"]["status"] == "allowed"
