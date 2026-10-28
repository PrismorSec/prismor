"""#538: evasion-detection must not block the benign subset of a blocked command."""
import sqlite3
from pathlib import Path

from prismor.runtime.learning import detect_evasion
from prismor.runtime.store import get_db_path, initialize_database

BLOCKED = "mkdir -p uploads && chmod -R 777 uploads && ls -ld uploads"


def _seed(ws: Path, sid: str) -> None:
    initialize_database(ws)
    conn = sqlite3.connect(get_db_path(ws))
    try:
        conn.execute(
            "INSERT INTO events (session_id, ts, type, agent_event, command_text, path_text, "
            "url_text, content_text, raw_json) VALUES (?,?,?,?,?,?,?,?,?)",
            (sid, "2026-09-29T00:00:00Z", "shell", "", BLOCKED, "", "", "", "{}"))
        conn.execute(
            "INSERT INTO findings (finding_id, session_id, event_index, severity, category, title) "
            "VALUES (?,?,?,?,?,?)",
            ("f1", sid, 0, "CRITICAL", "destructive", "Blocks world-writable chmod -R"))
        conn.commit()
    finally:
        conn.close()


def _detect(ws: Path, command: str):
    return detect_evasion(ws, "s1", {"type": "shell", "command": command}, [])


def test_dropping_the_blocked_segment_is_not_evasion(tmp_path):
    _seed(tmp_path, "s1")
    assert _detect(tmp_path, "mkdir -p uploads && ls -ld uploads") == []
    assert _detect(tmp_path, "mkdir -p uploads") == []


def test_rephrasing_the_blocked_part_is_still_evasion(tmp_path):
    _seed(tmp_path, "s1")
    found = _detect(tmp_path, "mkdir -p -m 777 uploads && ls -ld uploads")
    assert [f["ruleId"] for f in found] == ["evasion-detection"]


def _seed_cmd(ws: Path, sid: str, blocked: str) -> None:
    initialize_database(ws)
    conn = sqlite3.connect(get_db_path(ws))
    try:
        conn.execute(
            "INSERT INTO events (session_id, ts, type, agent_event, command_text, path_text, "
            "url_text, content_text, raw_json) VALUES (?,?,?,?,?,?,?,?,?)",
            (sid, "2026-10-08T00:00:00Z", "shell", "", blocked, "", "", "", "{}"))
        conn.execute(
            "INSERT INTO findings (finding_id, session_id, event_index, severity, category, title) "
            "VALUES (?,?,?,?,?,?)",
            ("f1", sid, 0, "CRITICAL", "destructive", "Blocked write"))
        conn.commit()
    finally:
        conn.close()


def test_readonly_command_is_never_evasion(tmp_path):
    # a blocked in-place sed write earlier in the session must not make a later
    # benign `sed -n '1,220p' file` read look like an evasion of it
    _seed_cmd(tmp_path, "s1", "sed -i 's/a/b/' prod.conf")
    assert _detect(tmp_path, "sed -n '1,220p' notes.md") == []
    assert _detect(tmp_path, "git diff -- a.py b.py") == []
