"""#538: evasion-detection must not block the benign subset of a blocked command."""
import json
import sqlite3
from pathlib import Path

import pytest

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


# #595: a block that came from session state is not a pattern to evade.
SED_A = "sed -n '10,20p' prismor/runtime/hooks.py"
SED_B = "sed -n '30,40p' prismor/runtime/hooks.py"


def _seed_rule(ws: Path, rule_id: str) -> None:
    initialize_database(ws)
    conn = sqlite3.connect(get_db_path(ws))
    try:
        conn.execute(
            "INSERT INTO events (session_id, ts, type, agent_event, command_text, path_text, "
            "url_text, content_text, raw_json) VALUES (?,?,?,?,?,?,?,?,?)",
            ("s1", "2026-10-08T00:00:00Z", "shell", "", SED_A, "", "", "", "{}"))
        conn.execute(
            "INSERT INTO findings (finding_id, session_id, event_index, severity, category, title, "
            "enrichment_json) VALUES (?,?,?,?,?,?,?)",
            ("f1", "s1", 0, "CRITICAL", "x", "blocked", json.dumps({"ruleId": rule_id})))
        conn.commit()
    finally:
        conn.close()


@pytest.mark.parametrize("rule_id", ["tag-rule:00d30a0689", "staged-execution"])
def test_retry_after_a_session_state_block_is_not_evasion(tmp_path, rule_id):
    _seed_rule(tmp_path, rule_id)
    assert _detect(tmp_path, SED_B) == []


def test_same_shape_after_a_pattern_block_is_still_evasion(tmp_path):
    _seed_rule(tmp_path, "destructive-command")
    assert [f["ruleId"] for f in _detect(tmp_path, SED_B)] == ["evasion-detection"]
