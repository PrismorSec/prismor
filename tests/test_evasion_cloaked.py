"""#808: the shell learning detectors must see (and store) the cloaked command.

A PostToolUse event carries the decloaked command. Before the fix the evasion
detector compared it against the placeholder form stored for the same call's
PreToolUse, called the pair an evasion, and wrote the raw secret to
``evasion_attempts``.
"""
import sqlite3

from prismor.runtime import learning
from prismor.runtime.learning import initialize_learning_tables
from prismor.runtime.runtime import evaluate_tool_call
from prismor.runtime.store import get_db_path, initialize_database

NAME = "FAKE_808_KEY"
VALUE = "Zq7xP2mLw9Rt4vBnK3"
PLACEHOLDER = "@@SECRET:" + NAME + "@@"


def _vault(tmp_path, monkeypatch):
    sdir = tmp_path / "secrets"
    sdir.mkdir()
    (sdir / NAME).write_text(VALUE)
    monkeypatch.setenv("PRISMOR_SECRETS_DIR", str(sdir))


def test_detectors_receive_recloaked_post_event(tmp_path, monkeypatch):
    _vault(tmp_path, monkeypatch)
    seen = []
    for name in ("detect_evasion", "detect_staged_execution"):
        monkeypatch.setattr(learning, name, lambda ws, sid, ev, f, _n=name: seen.append((_n, ev["command"])) or [])

    ws = tmp_path / "ws"
    (ws / ".prismor").mkdir(parents=True)
    event = {"type": "shell", "agent_event": "PostToolUse", "metadata": {"tool_name": "Bash"},
             "command": f"echo hello && echo {VALUE}"}
    evaluate_tool_call(event=event, workspace=ws, agent="claude", mode="observe",
                       session_id="s808", persist=True)

    assert [n for n, _ in seen] == ["detect_evasion", "detect_staged_execution"]
    for _, command in seen:
        assert VALUE not in command
        assert command == f"echo hello && echo {PLACEHOLDER}"


def test_existing_learning_rows_are_recloaked_once(tmp_path, monkeypatch):
    _vault(tmp_path, monkeypatch)
    ws = tmp_path / "ws"
    (ws / ".prismor").mkdir(parents=True)
    db = get_db_path(ws)
    db.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db)
    initialize_learning_tables(conn)
    conn.execute(
        "INSERT INTO evasion_attempts (session_id, blocked_rule_id, blocked_command, evading_command, "
        "similarity_score, detected_at) VALUES ('s', 'r', ?, ?, 0.6, 'now')",
        (f"echo {PLACEHOLDER}", f"echo {VALUE}"))
    conn.execute(
        "INSERT INTO staged_executions (session_id, category, created_path, created_origin, "
        "created_evidence, executing_command, detected_at) VALUES ('s', 'c', 'p', 'o', 'e', ?, 'now')",
        (f"sh run.sh {VALUE}",))
    conn.commit()
    conn.close()

    initialize_database(ws)

    conn = sqlite3.connect(db)
    rows = conn.execute("SELECT blocked_command, evading_command FROM evasion_attempts").fetchall()
    staged = conn.execute("SELECT executing_command FROM staged_executions").fetchall()
    conn.close()
    assert rows == [(f"echo {PLACEHOLDER}", f"echo {PLACEHOLDER}")]
    assert staged == [(f"sh run.sh {PLACEHOLDER}",)]
