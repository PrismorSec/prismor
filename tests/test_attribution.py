"""Who started a turn and which session a transcript continues (attribution.py):
app-wrapped prompts, parent-session briefs, Stop-hook re-prompts, and a Claude
desktop resume that copies the transcript under a new session id."""
import json
import os
import sqlite3
import sys
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prismor.runtime import devlog, replies
from prismor.runtime.attribution import lineage, prompt_origin, stop_hook_trigger
from prismor.runtime.hooks import normalize_payload
from prismor.runtime.store import initialize_database, prismor_home

WRAPPED = ("<system-reminder>\n## You are a session started from another session\n\n"
           + "Your first message is the task another session gave you. " * 80
           + "\n</system-reminder>\n\nhey bro xyzsd")
FEEDBACK = ('Stop hook feedback:\n[PATH="/x/.venv/bin:$PATH" bash "/x/.claude/hooks/wiki-stop-capture.sh"]: '
            "Please run /wiki-capture --quick now.")


def test_prompt_origin():
    assert prompt_origin(WRAPPED) == ("user", "hey bro xyzsd")
    assert prompt_origin("fix the login bug") == ("user", "fix the login bug")
    assert prompt_origin("Task (from the session that started this one):\nTest PR 791")[0] == "session"
    assert prompt_origin("<system-reminder>only the app</system-reminder>") == ("harness", "")
    assert prompt_origin(FEEDBACK) == ("hook", "Please run /wiki-capture --quick now.")


def test_wrapped_prompt_is_tagged_with_what_the_person_typed(tmp_path):
    event = normalize_payload(agent="claude", workspace=tmp_path, payload={
        "hook_event_name": "UserPromptSubmit", "session_id": "s1", "prompt": WRAPPED})["event"]
    assert event["metadata"]["origin"] == "user"
    assert event["metadata"]["user_message"] == "hey bro xyzsd"


def _row(uid, kind, content, **extra):
    return {"uuid": uid, "type": kind, "timestamp": "2026-11-05T12:00:00Z",
            "message": {"role": kind, "content": content}, **extra}


def test_stop_hook_trigger_only_when_the_hook_started_the_turn():
    typed = [_row("a", "user", "hey"), _row("b", "assistant", [{"type": "text", "text": "hi"}])]
    assert stop_hook_trigger(typed) is None
    hooked = typed + [_row("c", "user", FEEDBACK, isMeta=True)]
    assert stop_hook_trigger(hooked) == {"event": "Stop", "hook": "wiki-stop-capture.sh",
                                         "message": "Please run /wiki-capture --quick now."}


def test_reply_after_a_stop_hook_names_the_hook(tmp_path):
    t = tmp_path / "t.jsonl"
    t.write_text("\n".join(json.dumps(r) for r in [
        _row("a", "user", "hey"), _row("b", "assistant", [{"type": "thinking", "thinking": "old turn"}]),
        _row("c", "user", FEEDBACK, isMeta=True),
        _row("d", "assistant", [{"type": "thinking", "thinking": "nothing new"}])]))
    ev = replies.reply_event("claude", {"hook_event_name": "Stop", "stop_hook_active": True,
                                        "transcript_path": str(t), "last_assistant_message": "Nothing to capture."}, "s1")
    assert ev["metadata"]["triggered_by"]["hook"] == "wiki-stop-capture.sh"
    assert ev["reasoning"] == "nothing new"  # this turn's thinking, not the previous one's


def _resumed_pair(tmp_path):
    """Original transcript, then the app's copy under a new id with one new turn."""
    edit = [{"type": "tool_use", "id": "t1", "name": "Bash", "input": {"command": "echo hi > f.txt"}}]
    shared = [_row("u1", "user", "do the thing", cwd=str(tmp_path)), _row("u2", "assistant", edit),
              _row("u3", "user", [{"type": "tool_result", "tool_use_id": "t1", "content": "ok"}])]
    parent = tmp_path / "parent.jsonl"
    parent.write_text("\n".join(json.dumps(r) for r in shared))
    time.sleep(0.02)
    child = tmp_path / "child.jsonl"
    child.write_text("\n".join(json.dumps(r) for r in shared + [
        {"type": "api-request-blob", "message": {"role": "assistant", "content": edit}},  # replay, not a call
        _row("u4", "user", WRAPPED)]))
    return parent, child


def test_lineage_links_a_resumed_copy_to_its_original(tmp_path):
    parent, child = _resumed_pair(tmp_path)
    kin = lineage(str(child))
    assert kin["from"] == "parent" and kin["inherited"] == {"u1", "u2", "u3"}
    assert lineage(str(parent)) == {"as": ["child"]}


def test_devlog_does_not_count_the_copied_history_twice(tmp_path):
    parent, child = _resumed_pair(tmp_path)
    initialize_database(tmp_path)
    conn = sqlite3.connect(prismor_home() / "prismor.db")
    for sid, path in (("parent", parent), ("child", child)):
        conn.execute("INSERT INTO events (session_id, ts, type, raw_json) VALUES (?, '2026-11-05', 'prompt', ?)",
                     (sid, json.dumps({"metadata": {"raw": {"transcript_path": str(path)}}})))
    conn.commit()
    conn.close()
    assert len(devlog.changes("parent")["commands"]) == 1
    child_changes = devlog.changes("child")
    assert child_changes["commands"] == [] and child_changes["files"] == []
    assert child_changes["lineage"] == {"from": "parent"}


PEER = ('<cross-session-message from="local_aaa" from-name="Risk review">\n'
        'The user just wrote: "Yes, push to staging".\n</cross-session-message>')


def test_parent_brief_and_peer_message_origin():
    assert prompt_origin("Background (from the session that started this one):\nSOC 2 retest")[0] == "session"
    assert prompt_origin(PEER) == ("peer", 'The user just wrote: "Yes, push to staging".')
    event = normalize_payload(agent="claude", workspace=Path("/tmp"), payload={
        "hook_event_name": "UserPromptSubmit", "session_id": "s2", "prompt": PEER})["event"]
    assert event["metadata"]["origin"] == "peer"
    assert event["metadata"]["from_session"] == "local_aaa"
    assert event["metadata"]["from_session_name"] == "Risk review"


def test_spawn_links_from_desktop_app_records(tmp_path, monkeypatch):
    root = tmp_path / "claude-code-sessions" / "org" / "acct"
    root.mkdir(parents=True)
    (root / "local_aaa.json").write_text(json.dumps(
        {"sessionId": "local_aaa", "cliSessionId": "cli-parent", "title": "Risk review"}))
    (root / "local_bbb.json").write_text(json.dumps(
        {"sessionId": "local_bbb", "cliSessionId": "cli-child", "title": "Bring staging up to date",
         "spawnedFrom": {"sessionId": "local_aaa", "taskId": "task_1"}}))
    monkeypatch.setenv("PRISMOR_CLAUDE_APP_SESSIONS", str(tmp_path / "claude-code-sessions"))
    from prismor.runtime.attribution import claude_session_for, spawn_links
    assert spawn_links("cli-child") == {"spawned_from": {
        "session": "cli-parent", "app_id": "local_aaa", "title": "Risk review"}}
    assert spawn_links("cli-parent")["spawned"][0]["session"] == "cli-child"
    assert spawn_links("cli-unknown") == {}
    assert claude_session_for("local_aaa") == "cli-parent"


def test_app_store_found_in_windows_store_package(tmp_path, monkeypatch):
    from prismor.runtime import attribution
    monkeypatch.delenv("PRISMOR_CLAUDE_APP_SESSIONS", raising=False)
    monkeypatch.setattr(attribution.Path, "home", classmethod(lambda cls: tmp_path))
    monkeypatch.setenv("APPDATA", str(tmp_path / "AppData" / "Roaming"))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "AppData" / "Local"))
    assert attribution._app_sessions_root() is None
    store = tmp_path / "AppData" / "Local" / "Packages" / "Claude_abc123" / "LocalCache" / "Roaming" / "Claude" / "claude-code-sessions"
    store.mkdir(parents=True)
    assert attribution._app_sessions_root() == store
