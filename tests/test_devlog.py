"""prismor rca / blame / friction / session --changes, and the PostToolUseFailure
loop warning, over a synthetic Claude transcript and a fresh store
(conftest gives every test its own $PRISMOR_HOME)."""
import json
import os
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prismor.runtime import devlog
from prismor.runtime.store import initialize_database, prismor_home

SID = "s-devlog"


def _use(i, name, inp):
    return {"type": "assistant", "timestamp": f"2026-10-07T10:00:{i:02d}Z",
            "message": {"content": [{"type": "tool_use", "id": f"t{i}", "name": name, "input": inp}]}}


def _result(i, error=None, denied=False):
    rec = {"type": "user", "timestamp": f"2026-10-07T10:00:{i:02d}Z",
           "message": {"content": [{"type": "tool_result", "tool_use_id": f"t{i}",
                                    "is_error": bool(error), "content": error or "ok"}]}}
    if denied:
        rec["toolDenialKind"] = "hook"
    return rec


def _seed(tmp_path: Path, target: Path) -> None:
    edit = {"file_path": str(target), "old_string": "a = 1", "new_string": "a = 2"}
    undo = {"file_path": str(target), "old_string": "a = 2", "new_string": "a = 1"}
    recs = [{"type": "user", "gitBranch": "fix/x", "timestamp": "2026-10-07T10:00:00Z",
             "message": {"content": "make the tests pass"}}]
    recs += [_use(1, "Edit", edit), _result(1)]
    for i in (2, 3, 4):  # same failing command three times: a loop
        recs += [_use(i, "Bash", {"command": "pytest -q"}),
                 _result(i, "Exit code 1\nTraceback (most recent call last):\nImportError: no foo")]
    recs += [_use(5, "Bash", {"command": "cat .env"}), _result(5, "Blocked by policy", denied=True)]
    recs += [_use(6, "Edit", undo), _result(6), _use(7, "Bash", {"command": "pytest -q -x"}), _result(7)]
    transcript = tmp_path / "t.jsonl"
    transcript.write_text("\n".join(json.dumps(r) for r in recs))

    initialize_database(tmp_path)
    conn = sqlite3.connect(prismor_home() / "prismor.db")
    raw = lambda extra: json.dumps({"metadata": {"raw": {"transcript_path": str(transcript), **extra}}})
    conn.execute("INSERT INTO sessions (session_id, agent, source, workspace_path, started_at, updated_at) "
                 "VALUES (?, 'claude', 'hook', ?, datetime('now'), datetime('now'))", (SID, str(tmp_path)))
    conn.execute("INSERT INTO events (session_id, ts, type, agent_event, raw_json) VALUES (?, 't0', 'prompt', "
                 "'UserPromptSubmit', ?)", (SID, raw({"prompt": "make the tests pass"})))
    conn.execute("INSERT INTO events (session_id, ts, type, agent_event, path_text, raw_json) VALUES "
                 "(?, 't1', 'file_write', 'PostToolUse', ?, ?)",
                 (SID, str(target), raw({"tool_use_id": "t1", "tool_input": edit})))
    conn.commit()
    conn.close()


def test_rca_changes_blame(tmp_path):
    target = tmp_path / "mod.py"
    target.write_text("x = 0\na = 2\n")
    _seed(tmp_path, target)

    r = devlog.rca(SID)
    assert (r["failures"], r["denied"], r["branch"]) == (3, 1, "fix/x")
    assert r["firstFailure"]["error"] == "ImportError: no foo"
    assert [(l["detail"], l["count"]) for l in r["loops"]] == [("pytest -q", 3)]
    assert [v["path"] for v in r["reverts"]] == [str(target)]

    ch = devlog.changes(SID)
    f0 = ch["files"][0]
    assert (f0["path"], f0["writes"], f0["added"], f0["removed"]) == (str(target), 2, 2, 2)
    assert f0["diff"] == ["@@", "-a = 1", "+a = 2", "@@", "-a = 2", "+a = 1"]
    assert "- make the tests pass" in ch["prDescription"] and "`pytest -q -x`" in ch["prDescription"]

    hit = devlog.blame(str(target), line=2)
    assert hit["text"] == "a = 2" and hit["writes"][0]["prompt"] == "make the tests pass"
    assert hit["writes"][0]["diff"] == ["@@", "-a = 1", "+a = 2"]
    assert devlog.blame(str(target), line=1)["writes"] == []  # line 1 was never written by an agent
    assert [f["path"] for f in devlog.files("mod.py")["files"]] == [str(target)]

    f = devlog.friction(days=1)
    assert f["sessions"] == 1 and f["patterns"] == []  # one session is not a pattern


def test_loop_warning_on_third_identical_failure():
    p = {"session_id": "s1", "tool_name": "Bash", "tool_input": {"command": "make"}, "error": "Exit code 2\nno rule"}
    assert devlog.on_failure(p) is None and devlog.on_failure(p) is None
    out = devlog.on_failure(p)["hookSpecificOutput"]
    assert out["hookEventName"] == "PostToolUseFailure" and "failed 3 times" in out["additionalContext"]
    assert devlog.on_failure({**p, "tool_input": {"command": "make test"}}) is None  # different call


def test_claude_patch_wins_over_text_diff():
    patch = {"structuredPatch": [{"oldStart": 4, "oldLines": 1, "newStart": 4, "newLines": 1,
                                  "lines": ["-x = 1", "+x = 2"]}]}
    call = {"tool": "Write", "input": {"content": "whole new file"}}
    assert devlog._call_diff(call, patch) == ["@@ -4,1 +4,1 @@", "-x = 1", "+x = 2"]
    assert devlog._call_diff(call, {"type": "create", "structuredPatch": [], "content": "a\nb"}) == ["@@ new file", "+a", "+b"]
    assert devlog._call_diff(call, None) == ["@@", "+whole new file"]  # no result: text fallback
