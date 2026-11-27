"""Cloak hooks -> ledger -> telemetry record.

The bash cloak hooks append a line per catch to cloak_events.jsonl; the Python
hook drains it into findings. These tests run the real hooks and check that a
line carries the vault name and pattern but never the value, and that the
telemetry record built from it says what was redacted.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from prismor.runtime.cloaking import ledger
from prismor.runtime.enterprise import telemetry

_HOOKS = Path(__file__).resolve().parent.parent / "prismor" / "runtime" / "cloaking" / "hooks"
# Synthetic Groq-shaped canary, assembled at runtime so no literal token sits
# in this file (the cloaking Write guard would otherwise vault it).
_CANARY = "gsk_" + ("CANARY0" * 8)[:52]

pytestmark = pytest.mark.skipif(shutil.which("jq") is None, reason="cloak hooks need jq")


@pytest.fixture
def home(tmp_path, monkeypatch):
    (tmp_path / "secrets").mkdir()
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path))
    monkeypatch.setenv("PRISMOR_SECRETS_DIR", str(tmp_path / "secrets"))
    monkeypatch.setenv("PRISMOR_PROMPT_STASH_DIR", str(tmp_path / "stash"))
    monkeypatch.delenv("PRISMOR_CLOAK_LEDGER", raising=False)
    return tmp_path


def _run(script: str, payload: dict | str) -> str:
    data = payload if isinstance(payload, str) else json.dumps(payload)
    return subprocess.run(["bash", str(_HOOKS / script)], input=data, capture_output=True,
                          text=True, env=os.environ.copy(), timeout=30).stdout


def _lines(home: Path) -> list:
    path = home / "cloak_events.jsonl"
    return [json.loads(l) for l in path.read_text().splitlines()] if path.exists() else []


def test_prompt_secret_is_logged_by_name_not_value(home):
    assert len(_CANARY) == 56
    out = _run("userprompt-guard.sh", {"session_id": "s1", "prompt": f"use {_CANARY} please"})
    assert '"block"' in out
    [line] = _lines(home)
    assert line["source"] == "prompt" and line["action"] == "redacted"
    assert line["session_id"] == "s1" and line["name"].startswith("auto_")
    assert line["pattern"].startswith("gsk_")
    assert _CANARY not in (home / "cloak_events.jsonl").read_text()


def test_tool_input_secret_and_output_scrub(home):
    _run("secret-guard.sh", {"session_id": "s2", "tool_name": "Bash",
                             "tool_input": {"command": f"echo {_CANARY}"}})
    [line] = _lines(home)
    assert (line["source"], line["tool"]) == ("tool_input", "Bash")
    # The value is vaulted now, so a later command printing it gets scrubbed.
    env = {**os.environ, "PRISMOR_CLOAK_SESSION": "s2"}
    out = subprocess.run(["bash", str(_HOOKS / "scrub-stream.sh")], input=f"key={_CANARY}\n",
                         capture_output=True, text=True, env=env, timeout=30).stdout
    assert _CANARY not in out and "@@SECRET:auto_" in out
    assert [l["source"] for l in _lines(home)] == ["tool_input", "output"]


def test_clean_output_logs_nothing(home):
    (home / "secrets" / "api_key").write_text(_CANARY)
    subprocess.run(["bash", str(_HOOKS / "scrub-stream.sh")], input="nothing here\n",
                   capture_output=True, text=True, env=os.environ.copy(), timeout=30)
    assert _lines(home) == []


def test_drain_empties_ledger_and_builds_record(home):
    _run("userprompt-guard.sh", {"session_id": "s3", "prompt": f"token {_CANARY}"})
    records = ledger.drain()
    assert len(records) == 1 and ledger.drain() == []
    finding = ledger.to_finding(records[0])
    rec = telemetry.build_record(finding, {"type": "cloak", "occurred_at": records[0]["ts"]},
                                 {"session_id": "s3", "agent": "claude"})
    assert rec["rule_id"] == "cloak-prompt"
    assert rec["secret_name"] == records[0]["name"]
    assert rec["redaction_applied"] is True and rec["data_classes"] == ["secret"]
    assert rec["matched_pattern"].startswith("gsk_")
    telemetry.assert_redacted(rec)
    assert _CANARY not in json.dumps(rec)


def test_used_placeholder_reports_allowed(home):
    rec = telemetry.build_record(
        ledger.to_finding({"source": "command", "action": "used", "name": "stripe_key"}),
        {"type": "cloak"}, {})
    assert rec["verdict"] == "allowed" and rec["cloak_action"] == "used"
    assert not rec.get("redaction_applied")


def test_pii_entities_and_enforced_transform_map_to_redaction():
    rec = telemetry.build_record(
        {"ruleId": "pii-ner", "entities": ["PERSON", "US_SSN"], "mode": "enforce",
         "action": "modify", "transform": "pii_ner_redact"}, {"type": "prompt"}, {})
    assert rec["data_classes"] == ["PERSON", "US_SSN"] and rec["redaction_applied"] is True
    observed = telemetry.build_record(
        {"ruleId": "pii-ner", "entities": ["PERSON"], "mode": "observe", "action": "warn"},
        {"type": "prompt"}, {})
    assert not observed.get("redaction_applied")


def test_titles_survive_the_sink_scrubber():
    from prismor.runtime.sinks import _scrub_for_sink
    titles = [t for _, _, t in ledger._SOURCES.values()]
    assert [_scrub_for_sink(t) for t in titles] == titles


def test_malformed_and_unknown_lines_are_dropped(home):
    (home / "cloak_events.jsonl").write_text(
        'not json\n{"source":"bogus","action":"redacted"}\n'
        '{"source":"read","action":"blocked","name":"db_pass"}\n')
    [rec] = ledger.drain()
    assert rec["name"] == "db_pass"
    assert ledger.to_finding(rec)["mode"] == "enforce"


def test_env_guard_deny_is_queryable_and_holds_no_value(home, monkeypatch):
    from prismor.runtime import query, runtime, store
    from prismor.runtime.cloaking import installer

    value = "pw-" + "Zq8" * 6
    (home / "secrets" / "db_password").write_text(value)
    repo = home / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    (repo / "blog.md").write_text(f"title\n\nconnect with {value}\n")
    (repo / ".env").write_text("OTHER_TOKEN=" + "x9" * 12 + "\n")

    def call(cmd):
        return {"session_id": "s9", "tool_name": "Bash", "cwd": str(repo), "tool_input": {"command": cmd}}

    # `prismor check` runs the same hook but blocks nothing: nothing recorded.
    settings = repo / ".claude" / "settings.json"
    settings.parent.mkdir()
    settings.write_text(json.dumps({"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [
        {"type": "command", "command": f"bash {installer._ENV_GUARD}"}]}]}}))
    assert installer.precheck("Bash", {"command": "cat .env"}, workspace=repo, cwd=str(repo))
    assert _lines(home) == []

    out = _run("env-guard.sh", call("git add blog.md"))
    assert '"deny"' in out and "@@SECRET:db_password@@" in out and "'blog.md' line 3" in out
    assert value not in out
    assert '"deny"' in _run("env-guard.sh", call("cat .env"))
    assert [(l["source"], l["action"], l["session_id"]) for l in _lines(home)] == [("env_guard", "blocked", "s9")] * 2
    assert _lines(home)[0]["name"] == "db_password"
    assert value not in (home / "cloak_events.jsonl").read_text()

    # No sinks configured: the catches must still reach the local store.
    runtime._dispatch_cloak_ledger(engine=None, workspace=repo, agent="claude",
                                   session_id="later", subject=None)
    db = store.initialize_database(repo)
    rows = query.run_query("SELECT session_id, evidence FROM findings", db, workspace=repo)
    text = json.dumps(rows, default=str)
    assert len(rows) == 2 and "s9" in text
    assert "publish gate" in text and "db_password" in text and "OTHER_TOKEN" in text
    for f in Path(db).parent.glob(Path(db).name + "*"):
        assert value.encode() not in f.read_bytes()
    assert "x9" * 12 not in text


def test_push_deny_names_entry_file_and_line(home):
    from prismor.runtime.cloaking import publish_gate

    value = "pw-" + "Zq8" * 6
    (home / "secrets" / "db_password").write_text(value)
    repo = home / "repo"
    (repo / "posts").mkdir(parents=True)

    def git(*a):
        subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", *a], cwd=repo,
                       check=True, capture_output=True)
    git("init", "-q")
    (repo / "posts" / "a.md").write_text(f"one\n{value}\n")
    git("add", "-A")
    git("commit", "-qm", "post")
    reason = publish_gate.check("git push origin main", str(repo), {value})
    assert "@@SECRET:db_password@@ (in 'posts/a.md' line 2)" in reason and value not in reason
