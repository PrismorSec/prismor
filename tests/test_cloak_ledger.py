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
