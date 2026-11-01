"""An agent's `prismor check` that comes back BLOCK reaches the org as an
observed "would block" record (demo finding #8). The agent stops after the
pre-check, so the hook never sees the command and nothing else is reported."""
from types import SimpleNamespace

import pytest

from prismor.runtime import cli
from prismor.runtime.enterprise import telemetry

_AGENT_VARS = ("AI_AGENT", "CLAUDECODE", "CODEX_THREAD_ID", "CODEX_SANDBOX", "CURSOR_AGENT", "GEMINI_CLI")
_CMD = "dangerous --thing /home/alice/secret-project"


@pytest.fixture
def captured(monkeypatch):
    for k in _AGENT_VARS:
        monkeypatch.delenv(k, raising=False)
    seen = []
    monkeypatch.setattr("prismor.runtime.sinks.dispatch",
                        lambda findings, sinks, extra=None, raw_event=None:
                        seen.append((findings, extra, raw_event)))
    return seen


def _engine():
    return SimpleNamespace(outputs=[{"type": "prismor"}], workspace_managed=False, active_exemption=None)


def _finding(mode="enforce"):
    return {"ruleId": "destructive-command", "severity": "critical", "category": "destructive",
            "action": "block", "mode": mode, "title": "Destructive command", "evidence": _CMD}


def test_agent_precheck_block_is_reported_as_would_block(tmp_path, monkeypatch, captured):
    monkeypatch.setenv("CLAUDECODE", "1")
    cli._report_agent_precheck(_engine(), [_finding()], tmp_path, "command", _CMD)
    (findings, extra, raw_event), = captured
    assert extra["agent"] == "claude"
    rec = telemetry.build_record(findings[0], raw_event, extra=extra)
    telemetry.assert_redacted(rec)
    assert rec["verdict"] == "observed"  # nothing ran; not counted as a block
    assert rec["title"].startswith("Agent pre-check would block")
    assert rec["tool_name"] == "prismor check"
    assert rec["rule_id"] == "destructive-command"
    # Redacted as usual: the command and its path never leave.
    assert "secret-project" not in str(rec) and "alice" not in str(rec)


def test_human_or_ci_check_is_not_reported(tmp_path, captured):
    cli._report_agent_precheck(_engine(), [_finding()], tmp_path, "command", _CMD)
    assert captured == []


def test_only_blocking_findings_are_reported(tmp_path, monkeypatch, captured):
    monkeypatch.setenv("CODEX_THREAD_ID", "t")
    cli._report_agent_precheck(_engine(), [_finding(), _finding(mode="observe")], tmp_path, "command", _CMD)
    (findings, extra, _), = captured
    assert len(findings) == 1 and extra["agent"] == "codex"


def test_a_failing_sink_never_changes_the_check(tmp_path, monkeypatch):
    monkeypatch.setenv("CLAUDECODE", "1")
    monkeypatch.setattr("prismor.runtime.runtime._dispatch_telemetry",
                        lambda **kw: (_ for _ in ()).throw(RuntimeError("boom")))
    cli._report_agent_precheck(_engine(), [_finding()], tmp_path, "command", _CMD)  # no raise


def test_check_command_reports_when_it_blocks(tmp_path, monkeypatch, captured):
    monkeypatch.setenv("CLAUDECODE", "1")
    calls = []
    monkeypatch.setattr(cli, "_report_agent_precheck", lambda *a: calls.append(a))
    monkeypatch.setattr(cli.PolicyEngine, "check_command", lambda self, v: [_finding()])
    with pytest.raises(SystemExit) as exc:
        cli.main(["--workspace", str(tmp_path), "check", _CMD])
    assert exc.value.code == 2
    assert calls and calls[0][3:] == ("command", _CMD)
