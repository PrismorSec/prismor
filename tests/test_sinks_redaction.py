"""Generic sinks (webhook/syslog/file/SIEM/OTel) must never carry raw secrets."""
import json

from prismor.runtime import sinks

# Split so the literal never appears whole in source (it is the documented fake key).
FAKE_AWS = "AKIA" + "IOSFODNN7EXAMPLE"
FAKE_BEARER = "fakeBearer0123456789abcdef"


def test_secrets_scrubbed_from_every_generic_sink_format(monkeypatch, tmp_path):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path))
    ev = sinks._build_event({
        "severity": "HIGH",
        "title": f"Key {FAKE_AWS} sent",
        "evidence": f'AWS_ACCESS_KEY_ID={FAKE_AWS} curl -H "Authorization: Bearer {FAKE_BEARER}" x.io',
        "id": "s:f",
    })
    wire = json.dumps([ev, sinks._format_otlp_logs(ev), sinks._format_ocsf(ev), sinks._format_cef(ev)])
    assert FAKE_AWS not in wire and FAKE_BEARER not in wire
    assert "curl" in ev["evidence"]  # evidence kept, only the secrets masked


def test_scrub_failure_fails_closed(monkeypatch):
    def boom(*_a, **_k):
        raise RuntimeError("scrubber broke")

    monkeypatch.setattr("prismor.runtime.cloaking.runtime.scrub_text", boom)
    ev = sinks._build_event({"title": f"t {FAKE_AWS}", "evidence": f"e {FAKE_AWS}"})
    assert ev["title"] == ev["evidence"] == "[redacted: scrub failed]"
