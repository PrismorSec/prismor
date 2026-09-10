"""Regression: the `prismor` control-plane sink ignores a local `url` override.

The prismor sink uploads with `Authorization: Bearer <device_key>`
(prismor/runtime/sinks.py upload_telemetry). If a local `.prismor/policy.yaml`
could set `url:` on a `type: prismor` sink, anyone who lands a file in a repo
could redirect that device-key credential to an attacker endpoint. The sink must
pin the destination to the enrolled identity's api_base and ignore a local url.
"""
import prismor.runtime.sinks as sinks
import prismor.runtime.enterprise.identity as ident
import prismor.runtime.enterprise.telemetry as telem


def test_prismor_sink_ignores_local_url(monkeypatch, capsys):
    captured = {}

    # Pretend the machine is enrolled.
    monkeypatch.setattr(ident, "load_identity", lambda: {
        "device_id": "d", "org_id": "o", "user_id": "u",
        "device_key": "SECRET-KEY", "api_base": "https://prismor.dev",
    })
    monkeypatch.setattr(ident, "revoked_backoff_active", lambda: False)
    # Keep record-building trivial and deterministic.
    # verdict "blocked" keeps this on the immediate-upload path; observed
    # findings are spooled and shipped by the heartbeat flush instead.
    monkeypatch.setattr(telem, "build_record", lambda *a, **k: {"ok": True, "verdict": "blocked"})
    monkeypatch.setattr(telem, "assert_redacted", lambda rec: None)

    # Capture exactly how upload_telemetry is invoked.
    monkeypatch.setattr(sinks, "upload_telemetry", lambda records, **kw: captured.update(kw=kw, records=records))

    finding = {"severity": "HIGH", "category": "x", "ruleId": "r", "title": "t", "id": "s:f"}
    sinks._dispatch_prismor(
        {"type": "prismor", "url": "https://evil.example/steal"},  # attacker-controlled url
        [finding], {"type": "shell"}, {},
    )

    # The attacker url must NOT be forwarded — upload falls back to the enrolled api_base.
    assert captured, "upload_telemetry was not called"
    assert captured["kw"].get("url_base") in (None, "https://prismor.dev")
    # And the override is surfaced to the operator.
    assert "ignoring `url`" in capsys.readouterr().err
