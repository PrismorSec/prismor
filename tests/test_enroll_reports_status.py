"""`prismor enroll` reports hook coverage before it returns (demo finding #14).

The console's Coverage column reads device_status, which otherwise only rode
the first heartbeat flush, so a just-enrolled device showed "not reported"."""
from prismor.runtime import cli
from prismor.runtime.enterprise import heartbeat, identity, remote_policy


def test_enroll_uploads_device_status_for_the_workspace(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / ".prismor"))
    ws = tmp_path / "acme-app"
    ws.mkdir()
    monkeypatch.setattr(identity, "enroll", lambda token, base=None, label=None: {
        "org_name": "acme", "device_id": "d1", "label": "laptop"})
    monkeypatch.setattr(remote_policy, "fetch", lambda **_: None)
    monkeypatch.setattr("prismor.runtime.discover.send_report", lambda *a, **k: None)
    monkeypatch.setattr(cli, "_offer_post_enroll_install", lambda w: None)
    seen = []
    monkeypatch.setattr(heartbeat, "device_status_record",
                        lambda w=None: seen.append(w) or {"type": "device_status"})
    sent = []
    monkeypatch.setattr("prismor.runtime.sinks.upload_telemetry", lambda recs, **kw: sent.extend(recs))
    cli.main(["--workspace", str(ws), "enroll", "tok"])
    assert [r["type"] for r in sent] == ["device_status"]
    assert seen and seen[0].resolve() == ws.resolve()
