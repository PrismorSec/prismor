"""An SDK agent's PRISMOR_AGENT_KEY identity keeps its own spool and revoked marker.

Found on prod: a LangChain agent run with a freshly minted agent key on a
developer machine drained the machine's telemetry spool (queued Claude Code
hook events) and uploaded it under the agent's service identity, so the
console showed a phantom "Claude Code" agent on that key. And a rejected agent
key wrote the machine's device-revoked marker, silencing its own hooks.
"""
import json

import prismor.runtime.sinks as sinks
import prismor.runtime.enterprise.identity as ident
import prismor.runtime.enterprise.telemetry_spool as spool


class _Resp:
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self, n=-1):
        return b"{}"


def _machine(monkeypatch, tmp_path):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path))
    monkeypatch.delenv("PRISMOR_AGENT_KEY", raising=False)
    ident.save_identity({
        "device_id": "laptop", "org_id": "o", "user_id": "u",
        "device_key": "prism_dev_laptop", "api_base": "http://127.0.0.1:1",
    })
    posts = []

    def fake_urlopen(req, timeout=None):
        posts.append({"auth": req.headers.get("Authorization"), "events": json.loads(req.data)["events"]})
        return _Resp()

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    return posts


def _rec(tag):
    return {"ts": "2099-01-01T00:00:00Z", "verdict": "observed", "tag": tag}


def test_agent_key_upload_does_not_drain_the_machines_spool(monkeypatch, tmp_path):
    posts = _machine(monkeypatch, tmp_path)
    spool.append([_rec("claude-code-hook")])  # queued by the machine's hooks
    assert spool.pending_count() == 1

    monkeypatch.setenv("PRISMOR_AGENT_KEY", "prism_agent_sdk")
    sinks.upload_telemetry([_rec("langchain")])

    assert len(posts) == 1
    assert posts[0]["auth"] == "Bearer prism_agent_sdk"
    assert [r["tag"] for r in posts[0]["events"]] == ["langchain"]

    # Back as the machine: its hook event is still queued and goes up under its own key.
    monkeypatch.delenv("PRISMOR_AGENT_KEY")
    assert spool.pending_count() == 1
    sinks.upload_telemetry([])
    assert posts[1]["auth"] == "Bearer prism_dev_laptop"
    assert [r["tag"] for r in posts[1]["events"]] == ["claude-code-hook"]


def test_each_agent_key_has_its_own_spool(monkeypatch, tmp_path):
    _machine(monkeypatch, tmp_path)
    paths = set()
    for key in ("", "prism_agent_a", "prism_agent_b"):
        if key:
            monkeypatch.setenv("PRISMOR_AGENT_KEY", key)
        else:
            monkeypatch.delenv("PRISMOR_AGENT_KEY", raising=False)
        paths.add((spool.spool_path(), spool.drops_path(), spool.backoff_path()))
    assert len(paths) == 3
    # The enrolled machine keeps today's file names: nothing already spooled is stranded.
    monkeypatch.delenv("PRISMOR_AGENT_KEY")
    assert spool.spool_path().name == "telemetry-spool.jsonl"
    assert ident._revoked_marker_path().name == "device-revoked.json"
    # The key itself never lands in a file name.
    monkeypatch.setenv("PRISMOR_AGENT_KEY", "prism_agent_secretvalue")
    assert "secretvalue" not in str(spool.spool_path())


def test_rejected_agent_key_does_not_mark_the_machine_revoked(monkeypatch, tmp_path):
    _machine(monkeypatch, tmp_path)
    monkeypatch.setenv("PRISMOR_AGENT_KEY", "prism_agent_typo")
    ident.mark_revoked("401 from control plane")
    assert ident.revoked_info() is not None  # the agent key is backed off...

    monkeypatch.delenv("PRISMOR_AGENT_KEY")
    assert ident.revoked_info() is None  # ...the laptop's enrollment is not
    assert not ident.revoked_backoff_active()
