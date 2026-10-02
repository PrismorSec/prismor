"""eval-server over HTTP: arguments and resource reach `when:` rules."""

import json
import threading
import urllib.request

import pytest
import yaml

from prismor.runtime import eval_server
from prismor.runtime.eval_server import EvalHandler, _ThreadingHTTPServer

_RULE = {
    "id": "owner-only", "severity": "HIGH", "category": "custom-authz",
    "title": "Only the owner may delete", "event_types": ["shell"],
    "fields": ["tool_name"], "patterns": ["^delete_doc$"], "action": "block",
    "mode": "enforce", "when": "resource.attr.owner != principal.id",
}


@pytest.fixture
def server(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / "home"))
    (tmp_path / ".prismor").mkdir()
    (tmp_path / ".prismor" / "policy.yaml").write_text(
        yaml.safe_dump({"version": "1.0", "rules": [_RULE]}))
    monkeypatch.setattr(EvalHandler, "workspace", tmp_path)
    monkeypatch.setattr(EvalHandler, "api_key", None)
    srv = _ThreadingHTTPServer(("127.0.0.1", 0), EvalHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def _post(base, body):
    req = urllib.request.Request(
        base + "/v1/evaluate", data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read())


def _call(base, user):
    return _post(base, {
        "tool_name": "delete_doc", "arguments": {"doc": "d-1"}, "subject": f"user:{user}",
        "resource": {"kind": "doc", "id": "d-1", "attr": {"owner": "alice"}},
    })


def test_resource_attrs_drive_decision(server):
    assert _call(server, "alice")["allow"] is True
    out = _call(server, "mallory")
    assert out["allow"] is False and out["rule_id"] == "owner-only"


def test_resolved_subject_is_stamped(server):
    out = _call(server, "alice")
    assert out["subject"]["user_id"] == "alice"


def test_build_event_keeps_kwargs_and_resource():
    ev = eval_server._build_event(
        tool_name="t", arguments={"a": 1}, event_type="shell", agent="sdk",
        session_id="s", resource={"kind": "x"})
    assert ev["metadata"]["kwargs"] == {"a": 1}
    assert ev["metadata"]["resource"] == {"kind": "x"}
    assert "subject" not in ev["metadata"]
