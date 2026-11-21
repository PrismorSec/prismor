"""eval-server is shared by every caller: an anonymous caller gets a session of
its own, and nothing is written to a session transcript per request.

Before, every caller without a session_id shared ``eval-<pid>``: one injected
tool result tainted it, and every later anonymous network call was refused
(taint-escalation) until the server restarted."""

import json
import threading
import urllib.request

import pytest
import yaml

from prismor.runtime.eval_server import EvalHandler, _ThreadingHTTPServer

_RULE = {
    "id": "probe-rule", "severity": "HIGH", "category": "custom-authz",
    "title": "probe", "event_types": ["shell"], "fields": ["tool_name"],
    "patterns": ["^probe$"], "action": "block", "mode": "enforce",
}


@pytest.fixture
def server(tmp_path, monkeypatch):
    home = tmp_path / "home"
    monkeypatch.setenv("PRISMOR_HOME", str(home))
    (tmp_path / ".prismor").mkdir()
    (tmp_path / ".prismor" / "policy.yaml").write_text(
        yaml.safe_dump({"version": "1.0", "rules": [_RULE]}))
    monkeypatch.setattr(EvalHandler, "workspace", tmp_path)
    monkeypatch.setattr(EvalHandler, "api_key", None)
    srv = _ThreadingHTTPServer(("127.0.0.1", 0), EvalHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}", home
    srv.shutdown()


def _post(base, body):
    req = urllib.request.Request(base + "/v1/evaluate", data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read())


def _session_of(decision):
    return decision["blocking"]["id"].split(":", 1)[0]


def test_anonymous_callers_do_not_share_a_session(server):
    base, _ = server
    a = _post(base, {"tool_name": "probe", "arguments": {}})
    b = _post(base, {"tool_name": "probe", "arguments": {}})
    raw = _post(base, {"event": {"type": "shell", "command": "x",
                                 "metadata": {"tool_name": "probe"}}})
    assert len({_session_of(a), _session_of(b), _session_of(raw)}) == 3


def test_a_named_session_is_kept(server):
    base, _ = server
    out = _post(base, {"tool_name": "probe", "arguments": {}, "session_id": "tenant-a"})
    assert _session_of(out) == "tenant-a"


def test_requests_write_no_session_transcript(server):
    base, home = server
    for _ in range(3):
        _post(base, {"tool_name": "probe", "arguments": {}, "session_id": "tenant-a"})
    assert not list(home.glob("sessions/*.jsonl"))
