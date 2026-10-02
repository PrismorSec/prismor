"""AuthZEN Authorization API 1.0 on the eval-server, over real HTTP."""

import json
import threading
import urllib.error
import urllib.request

import pytest
import yaml

from prismor.runtime import authzen
from prismor.runtime.eval_server import EvalHandler, _ThreadingHTTPServer

POLICY = {"version": "1.0", "rules": [
    {"id": "owner-only", "severity": "HIGH", "category": "custom-authz", "title": "owner only",
     "event_types": ["shell"], "fields": ["tool_name"], "patterns": ["^delete_doc$"],
     "action": "block", "mode": "enforce", "when": "resource.attr.owner != principal.id"},
    {"id": "role-from-subject-props", "severity": "HIGH", "category": "custom-authz", "title": "admins",
     "event_types": ["shell"], "fields": ["tool_name"], "patterns": ["^purge$"],
     "action": "block", "mode": "enforce", "when": "'admin' not in principal.roles"},
]}


@pytest.fixture
def server(tmp_path, monkeypatch):
    for k in [k for k in __import__("os").environ if k.startswith("PRISMOR")]:
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / "home"))
    (tmp_path / ".prismor").mkdir()
    (tmp_path / ".prismor" / "policy.yaml").write_text(yaml.safe_dump(POLICY))
    monkeypatch.setattr(EvalHandler, "workspace", tmp_path)
    monkeypatch.setattr(EvalHandler, "api_key", None)
    srv = _ThreadingHTTPServer(("127.0.0.1", 0), EvalHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def _req(base, path, body=None, headers=None):
    req = urllib.request.Request(base + path, data=None if body is None else json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read()), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read()), dict(e.headers)


def _ev(user, owner, action="delete_doc"):
    return {"subject": {"type": "user", "id": user},
            "resource": {"type": "doc", "id": "d-1", "properties": {"owner": owner}},
            "action": {"name": action}}


def test_single_evaluation(server):
    s, body, _ = _req(server, "/access/v1/evaluation", _ev("alice", "alice"))
    assert s == 200 and body["decision"] is True
    s, body, _ = _req(server, "/access/v1/evaluation", _ev("mallory", "alice"))
    assert s == 200 and body["decision"] is False and body["context"]["rule_id"] == "owner-only"


def test_request_id_is_echoed(server):
    _, _, h = _req(server, "/access/v1/evaluation", _ev("alice", "alice"), {"X-Request-ID": "req-42"})
    assert h.get("X-Request-ID") == "req-42"


def test_subject_properties_cannot_grant_roles(server):
    ev = _ev("bob", "x", action="purge")
    ev["subject"]["properties"] = {"roles": ["admin"]}
    _, body, _ = _req(server, "/access/v1/evaluation", ev)
    assert body["decision"] is False


@pytest.mark.parametrize("bad", [
    {"resource": {"type": "doc", "id": "1"}, "action": {"name": "x"}},
    {**_ev("a", "a"), "subject": {"type": "user"}},
    {**_ev("a", "a"), "action": {}},
])
def test_malformed_is_400(server, bad):
    s, body, _ = _req(server, "/access/v1/evaluation", bad)
    assert s == 400 and "error" in body


def test_batch_defaults_and_semantics(server):
    base = {"subject": {"type": "user", "id": "alice"}, "action": {"name": "delete_doc"},
            "evaluations": [
                {"resource": {"type": "doc", "id": "1", "properties": {"owner": "alice"}}},
                {"resource": {"type": "doc", "id": "2", "properties": {"owner": "bob"}}},
                {"resource": {"type": "doc", "id": "3", "properties": {"owner": "alice"}}},
            ]}
    _, body, _ = _req(server, "/access/v1/evaluations", base)
    assert [e["decision"] for e in body["evaluations"]] == [True, False, True]
    _, body, _ = _req(server, "/access/v1/evaluations", {**base, "options": {"evaluations_semantic": "deny_on_first_deny"}})
    assert [e["decision"] for e in body["evaluations"]] == [True, False]
    _, body, _ = _req(server, "/access/v1/evaluations", {**base, "options": {"evaluations_semantic": "permit_on_first_permit"}})
    assert [e["decision"] for e in body["evaluations"]] == [True]
    s, _, _ = _req(server, "/access/v1/evaluations", {**base, "options": {"evaluations_semantic": "nope"}})
    assert s == 400


def test_metadata(server):
    s, body, _ = _req(server, "/.well-known/authzen-configuration")
    assert s == 200
    assert body["access_evaluation_endpoint"].endswith("/access/v1/evaluation")
    assert body["access_evaluations_endpoint"].endswith("/access/v1/evaluations")


def test_explain_via_context(server):
    ev = {**_ev("mallory", "alice"), "context": {"explain": True}}
    _, body, _ = _req(server, "/access/v1/evaluation", ev)
    assert any(r["rule_id"] == "owner-only" for r in body["context"]["explain"]["rules"])


def test_api_key_applies(server):
    EvalHandler.api_key = "k"
    try:
        s, _, _ = _req(server, "/access/v1/evaluation", _ev("alice", "alice"))
        assert s == 401
        s, _, _ = _req(server, "/access/v1/evaluation", _ev("alice", "alice"), {"Authorization": "Bearer k"})
        assert s == 200
    finally:
        EvalHandler.api_key = None
