"""The eval-server's simple ``POST /v1/evaluate`` form carries caller metadata
and a budget, the way the in-process client does (PrismorSec/prismor#281)."""
from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request

from prismor.runtime.eval_server import EvalHandler, _ThreadingHTTPServer
from prismor.runtime.runtime import Decision


def _post(port, path, body, headers=None):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def _options(port, path):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", method="OPTIONS")
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.status, dict(r.headers)


def _serve(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / "home"))
    handler = type("H", (EvalHandler,), {"workspace": tmp_path, "api_key": None})
    srv = _ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _spy(monkeypatch):
    calls = []

    def evaluate(**kwargs):
        calls.append(kwargs)
        return Decision(allow=True)

    monkeypatch.setattr("prismor.runtime.eval_server.evaluate_tool_call", evaluate)
    return calls


def test_simple_form_merges_metadata_and_budget_and_server_keys_win(tmp_path, monkeypatch):
    calls = _spy(monkeypatch)
    srv = _serve(tmp_path, monkeypatch)
    try:
        status, body = _post(srv.server_address[1], "/v1/evaluate", {
            "tool_name": "run_shell", "arguments": {"command": "echo hi"},
            "metadata": {"trace_id": "t-1", "surface": "spoofed", "tool_name": "x",
                         "subject": "user:mallory"},
            "budget": {"max_calls": 3},
        })
        assert status == 200 and body["allow"] is True
        meta = calls[0]["event"]["metadata"]
        assert meta["trace_id"] == "t-1"
        assert meta["budget"] == {"max_calls": 3}
        assert meta["surface"] == "eval-server"
        assert meta["tool_name"] == "run_shell"
        assert meta["subject"] is None  # the subject comes from the header/body field, never metadata
    finally:
        srv.shutdown()


def test_simple_form_without_metadata_is_unchanged(tmp_path, monkeypatch):
    calls = _spy(monkeypatch)
    srv = _serve(tmp_path, monkeypatch)
    try:
        status, _ = _post(srv.server_address[1], "/v1/evaluate", {"tool_name": "t", "arguments": {"a": 1}})
        assert status == 200
        assert "budget" not in calls[0]["event"]["metadata"]
    finally:
        srv.shutdown()


def test_simple_form_rejects_non_object_metadata(tmp_path, monkeypatch):
    _spy(monkeypatch)
    srv = _serve(tmp_path, monkeypatch)
    try:
        status, body = _post(srv.server_address[1], "/v1/evaluate",
                             {"tool_name": "t", "arguments": {}, "metadata": "nope"})
        assert status == 400 and "metadata" in body["error"]
    finally:
        srv.shutdown()


def test_canonical_event_form_accepts_budget(tmp_path, monkeypatch):
    calls = _spy(monkeypatch)
    srv = _serve(tmp_path, monkeypatch)
    try:
        event = {"type": "shell", "command": "echo hi", "agent_event": "PreToolUse",
                 "metadata": {"tool_name": "run_shell"}}
        status, _ = _post(srv.server_address[1], "/v1/evaluate", {"event": event, "budget": 5})
        assert status == 200
        assert calls[0]["event"]["metadata"]["budget"] == 5
    finally:
        srv.shutdown()


def test_preflight_allows_the_agent_name_header(tmp_path, monkeypatch):
    srv = _serve(tmp_path, monkeypatch)
    try:
        status, headers = _options(srv.server_address[1], "/v1/evaluate")
        assert status == 204
        assert "X-Prismor-Agent-Name" in headers["Access-Control-Allow-Headers"]
    finally:
        srv.shutdown()
