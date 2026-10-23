"""Hosted evaluation: PRISMOR_EVAL_URL sends evaluate_tool_call to an eval-server,
and the Lambda entrypoint serves the same routes."""

import importlib
import json
import threading
from pathlib import Path

import pytest
import yaml

from prismor.runtime import remote_eval
from prismor.runtime.eval_server import EvalHandler, _ThreadingHTTPServer
from prismor.runtime.runtime import evaluate_tool_call
from prismor.runtime.store import read_session_events

KEY = "test-eval-key"
_RULE = {
    "id": "no-danger", "severity": "HIGH", "category": "custom", "title": "danger is blocked",
    "event_types": ["shell"], "patterns": ["\\bdanger\\b"], "action": "block", "mode": "enforce",
}


def _policy_ws(path: Path) -> Path:
    (path / ".prismor").mkdir(parents=True)
    (path / ".prismor" / "policy.yaml").write_text(yaml.safe_dump({"version": "1.0", "rules": [_RULE]}))
    return path


@pytest.fixture
def hosted(tmp_path, monkeypatch):
    """An eval-server holding the policy, and a client env pointed at it."""
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / "home"))
    monkeypatch.setattr(remote_eval, "SERVING", False)
    server_ws = _policy_ws(tmp_path / "server")
    monkeypatch.setattr(EvalHandler, "workspace", server_ws)
    monkeypatch.setattr(EvalHandler, "api_key", KEY)
    srv = _ThreadingHTTPServer(("127.0.0.1", 0), EvalHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    monkeypatch.setenv("PRISMOR_EVAL_URL", f"http://127.0.0.1:{srv.server_address[1]}")
    monkeypatch.setenv("PRISMOR_EVAL_KEY", KEY)
    yield server_ws, tmp_path / "client"
    srv.shutdown()


def _call(client_ws, command, mode="enforce", sid="s1"):
    client_ws.mkdir(exist_ok=True)
    event = {"type": "shell", "command": command, "agent_event": "PreToolUse", "session_id": sid,
             "metadata": {"tool_name": "run_shell"}}
    return evaluate_tool_call(event=event, workspace=client_ws, agent="openai-agents",
                              agent_name="support-bot", mode=mode, session_id=sid)


def test_remote_allow_and_deny(hosted):
    server_ws, client_ws = hosted
    assert _call(client_ws, "echo hi").allow is True
    denied = _call(client_ws, "run danger now")
    assert denied.allow is False and denied.rule_id == "no-danger"
    # Recorded once, on the server, under the caller's session. Client and
    # server share PRISMOR_HOME here, so a client-side write would make it 4.
    assert len(read_session_events(server_ws, "s1")) == 2


def test_agent_name_reaches_server(hosted):
    server_ws, client_ws = hosted
    _call(client_ws, "echo hi", sid="named")
    (ev,) = read_session_events(server_ws, "named")
    assert ev["metadata"]["agent_name"] == "support-bot"


def test_bad_key_fails_closed_in_enforce_open_in_observe(hosted, monkeypatch):
    _, client_ws = hosted
    monkeypatch.setenv("PRISMOR_EVAL_KEY", "wrong")
    d = _call(client_ws, "echo hi")
    assert d.allow is False and d.rule_id == "hosted-eval-unavailable" and "HTTP 401" in d.reason
    assert _call(client_ws, "echo hi", mode="observe").allow is True


def test_unreachable_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / "home"))
    monkeypatch.setattr(remote_eval, "SERVING", False)
    monkeypatch.setenv("PRISMOR_EVAL_URL", "http://127.0.0.1:9")  # discard port: refused
    monkeypatch.setenv("PRISMOR_EVAL_TIMEOUT", "1")
    assert _call(tmp_path / "c", "echo hi").allow is False
    assert _call(tmp_path / "c", "echo hi", mode="observe").allow is True


def test_unset_url_is_local(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("PRISMOR_EVAL_URL", raising=False)
    ws = _policy_ws(tmp_path / "local")
    assert _call(ws, "run danger now").allow is False
    assert len(read_session_events(ws, "s1")) == 1


def test_text_value_moved_to_preferred_field():
    ev = remote_eval._canonical({"type": "prompt", "content": "hi"})
    assert ev["prompt"] == "hi"


@pytest.fixture
def lam(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("PRISMOR_WORKSPACE", str(_policy_ws(tmp_path / "lws")))
    monkeypatch.setenv("PRISMOR_EVAL_KEY", KEY)
    monkeypatch.delenv("PRISMOR_EVAL_URL", raising=False)
    monkeypatch.setattr(remote_eval, "SERVING", False)
    from prismor.runtime import lambda_handler
    mod = importlib.reload(lambda_handler)
    yield mod
    monkeypatch.setattr(EvalHandler, "api_key", None)


def _fn_url(path, body=None, key=KEY, method="POST"):
    headers = {"content-type": "application/json"}
    if key:
        headers["authorization"] = f"Bearer {key}"
    return {"version": "2.0", "rawPath": path, "headers": headers,
            "requestContext": {"http": {"method": method}},
            "body": json.dumps(body) if body is not None else "", "isBase64Encoded": False}


def test_lambda_allow_deny_and_auth(lam):
    allow = lam.handler(_fn_url("/v1/evaluate", {"tool_name": "run_shell", "arguments": {"command": "echo hi"}}))
    assert allow["statusCode"] == 200 and json.loads(allow["body"])["allow"] is True
    deny = lam.handler(_fn_url("/v1/evaluate", {"tool_name": "run_shell", "arguments": {"command": "danger"}}))
    assert json.loads(deny["body"])["allow"] is False
    assert lam.handler(_fn_url("/v1/evaluate", {"tool_name": "x", "arguments": {}}, key="nope"))["statusCode"] == 401
    assert lam.handler(_fn_url("/health", method="GET"))["statusCode"] == 200


def test_lambda_refuses_without_key(lam, monkeypatch):
    monkeypatch.setattr(EvalHandler, "api_key", None)
    assert lam.handler(_fn_url("/v1/evaluate", {"tool_name": "x", "arguments": {}}, key=None))["statusCode"] == 503
