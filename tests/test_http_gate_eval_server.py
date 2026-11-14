"""eval-server: a web page must not reach it, and a caller must not pick its policy.

H1/H2: wildcard CORS + no Host/Origin check let any page POST /v1/evaluate
(read policy regexes, forge audit records) and use /v1/redact as a secret
oracle. M7: the body's "workspace" chose the judging policy. L9: no body cap.
"""
import http.client
import json
import threading

import pytest

from prismor.runtime import eval_server
from prismor.runtime import redaction
from prismor.runtime.eval_server import EvalHandler, _ThreadingHTTPServer

CALL = {"tool_name": "Bash", "arguments": {"command": "echo hi"}}


class _Decision:
    def as_dict(self):
        return {"allow": True}


@pytest.fixture
def serve(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / "home"))
    servers = []

    def start(**attrs):
        handler = type("H", (EvalHandler,), {"workspace": tmp_path, "api_key": None, **attrs})
        srv = _ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
        return srv.server_address[1]

    yield start
    for srv in servers:
        srv.shutdown()
        srv.server_close()


def req(port, method, path, body=None, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    data = json.dumps(body).encode() if body is not None else None
    conn.request(method, path, body=data, headers={"Content-Type": "text/plain", **(headers or {})})
    r = conn.getresponse()
    out = r.read()
    conn.close()
    return r.status, dict(r.getheaders()), out


@pytest.mark.parametrize("path", ["/v1/evaluate", "/v1/redact"])
@pytest.mark.parametrize("headers", [
    {"Origin": "https://evil.example"},
    {"Origin": "null"},
    {"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "no-cors"},
    {"Host": "evil.example:7071"},  # DNS rebinding
])
def test_browser_requests_are_refused(serve, monkeypatch, path, headers):
    seen = []
    monkeypatch.setattr(eval_server, "evaluate_tool_call", lambda **kw: seen.append(kw) or _Decision())
    monkeypatch.setattr(redaction, "redact_payload_values", lambda *a, **kw: seen.append(a))
    status, hdrs, _ = req(serve(), "POST", path, {**CALL, "result": "x"}, headers)
    assert status == 403 and not seen
    assert "Access-Control-Allow-Origin" not in hdrs


def test_no_cors_and_no_preflight(serve):
    port = serve()
    status, hdrs, _ = req(port, "GET", "/health")
    assert status == 200 and "Access-Control-Allow-Origin" not in hdrs
    status, hdrs, _ = req(port, "OPTIONS", "/v1/evaluate", headers={"Origin": "https://evil.example"})
    assert status != 204 and "Access-Control-Allow-Origin" not in hdrs


def test_sdk_without_origin_still_works(serve):
    status, _, out = req(serve(), "POST", "/v1/evaluate", CALL)
    assert status == 200 and "allow" in json.loads(out)


def test_api_key_mode_accepts_another_host_but_not_a_browser(serve):
    port = serve(api_key="k")
    auth = {"Authorization": "Bearer k", "Host": "evals.example.com"}
    assert req(port, "POST", "/v1/evaluate", CALL, auth)[0] == 200
    assert req(port, "POST", "/v1/evaluate", CALL, {**auth, "Origin": "https://evil.example"})[0] == 403


def test_request_workspace_is_ignored_by_default(serve, tmp_path, monkeypatch):
    seen = []
    monkeypatch.setattr(eval_server, "evaluate_tool_call", lambda **kw: seen.append(kw["workspace"]) or _Decision())
    monkeypatch.setattr(redaction, "redact_payload_values",
                        lambda v, workspace=None, engine=None: (seen.append(workspace), (v, False))[1])
    other = str(tmp_path / "attacker-chosen")
    port = serve()
    req(port, "POST", "/v1/evaluate", {**CALL, "workspace": other})
    req(port, "POST", "/v1/evaluate", {"event": {"type": "shell", "command": "ls"}, "workspace": other})
    req(port, "POST", "/v1/redact", {"result": "x", "workspace": other})
    assert seen == [tmp_path, tmp_path, tmp_path]

    seen.clear()
    req(serve(allow_request_workspace=True), "POST", "/v1/evaluate", {**CALL, "workspace": other})
    assert [str(w) for w in seen] == [other]


def test_oversized_body_is_refused_unread(serve):
    conn = http.client.HTTPConnection("127.0.0.1", serve(), timeout=10)
    conn.putrequest("POST", "/v1/evaluate")
    conn.putheader("Content-Length", str(eval_server.MAX_BODY_BYTES + 1))
    conn.endheaders()
    assert conn.getresponse().status == 413
    conn.close()
