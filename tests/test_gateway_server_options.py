"""Per-server gateway options: forwardHeaders, logPayloads, maxBodyBytes,
sigv4, managedSession. HTTP cases run against a real local http.server; the
stdio limit against a tiny real stdio server."""

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
import yaml

from prismor.runtime import mcp_gateway as gw
from prismor.runtime.mcp_gateway import Gateway, UpstreamError, UpstreamHttp, _spec_from_entry


class _Upstream(BaseHTTPRequestHandler):
    seen = []          # (method, headers) per request
    expire_once = False
    big = 0            # bytes of padding in tools/call results

    def log_message(self, *a):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        cls = type(self)
        cls.seen.append((body.get("method"), {k.lower(): v for k, v in self.headers.items()}))
        if cls.expire_once and self.headers.get("Mcp-Session-Id") == "s1" and body.get("method") != "initialize":
            cls.expire_once = False
            self.send_response(404)
            self.end_headers()
            return
        method = body.get("method")
        if method == "initialize":
            result = {"protocolVersion": "2025-03-26", "capabilities": {"tools": {}}, "serverInfo": {"name": "t"}}
        elif method == "tools/list":
            result = {"tools": [{"name": "echo", "description": "Echo", "inputSchema": {"type": "object"}}]}
        elif method == "tools/call":
            result = {"content": [{"type": "text", "text": "ok" + "x" * cls.big}]}
        else:
            self.send_response(202)
            self.end_headers()
            return
        out = json.dumps({"jsonrpc": "2.0", "id": body.get("id"), "result": result}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Mcp-Session-Id", "s2" if any(m == "initialize" for m, _ in cls.seen[:-1]) else "s1")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)


@pytest.fixture
def upstream():
    _Upstream.seen, _Upstream.expire_once, _Upstream.big = [], False, 0
    srv = HTTPServer(("127.0.0.1", 0), _Upstream)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}/mcp"
    srv.shutdown()


@pytest.fixture
def ws(tmp_path, monkeypatch):
    for k in [k for k in __import__("os").environ if k.startswith(("PRISMOR", "AWS_"))]:
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / "home"))
    (tmp_path / ".prismor").mkdir()
    (tmp_path / ".prismor" / "policy.yaml").write_text(yaml.safe_dump({"version": "1.0", "rules": []}))
    return tmp_path


def _up(url, **entry):
    up = UpstreamHttp(_spec_from_entry("t", {"url": url, **entry}))
    up.initialize({"protocolVersion": "2025-03-26", "clientInfo": {"name": "t"}})
    return up


def test_parsing():
    s = _spec_from_entry("t", {"url": "https://x", "forwardHeaders": ["X-Tenant", "Authorization", 3],
                               "logPayloads": True, "maxBodyBytes": 2048,
                               "sigv4": {"service": "lambda", "region": "us-east-1"}, "managedSession": False})
    assert s.forward_headers == ["X-Tenant"]
    assert s.log_payloads and s.max_body_bytes == 2048 and not s.managed_session
    assert s.sigv4 == {"service": "lambda", "region": "us-east-1"} and not s.uses_oauth
    d = _spec_from_entry("t", {"url": "https://x", "logPayloads": "yes", "maxBodyBytes": True, "sigv4": {"service": "x"}})
    assert not d.log_payloads and d.max_body_bytes is None and d.sigv4 is None and d.managed_session


def test_forward_headers_copies_listed_never_credentials_and_entry_wins(upstream):
    gw._inbound.headers = {"x-tenant": "acme", "X-Other": "no", "Authorization": "Bearer client", "Cookie": "c"}
    try:
        up = _up(upstream, forwardHeaders=["X-Tenant", "Authorization", "Cookie"])
        up.request("tools/list", {})
        h = _Upstream.seen[-1][1]
        assert h["x-tenant"] == "acme" and "x-other" not in h
        assert "authorization" not in h and "cookie" not in h
        up2 = _up(upstream, forwardHeaders=["X-Tenant"], headers={"X-Tenant": "entry"})
        up2.request("tools/list", {})
        assert _Upstream.seen[-1][1]["x-tenant"] == "entry"
    finally:
        gw._inbound.headers = None


def test_forward_headers_reach_a_tool_call_on_the_worker_thread(upstream, ws):
    g = Gateway([_spec_from_entry("t", {"url": upstream, "forwardHeaders": ["X-Request-Id"]})], workspace=ws, mode="enforce")
    sent = []
    g._send = sent.append
    try:
        g._dispatch({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26", "clientInfo": {"name": "t"}}})
        g._dispatch({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        g._dispatch({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "t__echo", "arguments": {}},
                     "_inboundHeaders": {"X-Request-Id": "req-42"}})
        g._executor.shutdown(wait=True)
        call = [h for m, h in _Upstream.seen if m == "tools/call"][-1]
        assert call["x-request-id"] == "req-42"
    finally:
        g.close()


def test_sigv4_signs_with_entry_credentials_and_fails_closed_without(upstream):
    up = _up(upstream, sigv4={"service": "lambda", "region": "us-east-1"},
             env={"AWS_ACCESS_KEY_ID": "AKIDEXAMPLE", "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"})
    up.request("tools/list", {})
    auth = _Upstream.seen[-1][1]["authorization"]
    assert auth.startswith("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/") and "/us-east-1/lambda/aws4_request" in auth
    assert "x-amz-date" in _Upstream.seen[-1][1]
    before = len(_Upstream.seen)
    bare = UpstreamHttp(_spec_from_entry("t", {"url": upstream, "sigv4": {"service": "lambda", "region": "us-east-1"}}))
    with pytest.raises(UpstreamError, match="AWS_ACCESS_KEY_ID"):
        bare.request("tools/list", {})
    assert len(_Upstream.seen) == before  # nothing went out unsigned


def test_managed_session_reopens_an_expired_session_once(upstream):
    up = _up(upstream)
    _Upstream.expire_once = True
    assert up.request("tools/list", {})["tools"][0]["name"] == "echo"
    assert [m for m, _ in _Upstream.seen].count("initialize") == 2
    assert _Upstream.seen[-1][1].get("mcp-session-id") == "s2"


def test_unmanaged_session_never_sends_one(upstream):
    up = _up(upstream, managedSession=False)
    up.request("tools/list", {})
    assert all("mcp-session-id" not in h for _, h in _Upstream.seen)


def test_max_body_on_http_replies_and_call_arguments(upstream, ws):
    _Upstream.big = 5000
    up = _up(upstream, maxBodyBytes=2048)
    with pytest.raises(UpstreamError, match="maxBodyBytes"):
        up.request("tools/call", {"name": "echo", "arguments": {}})
    _Upstream.big = 0
    g = Gateway([_spec_from_entry("t", {"url": upstream, "maxBodyBytes": 2048})], workspace=ws, mode="enforce")
    sent = []
    g._send = sent.append
    try:
        g._dispatch({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26", "clientInfo": {"name": "t"}}})
        g._dispatch({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        calls = [m for m, _ in _Upstream.seen].count("tools/call")
        g._handle_tools_call_safe(3, {"name": "t__echo", "arguments": {"blob": "y" * 5000}})
        assert sent[-1]["error"]["code"] == -32602 and "maxBodyBytes" in sent[-1]["error"]["message"]
        assert [m for m, _ in _Upstream.seen].count("tools/call") == calls  # never reached the server
    finally:
        g.close()


STDIO = """
import json, sys
for line in sys.stdin:
    m = json.loads(line)
    if "id" not in m:
        continue
    r = {"protocolVersion": "2025-03-26", "capabilities": {"tools": {}}} if m["method"] == "initialize" else {"pad": "z" * 9000}
    print(json.dumps({"jsonrpc": "2.0", "id": m["id"], "result": r}), flush=True)
"""


def test_max_body_on_stdio_replies(tmp_path):
    script = tmp_path / "srv.py"
    script.write_text(STDIO)
    up = gw.make_upstream(_spec_from_entry("t", {"command": sys.executable, "args": [str(script)], "maxBodyBytes": 4096}))
    try:
        up.initialize({"protocolVersion": "2025-03-26", "clientInfo": {"name": "t"}})
        with pytest.raises(UpstreamError, match="maxBodyBytes"):
            up.request("tools/list", {})
    finally:
        up.close()


def test_log_payloads_puts_arguments_and_result_on_the_events(upstream, ws, monkeypatch):
    from prismor.runtime import runtime
    events = []
    monkeypatch.setattr(runtime, "_dispatch_telemetry", lambda **kw: events.append(kw["event"]))
    g = Gateway([_spec_from_entry("t", {"url": upstream, "logPayloads": True})], workspace=ws, mode="enforce")
    g._send = lambda m: None
    try:
        g._dispatch({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26", "clientInfo": {"name": "t"}}})
        g._dispatch({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        g._handle_tools_call_safe(3, {"name": "t__echo", "arguments": {"q": "hello"}})
    finally:
        g.close()
    payloads = [e["log_payloads"] for e in events if e.get("log_payloads")]
    assert {"arguments": json.dumps({"q": "hello"})} in payloads
    assert any(p.get("result", "").startswith("ok") for p in payloads)


def test_logged_arguments_are_masked_but_the_upstream_gets_the_real_ones(upstream, ws, monkeypatch):
    from prismor.runtime import runtime
    events = []
    monkeypatch.setattr(runtime, "_dispatch_telemetry", lambda **kw: events.append(kw["event"]))
    secret = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
    g = Gateway([_spec_from_entry("t", {"url": upstream, "logPayloads": True})], workspace=ws, mode="observe")
    g._send = lambda m: None
    real = gw.UpstreamHttp.request
    sent_args = []
    monkeypatch.setattr(gw.UpstreamHttp, "request", lambda self, m, p, timeout=30.0: (sent_args.append(p), real(self, m, p, timeout=timeout))[1])
    try:
        g._dispatch({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26", "clientInfo": {"name": "t"}}})
        g._dispatch({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        g._handle_tools_call_safe(3, {"name": "t__echo", "arguments": {"token": secret}})
    finally:
        g.close()
    logged = [e["log_payloads"]["arguments"] for e in events if "arguments" in (e.get("log_payloads") or {})]
    assert logged and all(secret not in a for a in logged)
    assert {"name": "echo", "arguments": {"token": secret}} in sent_args


def test_log_payloads_record_ships_detail_and_says_unredacted():
    from prismor.runtime.enterprise.telemetry import build_record
    finding = {"action": "allow", "severity": "info", "category": "audit", "ruleId": "audit-allowed", "title": "call allowed"}
    rec = build_record(finding, {"type": "network", "log_payloads": {"arguments": '{"q": "acme-7"}', "result": "x" * 9000}},
                       scrub_patterns=[r"acme-\d+"])
    assert rec["redacted"] is False
    assert "acme-7" not in rec["detail"]["arguments"]  # the org's scrub patterns still apply
    assert len(rec["detail"]["result"]) <= 4096
    plain = build_record(finding, {"type": "network"})
    assert plain["redacted"] is True and "detail" not in plain


def test_log_payloads_ships_unflagged_calls_in_redacted_mode(monkeypatch, ws):
    from prismor.runtime import runtime, sinks
    from prismor.runtime.enterprise import remote_policy
    shipped = []
    monkeypatch.setattr(sinks, "dispatch", lambda findings, outputs, **kw: shipped.append(findings))
    monkeypatch.setattr(remote_policy, "current_full_capture", lambda: False)
    engine = type("E", (), {"outputs": [{"type": "stdout"}], "active_exemption": None})()
    from prismor.runtime.principal import resolve_subject
    common = dict(engine=engine, findings=[], workspace=ws, agent="mcp-gateway", mode="enforce", session_id="s",
                  subject=resolve_subject())
    runtime._dispatch_telemetry(event={"type": "network"}, **common)
    assert shipped == []
    runtime._dispatch_telemetry(event={"type": "network", "log_payloads": {"arguments": "{}"}}, **common)
    assert len(shipped) == 1 and shipped[0][0]["ruleId"] == "audit-allowed"
