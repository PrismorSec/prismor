"""proxy: a web page must not drive it (H3), Origin stays local, bodies are capped (L9).

With an aws-sigv4 / gcp-oauth upstream the proxy signs whatever reaches it with
ambient cloud credentials, so a drive-by POST or a DNS-rebound page got a
billed Bedrock/Vertex client.
"""
import http.client
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from prismor.runtime import proxy as proxy_mod


@pytest.fixture
def live(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / "home"))
    hits = []

    class Upstream(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            hits.append({k.lower(): v for k, v in self.headers.items()})
            body = b'{"data": []}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    upstream = HTTPServer(("127.0.0.1", 0), Upstream)
    base = f"http://127.0.0.1:{upstream.server_port}"
    monkeypatch.setattr(proxy_mod.ProxyHandler, "config", proxy_mod.ProxyConfig(
        {"upstreams": {"anthropic": {"base_url": base}, "openai": {"base_url": base}}}))
    monkeypatch.setattr(proxy_mod.ProxyHandler, "screen",
                        proxy_mod.Screen(workspace=tmp_path, mode="observe", session_id="s"))
    proxy = proxy_mod._ThreadingHTTPServer(("127.0.0.1", 0), proxy_mod.ProxyHandler)
    for srv in (upstream, proxy):
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield proxy.server_port, hits
    for srv in (upstream, proxy):
        srv.shutdown()
        srv.server_close()


def req(port, method, path, headers=None, body=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request(method, path, body=body, headers=headers or {})
    r = conn.getresponse()
    r.read()
    conn.close()
    return r.status


@pytest.mark.parametrize("method", ["GET", "POST", "PUT", "DELETE"])
@pytest.mark.parametrize("headers", [
    {"Origin": "https://evil.example"},
    {"Origin": "null"},
    {"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "no-cors"},
    {"Host": "rebound.evil.example:7080"},
])
def test_browser_requests_never_reach_the_upstream(live, method, headers):
    port, hits = live
    body = json.dumps({"model": "m", "messages": []}) if method in ("POST", "PUT") else None
    assert req(port, method, "/v1/models", headers, body) == 403
    assert hits == []


def test_sdk_request_is_forwarded_without_origin(live):
    port, hits = live
    assert req(port, "GET", "/v1/models") == 200
    # A same-origin page passes the gate, but its Origin is not sent upstream.
    assert req(port, "GET", "/v1/models", {"Origin": f"http://127.0.0.1:{port}"}) == 200
    assert len(hits) == 2 and all("origin" not in h for h in hits)


def test_oversized_body_is_refused_unread(live):
    port, hits = live
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.putrequest("POST", "/v1/messages")
    conn.putheader("Content-Length", str(proxy_mod.MAX_BODY_BYTES + 1))
    conn.endheaders()
    assert conn.getresponse().status == 413
    conn.close()
    assert hits == []
