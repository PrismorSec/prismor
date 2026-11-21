"""`prismor proxy -- <agent>` (warp.py): CONNECT, child-only CA, path divert.

Offline: a stub on loopback stands in for the Prismor proxy, and the
intercepted host name resolves only through the CONNECT line, never DNS.
"""
import http.client
import shutil
import socket
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from prismor.runtime import warp

pytestmark = pytest.mark.skipif(shutil.which("openssl") is None, reason="needs openssl")


class _Stub(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    seen = []

    def log_message(self, *a):
        pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        _Stub.seen.append((self.path, self.headers.get("Host"), body))
        # SSE with no Content-Length: warp must re-chunk it, not buffer it.
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(b"event: ping\ndata: {}\n\n")
        self.close_connection = True

    do_GET = do_POST


@pytest.fixture()
def rig(tmp_path):
    stub = HTTPServer(("127.0.0.1", 0), _Stub)
    threading.Thread(target=stub.serve_forever, daemon=True).start()
    ca = warp.LocalCA.load_or_create(tmp_path / "warp")
    tunnel = warp.start_tunnel(ca.server_context(["api.anthropic.com"]), stub.server_address[1],
                               hosts=["api.anthropic.com"])
    _Stub.seen = []
    yield ca, tunnel.server_address[1], stub.server_address[1]
    tunnel.shutdown()
    stub.shutdown()


def test_generation_path_is_decrypted_and_diverted(rig):
    ca, tunnel_port, stub_port = rig
    ctx = ssl.create_default_context(cafile=str(ca.cert))  # only the child's trust
    conn = http.client.HTTPSConnection("127.0.0.1", tunnel_port, context=ctx, timeout=10)
    conn.set_tunnel("api.anthropic.com", 443)
    conn.request("POST", "/v1/messages", body=b'{"model":"m"}',
                 headers={"Content-Type": "application/json", "authorization": "Bearer x"})
    resp = conn.getresponse()
    assert resp.status == 200
    assert resp.read() == b"event: ping\ndata: {}\n\n"
    path, host, body = _Stub.seen[0]
    assert (path, host, body) == ("/v1/messages", f"127.0.0.1:{stub_port}", b'{"model":"m"}')


def test_websocket_on_a_generation_path_is_refused(rig):
    ca, tunnel_port, _ = rig
    conn = http.client.HTTPSConnection("127.0.0.1", tunnel_port, timeout=10,
                                       context=ssl.create_default_context(cafile=str(ca.cert)))
    conn.set_tunnel("api.anthropic.com", 443)
    conn.request("GET", "/v1/responses", headers={"Connection": "Upgrade", "Upgrade": "websocket"})
    assert conn.getresponse().status == 403  # never spliced past the screen
    assert _Stub.seen == []


def test_other_hosts_are_tunnelled_not_decrypted(rig):
    _ca, tunnel_port, stub_port = rig
    conn = http.client.HTTPConnection("127.0.0.1", tunnel_port, timeout=10)
    conn.set_tunnel("127.0.0.1", stub_port)  # not an intercepted host: raw bytes
    conn.request("GET", "/anything")
    assert conn.getresponse().status == 200
    assert _Stub.seen[0][0] == "/anything"


def test_child_env_drops_base_url_and_keeps_public_roots(tmp_path):
    ca = warp.LocalCA.load_or_create(tmp_path / "warp")
    trust = ca.write_trust_files({})
    env = warp.child_env({"ANTHROPIC_BASE_URL": "http://127.0.0.1:7080", "NO_PROXY": "corp"},
                         "http://127.0.0.1:1", trust)
    assert "ANTHROPIC_BASE_URL" not in env
    assert env["HTTPS_PROXY"] == "http://127.0.0.1:1"
    assert env["NO_PROXY"].split(",")[0] == "corp" and "127.0.0.1" in env["NO_PROXY"]
    bundle = open(env["SSL_CERT_FILE"], encoding="utf-8").read()
    # Replace-style trust vars must keep the public roots, not just our CA (pxpipe #245).
    assert bundle.count("BEGIN CERTIFICATE") > 1
    assert open(env["NODE_EXTRA_CA_CERTS"], encoding="utf-8").read().count("BEGIN CERTIFICATE") == 1


def test_connect_from_off_host_is_refused(rig, monkeypatch):
    _ca, tunnel_port, _ = rig
    monkeypatch.setattr(warp, "_is_loopback", lambda addr: False)
    s = socket.create_connection(("127.0.0.1", tunnel_port), timeout=10)
    s.sendall(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
    assert s.recv(64).startswith(b"HTTP/1.1 403")
    s.close()


# ── proxy side: what warp made visible ─────────────────────────────────────

def test_one_agent_session_holds_main_and_subagent_threads(tmp_path):
    from prismor.runtime.proxy import Screen
    s = Screen(workspace=tmp_path, mode="observe", session_id="p")
    main = {"system": "main agent", "messages": [{"role": "user", "content": "do it"}]}
    sub = {"system": "subagent", "messages": [{"role": "user", "content": "echo ping"}]}
    sid = s.session_for(main, "", "cc-1")
    assert s.session_for(sub, "", "cc-1") == sid          # one run, one session
    assert s.session_for(sub) != sid                       # no header: old behaviour
    meta = s._base("prompt", None, sid, thread="t1")["metadata"]
    assert meta["client_session_id"] == "cc-1" and meta["thread"] == "t1"


def test_compressed_request_bodies_are_read():
    import gzip
    from prismor.runtime.proxy import decode_body
    raw = b'{"model":"m","input":[]}'
    assert decode_body(gzip.compress(raw), "gzip", 1 << 20) == raw
    assert decode_body(gzip.compress(b"x" * 10_000), "gzip", 100) is None  # over the cap
    assert decode_body(b"junk", "gzip", 1 << 20) is None
    try:
        from compression import zstd  # Python 3.14+
    except ImportError:
        return
    assert decode_body(zstd.compress(raw), "zstd", 1 << 20) == raw  # Codex on a ChatGPT login


def test_cloudcode_envelope_is_unwrapped():
    from prismor.runtime.proxy import _turns, model_of
    body = {"model": "gemini-4-argon", "project": "p",
            "request": {"contents": [{"role": "user", "parts": [{"text": "hi"}]}]}}
    assert _turns(body)[0]["content"] == [{"text": "hi"}]
    assert model_of("google", "/v1internal:streamGenerateContent", body) == "gemini-4-argon"


def test_warp_origin_header_needs_the_launch_token():
    from prismor.runtime.proxy import ProxyConfig, ProxyHandler
    h = object.__new__(ProxyHandler)
    h.config = ProxyConfig({"upstreams": {"warp:chatgpt.com": {"base_url": "https://chatgpt.com"}}})
    h.warp_token = "secret-token"
    h.headers = {"x-prismor-warp": "secret-token", "x-prismor-warp-origin": "chatgpt.com"}
    assert h._warp_upstream() == "warp:chatgpt.com"
    h.headers = {"x-prismor-warp": "guess", "x-prismor-warp-origin": "chatgpt.com"}
    assert h._warp_upstream() == ""                         # any other local client: ignored
    h.headers = {"x-prismor-warp": "secret-token", "x-prismor-warp-origin": "evil.example"}
    assert h._warp_upstream() == ""                         # only hosts warp registered
