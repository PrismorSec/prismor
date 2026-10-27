"""OAuth sign-in for remote MCP servers behind the gateway (runtime/mcp_oauth.py).

Drives a real loopback server that plays both roles of the MCP authorization
spec: a protected MCP endpoint answering 401 + ``resource_metadata``, and an
authorization server with metadata, dynamic registration, PKCE and refresh.
"""
from __future__ import annotations

import base64
import hashlib
import http.server
import json
import os
import stat
import sys
import threading
import time
import urllib.parse
import urllib.request
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

from prismor.runtime import mcp_oauth  # noqa: E402
from prismor.runtime.mcp_gateway import (  # noqa: E402
    Gateway,
    UpstreamError,
    UpstreamHttp,
    UpstreamSpec,
    _spec_from_entry,
)


# ── fake server ──────────────────────────────────────────────────────────────

class FakeOAuthMCP:
    """One process, two roles: MCP resource server at /mcp and its
    authorization server at the origin."""

    def __init__(self, expires_in=3600, prm_resource=None, dcr=True, issuer=None,
                 omit_iss=False, iss_supported=False, as_scopes=None, prm_status=200):
        self.issuer_override = issuer
        self.omit_iss = omit_iss
        self.iss_supported = iss_supported
        self.as_scopes = as_scopes
        self.prm_status = prm_status
        self.need_scope = None    # tools/call answers 403 insufficient_scope until granted
        self.granted = {}         # access token -> scope
        self.expires_in = expires_in
        self.prm_resource = prm_resource
        self.dcr = dcr
        self.clients = {}
        self.codes = {}
        self.access = {}      # token -> user
        self.refresh = {}     # token -> user
        self.authorize_params = []
        self.token_forms = []
        self.mcp_auth_headers = []
        self.state_override = None
        fake = self

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _json(self, code, obj, headers=None):
                body = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _body(self):
                n = int(self.headers.get("Content-Length") or 0)
                return self.rfile.read(n).decode()

            def do_GET(self):  # noqa: N802
                u = urllib.parse.urlsplit(self.path)
                if u.path.startswith("/.well-known/oauth-protected-resource") and fake.prm_status != 200:
                    return self._json(fake.prm_status, {"error": "boom"})
                if u.path == "/.well-known/oauth-protected-resource/mcp":
                    return self._json(200, {"resource": fake.prm_resource or fake.base + "/mcp",
                                            "authorization_servers": [fake.base],
                                            "scopes_supported": ["read"]})
                if u.path == "/.well-known/oauth-authorization-server":
                    meta = {"issuer": fake.issuer_override or fake.base,
                            "authorization_endpoint": fake.base + "/authorize",
                            "token_endpoint": fake.base + "/token",
                            "code_challenge_methods_supported": ["S256"]}
                    if fake.dcr:
                        meta["registration_endpoint"] = fake.base + "/register"
                    if fake.iss_supported:
                        meta["authorization_response_iss_parameter_supported"] = True
                    if fake.as_scopes:
                        meta["scopes_supported"] = fake.as_scopes
                    return self._json(200, meta)
                if u.path == "/authorize":
                    q = dict(urllib.parse.parse_qsl(u.query))
                    fake.authorize_params.append(q)
                    code = "code-" + str(len(fake.codes))
                    fake.codes[code] = q
                    state = fake.state_override or q["state"]
                    params = {"code": code, "state": state}
                    if not fake.omit_iss:
                        params["iss"] = fake.base
                    loc = q["redirect_uri"] + "?" + urllib.parse.urlencode(params)
                    self.send_response(302)
                    self.send_header("Location", loc)
                    self.end_headers()
                    return
                self._json(404, {"error": "not_found"})

            def do_POST(self):  # noqa: N802
                u = urllib.parse.urlsplit(self.path)
                if u.path == "/register":
                    reg = json.loads(self._body())
                    cid = "client-" + str(len(fake.clients))
                    fake.clients[cid] = reg
                    return self._json(201, {"client_id": cid, **reg})
                if u.path == "/token":
                    form = dict(urllib.parse.parse_qsl(self._body()))
                    fake.token_forms.append(form)
                    if form.get("resource") != fake.base + "/mcp":
                        return self._json(400, {"error": "invalid_target"})
                    if form["grant_type"] == "authorization_code":
                        q = fake.codes.pop(form.get("code"), None)
                        if q is None:
                            return self._json(400, {"error": "invalid_grant"})
                        want = base64.urlsafe_b64encode(
                            hashlib.sha256(form["code_verifier"].encode()).digest()).rstrip(b"=").decode()
                        if want != q["code_challenge"] or form["redirect_uri"] != q["redirect_uri"]:
                            return self._json(400, {"error": "invalid_grant", "error_description": "pkce"})
                        return self._json(200, fake.issue("alice", q.get("scope", "")))
                    if form["grant_type"] == "refresh_token":
                        user = fake.refresh.pop(form.get("refresh_token"), None)
                        if user is None:
                            return self._json(400, {"error": "invalid_grant"})
                        return self._json(200, fake.issue(user))
                    return self._json(400, {"error": "unsupported_grant_type"})
                if u.path == "/mcp":
                    auth = self.headers.get("Authorization") or ""
                    fake.mcp_auth_headers.append(auth)
                    user = fake.access.get(auth[len("Bearer "):]) if auth.startswith("Bearer ") else None
                    if user is None:
                        return self._json(401, {"error": "unauthorized"}, {
                            "WWW-Authenticate": f'Bearer resource_metadata="{fake.base}/.well-known/oauth-protected-resource/mcp", scope="read"'})
                    msg = json.loads(self._body())
                    if "id" not in msg:
                        self.send_response(202)
                        self.end_headers()
                        return
                    m = msg["method"]
                    if m == "initialize":
                        res = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                               "serverInfo": {"name": "fake", "version": "1"}}
                    elif m == "tools/list":
                        res = {"tools": [{"name": "whoami", "description": "Who am I",
                                          "inputSchema": {"type": "object"}}]}
                    elif m == "tools/call" and fake.need_scope and \
                            fake.need_scope not in fake.granted.get(auth[len("Bearer "):], "").split():
                        return self._json(403, {"error": "insufficient_scope"}, {
                            "WWW-Authenticate": f'Bearer error="insufficient_scope", scope="{fake.need_scope}"'})
                    elif m == "tools/call":
                        res = {"content": [{"type": "text", "text": f"you are {user}"}]}
                    else:
                        res = {}
                    return self._json(200, {"jsonrpc": "2.0", "id": msg["id"], "result": res})
                self._json(404, {"error": "not_found"})

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        self.url = self.base + "/mcp"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def issue(self, user, scope=""):
        n = len(self.access) + len(self.refresh)
        at, rt = f"at-{n}-{user}", f"rt-{n}-{user}"
        self.access[at] = user
        self.granted[at] = scope
        self.refresh[rt] = user
        return {"access_token": at, "refresh_token": rt, "token_type": "Bearer",
                "expires_in": self.expires_in, "scope": "read"}

    def revoke_access(self):
        self.access.clear()

    def revoke_all(self):
        self.access.clear()
        self.refresh.clear()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / "home"))
    return tmp_path / "home"


@pytest.fixture
def server():
    s = FakeOAuthMCP()
    yield s
    s.close()


def _follow(url):
    """Play the browser: the fake /authorize redirects straight to the
    loopback callback, which urllib follows."""
    threading.Thread(target=lambda: urllib.request.urlopen(url, timeout=10).read(), daemon=True).start()


def _login(server, **kw):
    return mcp_oauth.login("linear", server.url, open_browser=False, timeout=10,
                           on_authorize_url=_follow, **kw)


def _init(up):
    return up.initialize({"protocolVersion": "2025-06-18", "capabilities": {},
                          "clientInfo": {"name": "t", "version": "0"}})


# ── discovery / parsing ──────────────────────────────────────────────────────

def test_parse_www_authenticate():
    p = mcp_oauth.parse_www_authenticate(
        'Bearer realm="x", resource_metadata="https://a.example/.well-known/oauth-protected-resource", scope="read write"')
    assert p["resource_metadata"] == "https://a.example/.well-known/oauth-protected-resource"
    assert p["scope"] == "read write"
    assert mcp_oauth.parse_www_authenticate('Basic realm="x"') == {}


def test_discover_follows_challenge_to_authorization_server(server):
    meta = mcp_oauth.discover(server.url, {"resource_metadata": server.base + "/.well-known/oauth-protected-resource/mcp"})
    assert meta["token_endpoint"] == server.base + "/token"
    assert meta["registration_endpoint"] == server.base + "/register"
    assert meta["resource"] == server.url


def test_discover_rejects_metadata_for_another_resource():
    s = FakeOAuthMCP(prm_resource="https://evil.example/mcp")
    try:
        with pytest.raises(mcp_oauth.OAuthError, match="not "):
            mcp_oauth.discover(s.url)
    finally:
        s.close()


def test_plain_http_endpoints_refused_off_loopback():
    with pytest.raises(mcp_oauth.OAuthError, match="https"):
        mcp_oauth._require_secure("http://auth.example.com/token", "token_endpoint")
    assert mcp_oauth._require_secure("http://127.0.0.1:9/token", "t")


# ── login ────────────────────────────────────────────────────────────────────

def test_login_registers_uses_pkce_and_resource_and_stores_0600(home, server):
    rec = _login(server)
    assert rec["client_id"] == "client-0"
    q = server.authorize_params[0]
    assert q["code_challenge_method"] == "S256" and q["resource"] == server.url
    assert q["scope"] == "read"
    assert q["redirect_uri"].startswith("http://127.0.0.1:")
    assert server.clients["client-0"]["token_endpoint_auth_method"] == "none"
    path = mcp_oauth._store_path(server.url)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert json.loads(path.read_text())["access_token"] == rec["access_token"]


def test_login_rejects_state_mismatch(home, server):
    server.state_override = "forged"
    with pytest.raises(mcp_oauth.OAuthError, match="state"):
        _login(server)
    assert mcp_oauth.load_record(server.url) is None


def test_login_without_dcr_needs_client_id(home):
    s = FakeOAuthMCP(dcr=False)
    try:
        with pytest.raises(mcp_oauth.OAuthError, match="client_id"):
            _login(s)
        rec = _login(s, oauth_cfg={"client_id": "preregistered"})
        assert rec["client_id"] == "preregistered"
    finally:
        s.close()


def test_record_for_another_url_is_not_used(home, server):
    _login(server)
    src = mcp_oauth._store_path(server.url)
    other = "https://other.example/mcp"
    dst = mcp_oauth._store_path(other)
    dst.write_text(src.read_text())
    assert mcp_oauth.load_record(other) is None


# ── gateway use ──────────────────────────────────────────────────────────────

def _upstream(server):
    return UpstreamHttp(UpstreamSpec(name="linear", url=server.url, transport="http"))


def test_not_signed_in_tells_the_model_what_to_run(home, server):
    with pytest.raises(UpstreamError, match="prismor mcp-gateway login linear"):
        _init(_upstream(server))


def test_signed_in_calls_carry_the_users_token(home, server):
    _login(server)
    up = _upstream(server)
    _init(up)
    out = up.request("tools/call", {"name": "whoami", "arguments": {}})
    assert out["content"][0]["text"] == "you are alice"
    assert server.mcp_auth_headers[-1].startswith("Bearer at-")


def test_login_while_running_is_picked_up_without_restart(home, server):
    up = _upstream(server)
    with pytest.raises(UpstreamError):
        _init(up)
    _login(server)
    _init(up)


def test_expiring_token_is_refreshed_before_the_call(home, server):
    rec = _login(server)
    rec["refresh_at"] = int(time.time()) - 1
    mcp_oauth.save_record(server.url, rec)
    up = _upstream(server)
    _init(up)
    up.request("tools/list", {})
    grants = [f["grant_type"] for f in server.token_forms]
    assert grants == ["authorization_code", "refresh_token"]   # once, not per call
    assert server.token_forms[-1]["resource"] == server.url
    assert mcp_oauth.load_record(server.url)["access_token"] in server.access


def test_short_lived_tokens_are_not_refreshed_on_every_call(home):
    s = FakeOAuthMCP(expires_in=30)   # shorter than EXPIRY_SKEW
    try:
        _login(s)
        up = _upstream(s)
        _init(up)
        up.request("tools/list", {})
        assert [f["grant_type"] for f in s.token_forms] == ["authorization_code"]
    finally:
        s.close()


def test_revoked_access_token_refreshes_and_retries_once(home, server):
    _login(server)
    up = _upstream(server)
    _init(up)
    server.revoke_access()
    out = up.request("tools/call", {"name": "whoami", "arguments": {}})
    assert out["content"][0]["text"] == "you are alice"
    assert [f["grant_type"] for f in server.token_forms][-1] == "refresh_token"


def test_revoked_refresh_token_falls_back_to_login_hint(home, server):
    _login(server)
    up = _upstream(server)
    _init(up)
    server.revoke_all()
    with pytest.raises(UpstreamError, match="login linear"):
        up.request("tools/list", {})


def test_static_authorization_header_disables_oauth(home, server):
    spec = _spec_from_entry("linear", {"url": server.url, "headers": {"Authorization": "Bearer pat"}})
    assert not spec.uses_oauth
    with pytest.raises(UpstreamError, match="HTTP 401"):
        _init(UpstreamHttp(spec))
    assert not _spec_from_entry("x", {"url": server.url, "oauth": False}).uses_oauth
    assert _spec_from_entry("x", {"url": server.url, "oauth": {"client_id": "c"}}).oauth == {"client_id": "c"}


def test_gateway_status_tool_carries_the_hint(home, server, tmp_path, monkeypatch):
    gw = Gateway([UpstreamSpec(name="linear", url=server.url, transport="http")],
                 workspace=tmp_path, mode="enforce")
    sent = []
    monkeypatch.setattr(gw, "_send", sent.append)
    gw._dispatch({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                  "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                             "clientInfo": {"name": "t", "version": "0"}}})
    gw._dispatch({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    deadline = time.time() + 10
    while time.time() < deadline and not any(m.get("id") == 2 for m in sent):
        time.sleep(0.05)
    listed = next(m for m in sent if m.get("id") == 2)["result"]["tools"]
    status = [t for t in listed if t["name"] == "prismor_gateway_status"]
    assert status and "prismor mcp-gateway login linear" in status[0]["description"]
    gw.close()


# ── behaviour aligned with the MCP SDK clients ───────────────────────────────

def test_metadata_for_another_issuer_is_rejected(home):
    s = FakeOAuthMCP(issuer="https://evil.example")
    try:
        with pytest.raises(mcp_oauth.OAuthError, match="expected"):
            mcp_oauth.discover(s.url)
    finally:
        s.close()


def test_missing_iss_rejected_when_server_promised_it(home):
    s = FakeOAuthMCP(iss_supported=True, omit_iss=True)
    try:
        with pytest.raises(mcp_oauth.OAuthError, match="iss"):
            _login(s)
    finally:
        s.close()
    s = FakeOAuthMCP(omit_iss=True)          # not promised: accepted
    try:
        _login(s)
    finally:
        s.close()


def test_offline_access_requested_when_supported(home):
    s = FakeOAuthMCP(as_scopes=["read", "offline_access"])
    try:
        _login(s)
        assert s.authorize_params[0]["scope"].split() == ["read", "offline_access"]
    finally:
        s.close()


def test_prm_server_error_does_not_fall_back_to_legacy(home):
    s = FakeOAuthMCP(prm_status=503)
    try:
        with pytest.raises(mcp_oauth.OAuthError, match="503"):
            mcp_oauth.discover(s.url)
    finally:
        s.close()


def test_second_login_reuses_the_registered_client(home, server):
    first = _login(server)
    second = _login(server)
    assert len(server.clients) == 1
    assert second["client_id"] == first["client_id"]
    port = mcp_oauth.default_callback_port(server.url)
    assert server.authorize_params[1]["redirect_uri"] == f"http://127.0.0.1:{port}/callback"


def test_insufficient_scope_hints_and_next_login_steps_up(home, server):
    _login(server)
    server.need_scope = "write"
    up = _upstream(server)
    _init(up)
    with pytest.raises(UpstreamError, match="needs more access .*write.*login linear"):
        up.request("tools/call", {"name": "whoami", "arguments": {}})
    _login(server)
    assert server.authorize_params[-1]["scope"].split() == ["read", "write"]
    up2 = _upstream(server)
    _init(up2)
    out = up2.request("tools/call", {"name": "whoami", "arguments": {}})
    assert out["content"][0]["text"] == "you are alice"
