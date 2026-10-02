"""Verified end-user identity on the MCP gateway: the token comes from
PRISMOR_IDENTITY_TOKEN_FILE (re-read per call) or PRISMOR_IDENTITY_TOKEN, and
the tool list follows the verified roles."""

import json
import sys
import time
from pathlib import Path

import pytest
import yaml

jwt = pytest.importorskip("jwt")
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402

from prismor.runtime import identity_token  # noqa: E402
from prismor.runtime.mcp_gateway import Gateway, UpstreamSpec  # noqa: E402
from prismor.runtime.principal import current_token, use_subject  # noqa: E402

SERVER = Path(__file__).parent / "fixtures" / "shop_mcp_server.py"
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
CFG = {"mode": "require", "issuer": "https://idp.test/", "audience": ["api://shop"],
       "jwks_uri": "https://idp.test/jwks", "user_claim": "preferred_username",
       "roles_claim": "realm_access.roles"}
POLICY = {"version": "1.0", "rules": [
    {"id": "export-finance-only", "severity": "HIGH", "category": "custom-authz", "title": "export",
     "event_types": ["tool_result", "network", "mcp"], "fields": ["tool_name"],
     "patterns": ["__export_all_customers$"], "when": "'finance' not in principal.roles",
     "action": "block", "mode": "enforce"},
]}


def tok(user, roles, exp=600):
    return jwt.encode({"iss": CFG["issuer"], "aud": "api://shop", "sub": "uuid", "exp": int(time.time()) + exp,
                       "preferred_username": user, "realm_access": {"roles": roles}},
                      KEY, algorithm="RS256", headers={"kid": "k1"})


@pytest.fixture
def ws(tmp_path, monkeypatch):
    import os
    for k in [k for k in os.environ if k.startswith("PRISMOR")]:
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / "home"))
    pub = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(KEY.public_key()))
    identity_token._jwks_clients.clear()
    monkeypatch.setattr(jwt.PyJWKClient, "fetch_data", lambda self: {"keys": [{**pub, "kid": "k1", "alg": "RS256"}]})
    identity_token.set_server_config(CFG)
    (tmp_path / ".prismor").mkdir()
    (tmp_path / ".prismor" / "policy.yaml").write_text(yaml.safe_dump(POLICY))
    yield tmp_path
    identity_token.set_server_config(None)


def _tools(ws):
    g = Gateway([UpstreamSpec(name="shop", command=[sys.executable, str(SERVER)])], workspace=ws, mode="enforce")
    sent = []
    g._send = lambda m: sent.append(m)
    try:
        g._dispatch({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                     "params": {"protocolVersion": "2025-03-26", "clientInfo": {"name": "t"}}})
        g._dispatch({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        return {t["name"] for t in sent[-1]["result"]["tools"]}
    finally:
        g.close()


def test_token_sources_in_order(tmp_path, monkeypatch):
    f = tmp_path / "tok"
    monkeypatch.delenv("PRISMOR_IDENTITY_TOKEN_FILE", raising=False)
    monkeypatch.setenv("PRISMOR_IDENTITY_TOKEN", "from-env")
    assert current_token() == "from-env"
    f.write_text("Bearer from-file\n")
    monkeypatch.setenv("PRISMOR_IDENTITY_TOKEN_FILE", str(f))
    assert current_token() == "from-file"
    f.write_text("rotated")
    assert current_token() == "rotated"           # re-read per call
    with use_subject(token="per-request"):
        assert current_token() == "per-request"   # explicit wins


def test_tool_list_follows_verified_roles(ws, monkeypatch):
    monkeypatch.setenv("PRISMOR_IDENTITY_TOKEN", tok("bob", ["support"]))
    assert "shop__export_all_customers" not in _tools(ws)
    monkeypatch.setenv("PRISMOR_IDENTITY_TOKEN", tok("carol", ["finance"]))
    assert "shop__export_all_customers" in _tools(ws)


def test_require_without_a_token_hides_everything(ws):
    assert _tools(ws) == set()


def test_expired_token_in_file_hides_everything(ws, tmp_path, monkeypatch):
    f = tmp_path / "tok"
    f.write_text(tok("carol", ["finance"], exp=-3600))
    monkeypatch.setenv("PRISMOR_IDENTITY_TOKEN_FILE", str(f))
    assert _tools(ws) == set()
    f.write_text(tok("carol", ["finance"]))      # refresher rotates it
    assert "shop__export_all_customers" in _tools(ws)


def test_token_change_tells_the_host_to_relist(ws, monkeypatch):
    monkeypatch.setenv("PRISMOR_IDENTITY_TOKEN", tok("bob", ["support"]))
    g = Gateway([UpstreamSpec(name="shop", command=[sys.executable, str(SERVER)])], workspace=ws, mode="enforce")
    sent = []
    g._send = lambda m: sent.append(m)
    try:
        g._dispatch({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                     "params": {"protocolVersion": "2025-03-26", "clientInfo": {"name": "t"}}})
        g._dispatch({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        g._handle_tools_call_safe(3, {"name": "shop__list_orders", "arguments": {}})
        assert not any(m.get("method") == "notifications/tools/list_changed" for m in sent)
        monkeypatch.setenv("PRISMOR_IDENTITY_TOKEN", tok("carol", ["finance"]))
        g._handle_tools_call_safe(4, {"name": "shop__list_orders", "arguments": {}})
        g._handle_tools_call_safe(5, {"name": "shop__list_orders", "arguments": {}})
        assert sum(m.get("method") == "notifications/tools/list_changed" for m in sent) == 1
    finally:
        g.close()
