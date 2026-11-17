"""vault:// / openbao://, infisical:// and aws-sm:// sources.

Vault and Infisical run against a real local HTTP server that answers like
the product's API, so URL building, headers and KV v1/v2 detection are tested
end to end. AWS Secrets Manager uses a stand-in boto3 module.
"""
from __future__ import annotations

import json
import sys
import threading
import types
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from prismor.runtime.cloaking import sources
from prismor.runtime.cloaking.sources import SourceError

VALUE = "s3cr3t-value-123"


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("PRISMOR_SECRETS_DIR", raising=False)
    for var in ("VAULT_ADDR", "VAULT_TOKEN", "VAULT_NAMESPACE", "BAO_ADDR", "BAO_TOKEN",
                "INFISICAL_TOKEN", "INFISICAL_API_URL", "INFISICAL_UNIVERSAL_AUTH_CLIENT_ID",
                "INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET"):
        monkeypatch.delenv(var, raising=False)
    return tmp_path


@pytest.fixture
def server():
    """A local server; tests set ``state["routes"]`` to {(method, path): (status, json)}."""
    state = {"routes": {}, "seen": []}

    class H(BaseHTTPRequestHandler):
        def _answer(self):
            parts = urlsplit(self.path)
            n = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(n)) if n else None
            state["seen"].append({"method": self.command, "path": parts.path, "query": parse_qs(parts.query),
                                  "headers": dict(self.headers), "body": body})
            status, payload = state["routes"].get((self.command, parts.path), (404, {"errors": []}))
            raw = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        do_GET = do_POST = _answer

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    state["url"] = f"http://127.0.0.1:{srv.server_address[1]}"
    yield state
    srv.shutdown()


def vaulted(home: Path, name: str) -> str:
    from prismor.runtime.cloaking.secrets_store import secrets_dir
    return (secrets_dir() / name).read_text(encoding="utf-8")


# ── HashiCorp Vault / OpenBao ──────────────────────────────────────────────

def test_vault_kv2_value_is_vaulted_and_only_the_ref_kept(home, server, monkeypatch):
    monkeypatch.setenv("VAULT_ADDR", server["url"])
    monkeypatch.setenv("VAULT_TOKEN", "hvs.test")
    monkeypatch.setenv("VAULT_NAMESPACE", "team-a")
    server["routes"][("GET", "/v1/secret/data/apps/web")] = (200, {"data": {"data": {"api_key": VALUE}}})
    sources.add_from_ref("WEB_KEY", "vault://secret/apps/web#api_key")
    assert vaulted(home, "WEB_KEY") == VALUE
    assert VALUE not in sources.sources_file().read_text()
    seen = server["seen"][0]
    assert seen["headers"]["X-Vault-Token"] == "hvs.test" and seen["headers"]["X-Vault-Namespace"] == "team-a"


def test_vault_falls_back_to_kv1(home, server, monkeypatch):
    monkeypatch.setenv("VAULT_ADDR", server["url"] + "/")
    monkeypatch.setenv("VAULT_TOKEN", "t")
    server["routes"][("GET", "/v1/kv/db")] = (200, {"data": {"password": VALUE}})
    assert sources.fetch("vault://kv/db") == VALUE   # one field: no #field needed
    assert [s["path"] for s in server["seen"]] == ["/v1/kv/data/db", "/v1/kv/db"]


def test_vault_several_fields_need_a_pick_and_errors_never_echo(home, server, monkeypatch):
    monkeypatch.setenv("VAULT_ADDR", server["url"])
    monkeypatch.setenv("VAULT_TOKEN", "t")
    server["routes"][("GET", "/v1/secret/data/x")] = (200, {"data": {"data": {"a": VALUE, "b": "2"}}})
    with pytest.raises(SourceError, match="several fields"):
        sources.fetch("vault://secret/x")
    with pytest.raises(SourceError, match="no field 'c'"):
        sources.fetch("vault://secret/x#c")
    server["routes"][("GET", "/v1/secret/data/y")] = (500, {"errors": [VALUE]})
    with pytest.raises(SourceError) as exc:
        sources.fetch("vault://secret/y")
    assert "HTTP 500" in str(exc.value) and VALUE not in str(exc.value)
    with pytest.raises(SourceError, match="/v1/secret/data/missing returned HTTP 404"):
        sources.fetch("vault://secret/missing")   # the KV v2 error, not the v1 fallback's


def test_vault_token_from_login_file_and_openbao_env(home, server, monkeypatch):
    (home / ".vault-token").write_text("from-file\n")
    monkeypatch.setenv("BAO_ADDR", server["url"])
    server["routes"][("GET", "/v1/secret/data/z")] = (200, {"data": {"data": {"k": VALUE}}})
    assert sources.fetch("openbao://secret/z") == VALUE
    assert server["seen"][-1]["headers"]["X-Vault-Token"] == "from-file"


def test_vault_needs_address_token_and_safe_scheme(home, monkeypatch):
    with pytest.raises(SourceError, match="VAULT_ADDR"):
        sources.fetch("vault://secret/a")
    monkeypatch.setenv("VAULT_ADDR", "http://vault.corp.example:8200")
    monkeypatch.setenv("VAULT_TOKEN", "t")
    with pytest.raises(SourceError, match="https"):
        sources.fetch("vault://secret/a")
    monkeypatch.setenv("VAULT_ADDR", "https://vault.corp.example")
    monkeypatch.delenv("VAULT_TOKEN")
    with pytest.raises(SourceError, match="VAULT_TOKEN"):
        sources.fetch("vault://secret/a")
    with pytest.raises(SourceError, match="vault://<mount>/<path>"):
        sources.fetch("vault://secret")


def test_vault_path_parts_are_escaped(home, server, monkeypatch):
    monkeypatch.setenv("VAULT_ADDR", server["url"])
    monkeypatch.setenv("VAULT_TOKEN", "t")
    with pytest.raises(SourceError):
        sources.fetch("vault://secret/a?b/../c")
    assert all("?" not in s["path"] and ".." in s["path"] for s in server["seen"])


# ── Infisical ──────────────────────────────────────────────────────────────

def test_infisical_machine_identity_login_then_raw_secret(home, server, monkeypatch):
    monkeypatch.setenv("INFISICAL_API_URL", server["url"] + "/api")
    monkeypatch.setenv("INFISICAL_UNIVERSAL_AUTH_CLIENT_ID", "cid")
    monkeypatch.setenv("INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET", "csecret")
    server["routes"][("POST", "/api/v1/auth/universal-auth/login")] = (200, {"accessToken": "at-1"})
    server["routes"][("GET", "/api/v3/secrets/raw/STRIPE_KEY")] = (200, {"secret": {"secretValue": VALUE}})
    sources.add_from_ref("STRIPE_KEY", "infisical://proj-1/prod/billing/api/STRIPE_KEY")
    assert vaulted(home, "STRIPE_KEY") == VALUE
    login, get = server["seen"]
    assert login["body"] == {"clientId": "cid", "clientSecret": "csecret"}
    assert get["headers"]["Authorization"] == "Bearer at-1"
    assert get["query"] == {"workspaceId": ["proj-1"], "environment": ["prod"], "secretPath": ["/billing/api"]}


def test_infisical_token_at_root_and_errors(home, server, monkeypatch):
    monkeypatch.setenv("INFISICAL_API_URL", server["url"])
    monkeypatch.setenv("INFISICAL_TOKEN", "st.1")
    server["routes"][("GET", "/api/v3/secrets/raw/K")] = (200, {"secret": {"secretValue": VALUE}})
    assert sources.fetch("infisical://p/dev/K") == VALUE
    assert server["seen"][-1]["query"]["secretPath"] == ["/"]
    with pytest.raises(SourceError, match="HTTP 404"):
        sources.fetch("infisical://p/dev/MISSING")
    with pytest.raises(SourceError, match="infisical://<project_id>"):
        sources.fetch("infisical://p/K")
    monkeypatch.delenv("INFISICAL_TOKEN")
    with pytest.raises(SourceError, match="machine identity"):
        sources.fetch("infisical://p/dev/K")


# ── AWS Secrets Manager ────────────────────────────────────────────────────

@pytest.fixture
def aws(monkeypatch):
    class ClientError(Exception):
        def __init__(self, response, operation_name):
            self.response, self.operation_name = response, operation_name

    class BotoCoreError(Exception):
        pass

    state = {"secrets": {}, "calls": []}

    class Client:
        def get_secret_value(self, SecretId):
            state["calls"].append(SecretId)
            if SecretId not in state["secrets"]:
                raise ClientError({"Error": {"Code": "ResourceNotFoundException",
                                             "Message": "Secrets Manager can't find the specified secret."}},
                                  "GetSecretValue")
            return state["secrets"][SecretId]

    def client(service, region_name=None, config=None):
        state["client"] = (service, region_name)
        return Client()

    monkeypatch.setitem(sys.modules, "boto3", types.SimpleNamespace(client=client))
    config = types.ModuleType("botocore.config")
    config.Config = lambda **kw: kw
    exceptions = types.ModuleType("botocore.exceptions")
    exceptions.ClientError, exceptions.BotoCoreError = ClientError, BotoCoreError
    monkeypatch.setitem(sys.modules, "botocore", types.ModuleType("botocore"))
    monkeypatch.setitem(sys.modules, "botocore.config", config)
    monkeypatch.setitem(sys.modules, "botocore.exceptions", exceptions)
    return state


def test_aws_sm_plain_and_json_fields(home, aws):
    aws["secrets"]["prod/stripe"] = {"SecretString": VALUE}
    aws["secrets"]["prod/db"] = {"SecretString": json.dumps({"user": "app", "password": VALUE})}
    sources.add_from_ref("STRIPE", "aws-sm://us-east-1/prod/stripe")
    assert vaulted(home, "STRIPE") == VALUE and aws["client"] == ("secretsmanager", "us-east-1")
    assert sources.fetch("aws-sm://us-east-1/prod/db#password") == VALUE
    with pytest.raises(SourceError, match="several fields"):
        sources.fetch("aws-sm://us-east-1/prod/db")
    with pytest.raises(SourceError, match="plain string"):
        sources.fetch("aws-sm://us-east-1/prod/stripe#x")


def test_aws_sm_errors(home, aws):
    with pytest.raises(SourceError, match="ResourceNotFoundException"):
        sources.fetch("aws-sm://us-east-1/nope")
    aws["secrets"]["bin"] = {"SecretBinary": b"x"}
    with pytest.raises(SourceError, match="binary"):
        sources.fetch("aws-sm://us-east-1/bin")
    with pytest.raises(SourceError, match="aws-sm://<region>/<secret_id>"):
        sources.fetch("aws-sm://us-east-1")


def test_sync_refetches_a_rotated_vault_secret(home, server, monkeypatch):
    monkeypatch.setenv("VAULT_ADDR", server["url"])
    monkeypatch.setenv("VAULT_TOKEN", "t")
    route = ("GET", "/v1/secret/data/r")
    server["routes"][route] = (200, {"data": {"data": {"k": "v1"}}})
    sources.add_from_ref("R", "vault://secret/r")
    server["routes"][route] = (200, {"data": {"data": {"k": "v2"}}})
    assert sources.sync() == [{"name": "R", "status": "updated"}]
    assert vaulted(home, "R") == "v2"
