"""inference-hook (H4): once an org has a credential, an unknown or empty
tenant_id must not fall back to unsigned bootstrap."""
import json

from prismor.runtime import inference_hook as ih
from prismor.runtime.inference_hook_server import authenticate, credentialed_orgs

SECRET = ih.generate_secret()
CONFIG = {"orgs": {"org_acme": {"signing_secret": SECRET}, "org_new": {"mode": "observe"}}}


def auth(tenant, file_config=CONFIG):
    body = json.dumps({"type": "prompt", "request_id": "r", "tenant_id": tenant, "messages": []}).encode()
    frame = ih.parse_frame(json.loads(body))
    cfg = ih.resolve_config(tenant, file_config=file_config)
    return authenticate(cfg, {}, body, frame, file_config=file_config)[:2]


def test_unknown_or_empty_tenant_is_rejected_once_any_org_is_signed():
    assert auth("org_evil") == (False, "rejected")
    assert auth("") == (False, "rejected")
    assert auth("org_acme") == (False, "rejected")  # its own secret still applies


def test_configured_org_without_credential_can_still_bootstrap():
    assert auth("org_new") == (True, "unsigned-bootstrap")


def test_nothing_configured_is_still_bootstrap():
    assert auth("anything", {}) == (True, "unsigned-bootstrap")
    assert auth("", {"orgs": {"org_new": {}}}) == (True, "unsigned-bootstrap")


def test_credentialed_orgs():
    assert credentialed_orgs(CONFIG) == ["org_acme"]
    assert credentialed_orgs({"orgs": {"a": {"api_key": "  "}}}) == []


# ── browser gate on the live server ─────────────────────────────────────────
import http.client  # noqa: E402
import threading  # noqa: E402
from http.server import ThreadingHTTPServer  # noqa: E402

import pytest  # noqa: E402

from prismor.runtime.inference_hook_server import InferenceHookHandler  # noqa: E402


@pytest.fixture
def server(tmp_path, monkeypatch):
    monkeypatch.setattr(InferenceHookHandler, "workspace", tmp_path)
    monkeypatch.setattr(InferenceHookHandler, "file_config", {})
    monkeypatch.setattr(InferenceHookHandler, "cli_overrides", {})
    srv = ThreadingHTTPServer(("127.0.0.1", 0), InferenceHookHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1]
    srv.shutdown()


def _post(port, headers):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    body = json.dumps({"type": "prompt", "request_id": "r", "tenant_id": "", "messages": []})
    c.request("POST", "/v1/inference-hook", body=body, headers={"Content-Type": "text/plain", **headers})
    r = c.getresponse()
    return r.status


@pytest.mark.parametrize("headers", [
    {"Origin": "https://evil.example"},
    {"Origin": "null"},
    {"Host": "rebind.evil.example"},
    {"Sec-Fetch-Site": "cross-site"},
])
def test_browser_requests_are_refused(server, headers):
    assert _post(server, headers) == 403


def test_webhook_without_origin_still_served(server):
    assert _post(server, {}) != 403
