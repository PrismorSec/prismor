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
