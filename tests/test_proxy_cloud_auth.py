"""Cloud-provider credentials on the proxy: Bedrock SigV4, Vertex OAuth, Azure.

A managed model endpoint does not take a static API key, so the proxy could not
govern an agent pointed at Bedrock or Vertex at all. The signature here is the
part worth pinning: a subtly wrong one fails as a 403 from AWS, which reads
like a bad credential rather than a bug. The expected value below was verified
byte-for-byte against botocore's SigV4Auth.
"""
from __future__ import annotations

import datetime
import json
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

from prismor.runtime import proxy as proxy_mod  # noqa: E402
from prismor.runtime.proxy import (  # noqa: E402
    PROVIDER_ROUTES,
    ProxyConfigError,
    _aws_region_of,
    _canonical_query,
    aws_canonical_path,
    gcp_access_token,
    sigv4_headers,
)

AK = "AKIDEXAMPLE"
SK = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
HOST = "bedrock-runtime.us-east-1.amazon" + "aws.com"
NOW = datetime.datetime(2026, 9, 22, 12, 36, 0, tzinfo=datetime.timezone.utc)


def test_sigv4_matches_the_verified_vector():
    # Signature from botocore's SigV4Auth for the same request: the model id's
    # colon is signed double-encoded (%253A), as AWS does for non-S3 services.
    out = sigv4_headers(
        access_key=AK, secret_key=SK, session_token="", region="us-east-1",
        service="bedrock", method="POST",
        canonical_uri="/model/anthropic.claude-3-5-sonnet-20241022-v2:0/invoke",
        query="", payload=b'{"messages":[{"role":"user","content":"hi"}]}',
        host=HOST, now=NOW)
    assert out["x-amz-date"] == "20260922T123600Z"
    assert out["authorization"] == (
        "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260922/us-east-1/bedrock/"
        "aws4_request, SignedHeaders=host;x-amz-date, Signature="
        "e839270bb2133fcb4fa1f13bf192b97fd6121676891e5855707be8a191bd9920")


def test_session_token_is_signed_and_sent():
    out = sigv4_headers(
        access_key=AK, secret_key=SK, session_token="TOKEN123", region="us-east-1",
        service="bedrock", method="POST", canonical_uri="/model/m/invoke",
        query="", payload=b"{}", host=HOST, now=NOW)
    assert out["x-amz-security-token"] == "TOKEN123"
    assert "x-amz-security-token" in out["authorization"]


def test_body_is_bound_to_the_signature():
    kw = dict(access_key=AK, secret_key=SK, session_token="", region="us-east-1",
              service="bedrock", method="POST", canonical_uri="/model/m/invoke",
              query="", host=HOST, now=NOW)
    a = sigv4_headers(payload=b'{"a":1}', **kw)["authorization"]
    b = sigv4_headers(payload=b'{"a":2}', **kw)["authorization"]
    assert a != b            # a screened/masked body must be re-signed


def test_canonical_path_encodes_the_colon_and_is_idempotent():
    # a Bedrock model id carries a colon; signing it raw yields a 403
    once = aws_canonical_path("/model/anthropic.claude-v2:0/invoke")
    assert "%3A" in once
    assert aws_canonical_path(once) == once


def test_canonical_query_does_not_double_encode():
    assert _canonical_query("b=one%20two&a=2") == "a=2&b=one%20two"
    assert _canonical_query("") == ""


def test_region_comes_from_the_host_unless_named():
    assert _aws_region_of({}, "bedrock-runtime.eu-west-1.amazon" + "aws.com") == "eu-west-1"
    assert _aws_region_of({"region": "ap-south-1"}, HOST) == "ap-south-1"


def test_managed_endpoint_paths_are_screened_not_just_signed():
    routes = dict(PROVIDER_ROUTES)
    # Bedrock InvokeModel carries the Anthropic body shape
    assert routes["/invoke"] == "anthropic"
    # Azure puts the deployment in the path, so /v1/chat/completions never matches
    assert routes["/chat/completions"] == "openai"


def test_gcp_token_is_cached_and_refetched_after_expiry(monkeypatch):
    calls = []

    def fake_metadata():
        calls.append(1)
        return f"tok-{len(calls)}", 3600.0

    monkeypatch.setattr(proxy_mod, "_gcp_token_from_metadata", fake_metadata)
    monkeypatch.setitem(proxy_mod._GCP_TOKEN, "value", "")
    monkeypatch.setitem(proxy_mod._GCP_TOKEN, "expires", 0.0)

    assert gcp_access_token() == "tok-1"
    assert gcp_access_token() == "tok-1"      # cached, not refetched
    assert len(calls) == 1
    proxy_mod._GCP_TOKEN["expires"] = 0.0      # pretend it aged out
    assert gcp_access_token() == "tok-2"


def test_gcp_token_failure_is_an_actionable_config_error(monkeypatch):
    monkeypatch.setattr(proxy_mod, "_gcp_token_from_metadata", lambda: ("", 0.0))
    monkeypatch.setattr(proxy_mod, "_gcp_token_from_gcloud", lambda: ("", 0.0))
    monkeypatch.setitem(proxy_mod._GCP_TOKEN, "value", "")
    monkeypatch.setitem(proxy_mod._GCP_TOKEN, "expires", 0.0)
    with pytest.raises(ProxyConfigError, match="gcp-oauth"):
        gcp_access_token()


def test_client_signing_headers_are_replaced_not_forwarded(monkeypatch):
    """boto3/LiteLLM sign for themselves; their x-amz-* beside ours fails SigV4."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", AK)
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", SK)
    monkeypatch.setenv("AWS_SESSION_TOKEN", "TOKEN123")
    handler = proxy_mod.ProxyHandler.__new__(proxy_mod.ProxyHandler)
    handler.command = "POST"
    handler.headers = {"Authorization": "AWS4-HMAC-SHA256 client-sig",
                       "X-Amz-Date": "20200101T000000Z", "X-Amz-Security-Token": "client-token",
                       "X-Amzn-Bedrock-GuardrailIdentifier": "gr-1",
                       "Content-Type": "application/json"}
    out = handler._upstream_headers(
        {"auth": "aws-sigv4", "region": "us-east-1", "service": "bedrock"}, b"{}",
        host=HOST, path="/model/m-v1%3A0/invoke-with-response-stream", query="")
    names = [k.lower() for k in out]
    assert names.count("x-amz-date") == 1 and out.get("x-amz-date") != "20200101T000000Z"
    assert out.get("x-amz-security-token") == "TOKEN123"
    assert "client-sig" not in json.dumps(out)
    assert out.get("X-Amzn-Bedrock-GuardrailIdentifier") == "gr-1"
