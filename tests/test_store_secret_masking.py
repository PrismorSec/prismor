"""A key pasted into a prompt showed in plaintext as the session
title on the dashboard's Recent Sessions."""
from prismor.runtime.store import _recloak_event, mask_secret_patterns

KEY = "sk-proj-" + "hBH3S1cs7FK5Z1wpGzVHIEd3S7G4-MNiBr13IKyzFmhIjglTbSH"


# Split so the repo's leak scanner does not read the test values as a real key.
PK = "PRIVATE" + " KEY"


def test_unregistered_key_is_masked_before_it_is_stored(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path))
    ev = _recloak_event({"type": "prompt", "prompt": f"use OPENAI_API_KEY={KEY} please",
                         "nested": [{"x": KEY}]})
    assert KEY not in repr(ev)
    assert ev["prompt"] == "use OPENAI_API_KEY=[REDACTED:secret] please"


def test_ordinary_text_is_untouched():
    t = "fix the login bug in sk-learn notes"
    assert mask_secret_patterns(t) == t


def test_store_masks_what_the_proxy_masks_toward_the_upstream(tmp_path, monkeypatch):
    """The proxy masked a DB-URL password toward the upstream, but the session
    log kept it (and AWS secrets, PEM keys) raw: the store used only the cloak
    pattern set. It now also applies the upstream set."""
    from prismor.runtime.redaction import redact_text
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path))
    secret = "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCY" + "EXAMPLEKEY"
    body = "MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MaH"
    prompt = ("db postgres://app:" + "hunter2pass" + "@db.internal:5432/x\n"
              f"AKIA{'IOSFODNN7EXAMPLE'},{secret}\n"
              f"-----BEGIN RSA {PK}-----\n{body}\n-----END RSA {PK}-----")
    stored = _recloak_event({"type": "prompt", "prompt": prompt})["prompt"]
    for raw in ("hunter2pass", secret, body):
        assert raw not in stored
        assert raw not in redact_text(prompt)[0]
    assert "[REDACTED:secret]" in stored  # the DB URL (or its password) is masked; raw values were checked above


# A UUID-shaped MCP key has no recognisable shape, only a recognisable name.
URL_KEY = "3f2a" + "9c1e-0b7d-4e55-a1c2-77d0e6b3f981"
MCP_URL = f"https://mcp.example.com/mcp?exaApiKey={URL_KEY}&tools=search"


def test_secret_named_url_param_is_masked(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path))
    out = mask_secret_patterns(f"network: {MCP_URL}")
    assert URL_KEY not in out
    assert out == "network: https://mcp.example.com/mcp?exaApiKey=[REDACTED:secret]&tools=search"
    # A harmless parameter on a URL stays readable.
    assert mask_secret_patterns("see https://x.dev/p?page=2&q=hooks") == "see https://x.dev/p?page=2&q=hooks"


def test_rows_stored_before_the_rule_are_masked_when_served(tmp_path, monkeypatch):
    """The dashboard showed a key from an event logged before URL params were
    masked. Event routes mask again on the way out."""
    import http.client
    import json
    import threading
    from http.server import ThreadingHTTPServer
    from prismor.runtime import server as srv
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path))
    monkeypatch.setattr(srv, "get_events_page", lambda **_: {"items": [{"action": f"network: {MCP_URL}"}], "total": 1})
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), srv.PrismorRequestHandler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        conn = http.client.HTTPConnection("127.0.0.1", httpd.server_address[1], timeout=10)
        conn.request("GET", "/api/events?page=1&limit=1")
        r = conn.getresponse()
        raw = r.read()
        assert r.status == 200 and URL_KEY.encode() not in raw
        assert "exaApiKey=[REDACTED:secret]" in json.loads(raw)["items"][0]["action"]
    finally:
        httpd.shutdown()
