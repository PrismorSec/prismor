"""prismor chatgpt-logs: compliance-log paging, record mapping, secret masking."""
import http.server
import json
import threading

import pytest

from prismor.runtime import chatgpt_logs as cgl

# Shapes from the published CONVERSATION_MESSAGE samples.
USER = {
    "event_id": "e1", "type": "CONVERSATION_MESSAGE",
    "principal": {"id": "ws-1", "type": "CHATGPT_WORKSPACE"},
    "actor": {"type": "ACCOUNT_USER", "user_id": "user-1", "user_email": "alice@example.com"},
    "timestamp": "2026-07-15T15:29:00.243000Z",
    "message": {"id": "m1", "created_at": "2026-07-15T15:29:00.243000Z",
                "author": {"type": "user", "client_type": "macos_app"},
                "content": {"type": "text", "value": "Draft a release note."}},
    "conversation": {"id": "c1", "title": "Release notes", "is_temporary_chat": False},
}
ASSISTANT = {**USER, "event_id": "e2", "message": {
    "id": "m2", "created_at": "2026-07-15T15:29:05Z",
    "author": {"type": "assistant", "model": "gpt-5-5", "tools_used": ["browser"]},
    "content": {"type": "text", "value": "Here it is."}}}


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("PRISMOR_AGENT_KEY", raising=False)


def test_user_text_is_a_prompt_and_model_text_is_untrusted_content():
    ev = cgl.to_event(USER)
    assert (ev["type"], ev["prompt"], ev["session_id"]) == ("prompt", "Draft a release note.", "c1")
    assert ev["occurred_at"] == "2026-07-15T15:29:00.243000Z"
    assert ev["metadata"]["client_type"] == "macos_app"
    out = cgl.to_event(ASSISTANT)
    assert (out["type"], out["content"]) == ("tool_result", "Here it is.")
    assert out["metadata"]["tools_used"] == ["browser"]
    assert cgl.to_event({**USER, "type": "AUTH_LOG"}) is None
    assert cgl.to_event({**USER, "message": {"content": {"value": "  "}}}) is None
    assert cgl.subject_of(USER).user_id == "alice@example.com"


def test_pages_forward_and_skips_the_boundary_file_the_api_repeats():
    pages = {
        "2026-01-01T00:00:00Z": {"data": [{"id": "f1"}, {"id": "f2"}], "has_more": True, "last_end_time": "T2"},
        # The boundary file comes back when re-queried from the cursor.
        "T2": {"data": [{"id": "f2"}, {"id": "f3"}], "has_more": False, "last_end_time": "T3"},
        "T3": {"data": [{"id": "f3"}], "has_more": False, "last_end_time": "T3"},
    }
    seen = []

    def fetch(url, headers):
        assert headers["Authorization"] == "Bearer k"
        if "/logs?" in url:
            assert "event_type=CONVERSATION_MESSAGE" in url
            return json.dumps(pages[url.split("after=")[1].split("&")[0].replace("%3A", ":")]).encode()
        seen.append(url.rsplit("/", 1)[1])
        return b""

    client = cgl.Client("k", "ws-1", fetch=fetch)
    assert client.root.endswith("/workspaces/ws-1/logs")
    state = {}
    list(cgl.iter_files(client, state, "2026-01-01T00:00:00Z"))
    assert seen == ["f1", "f2", "f3"]
    assert state == {"last_end_time": "T3", "last_file_id": "f3"}
    list(cgl.iter_files(client, state, "ignored"))  # nothing new
    assert seen == ["f1", "f2", "f3"]
    assert cgl.Client("k", "org-9", fetch=fetch).root.endswith("/organizations/org-9/logs")


def test_pasted_secret_is_found_and_masked_before_screening():
    key = "AKIA" + "IOSFODNN7" + "EXAMPLE"
    rec = {**USER, "message": {**USER["message"], "content": {"type": "text", "value": f"use {key} please"}}}
    ev = cgl.to_event(rec)
    findings = cgl._mask_secrets(ev)
    assert findings and findings[0]["category"] == "secret_exfiltration"
    assert key not in ev["prompt"] and key not in json.dumps(findings)


def test_sync_screens_every_message_and_keeps_its_cursor(tmp_path):
    body = "\n".join(json.dumps(r) for r in (USER, ASSISTANT, {"type": "AUTH_LOG"})).encode()

    def fetch(url, headers):
        if "/logs?" in url:
            return json.dumps({"data": [{"id": "f1"}], "has_more": False, "last_end_time": "T1"}).encode()
        return body

    counts = cgl.sync(cgl.Client("k", "ws-1", fetch=fetch), "ws-1", tmp_path, since="T0")
    assert counts == {"files": 1, "messages": 2, "findings": 0}
    assert cgl.load_state("ws-1") == {"last_end_time": "T1", "last_file_id": "f1"}


def test_download_redirect_drops_the_compliance_key_but_keeps_the_user_agent():
    got = {}

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path.startswith("/logs/"):
                self.send_response(307)
                self.send_header("Location", "/signed?sig=x")
                self.end_headers()
                return
            got["auth"] = self.headers.get("Authorization")
            got["ua"] = self.headers.get("User-Agent")
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"ok":1}\n')

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        body = cgl._get(f"http://127.0.0.1:{srv.server_port}/logs/f1", {"Authorization": "Bearer k"})
    finally:
        srv.shutdown()
    assert body == b'{"ok":1}\n' and got["auth"] is None
    assert got["ua"] == cgl._ua()


def test_missing_key_says_which_variable(monkeypatch, capsys):
    monkeypatch.delenv(cgl.KEY_ENV, raising=False)
    assert cgl.cmd_sync("ws-1", None, 24, cgl.DEFAULT_BASE) == 2
    assert cgl.KEY_ENV in capsys.readouterr().err
