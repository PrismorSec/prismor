"""prismor-lite local judge: transcript -> state, and the server reply -> finding."""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from prismor.runtime import local_judge


def _event(tmp_path, command="ls"):
    rows = [{"type": "user", "message": {"content": "fix the build"}},
            {"type": "assistant", "message": {"content": [
                {"type": "tool_use", "id": "a", "name": "Read", "input": {"file_path": "/r/x.py"}}]}},
            {"type": "user", "message": {"content": [{"type": "tool_result", "tool_use_id": "a", "content": "print(1)"}]}},
            {"type": "user", "message": {"content": "<command-name>/clear</command-name>"}},
            {"type": "user", "message": {"content": "now ship it"}}]
    t = tmp_path / "t.jsonl"
    t.write_text("\n".join(json.dumps(r) for r in rows))
    return {"agent_event": "PreToolUse", "metadata": {"raw": {
        "tool_name": "Bash", "cwd": "/r", "transcript_path": str(t), "tool_input": {"command": command}}}}


def test_state_from_transcript(tmp_path):
    st = local_judge.build_state(_event(tmp_path), "claude")
    assert st == {"agent": "claude-code", "user_task": "now ship it", "cwd": "/r",
                  "recent_context": [{"type": "file_read", "source": "/r/x.py", "excerpt": "print(1)"},
                                     {"type": "user_message", "source": "user", "excerpt": "fix the build"}],
                  "tool_call": {"tool": "Bash", "input": {"command": "ls"}}}


def test_no_server_no_finding(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path))
    assert local_judge.judge_finding(_event(tmp_path), "claude", "s1") is None


@pytest.mark.parametrize("verdict,action", [("deny", "block"), ("ask", "step_up"), ("allow", None)])
def test_verdict_to_finding(tmp_path, monkeypatch, verdict, action):
    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers["Content-Length"]))
            body = json.dumps({"verdict": verdict, "p_deny": 0.9, "p_ask": 0.05, "model": "m",
                               "state_tokens": 10, "kept_context": 2, "ms": 5}).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path))
    (tmp_path / "local-judge.json").write_text(json.dumps(
        {"url": f"http://127.0.0.1:{srv.server_port}", "mode": "enforce"}))
    try:
        f = local_judge.judge_finding(_event(tmp_path), "claude", "s1")
    finally:
        srv.shutdown()
    if action is None:
        assert f is None
    else:
        assert f["action"] == action and f["mode"] == "enforce" and f["ruleId"] == f"prismor-lite-{verdict}"


def test_post_tool_events_are_not_judged(tmp_path):
    ev = _event(tmp_path)
    ev["agent_event"] = "PostToolUse"
    assert local_judge.judge_finding(ev, "claude", "s1") is None
