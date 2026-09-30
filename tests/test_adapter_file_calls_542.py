"""#542: SDK tools that read a file are screened as file reads, and connection-URL
passwords are masked in tool results."""
import json
from pathlib import Path

from prismor.runtime.redaction import redact_text
from prismor.runtime.runtime import _retype_adapter_file_call, evaluate_tool_call

PW = "hun" + "ter2"


def _fn_tool_event(tool, args):
    # The shape prismor.openai builds for an Agents SDK FunctionTool call.
    return {"ts": "2026-09-29T00:00:00Z", "agent_event": "PreToolUse", "type": "shell",
            "command": " ".join(args.values()),
            "metadata": {"tool_name": tool, "framework": "openai-agents",
                         "kwargs": {"input": json.dumps(args)}}}


def test_read_tool_with_a_path_becomes_file_read():
    ev = _fn_tool_event("read_file", {"path": "/srv/payments/.env"})
    _retype_adapter_file_call(ev)
    assert ev["type"] == "file_read" and ev["path"] == "/srv/payments/.env"


def test_shell_tools_and_hook_events_are_left_alone():
    ev = _fn_tool_event("run_shell", {"command": "cat /srv/payments/.env"})
    _retype_adapter_file_call(ev)
    assert ev["type"] == "shell"
    hook = {"type": "shell", "command": "/srv/x", "metadata": {"tool_name": "read_file"}}
    _retype_adapter_file_call(hook)
    assert hook["type"] == "shell"


def test_env_read_through_an_sdk_tool_is_flagged(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / "home"))
    ws = tmp_path / "ws"
    ws.mkdir()
    d = evaluate_tool_call(event=_fn_tool_event("read_file", {"path": str(ws / ".env")}),
                           workspace=ws, agent="openai-agents", mode="enforce", session_id="s")
    assert any(f.get("category") == "secret_access" for f in d.findings), d.findings
    assert not d.allow


def test_connection_url_password_is_masked():
    out, changed = redact_text(f"DATABASE_URL=postgres://payments:{PW}@db.acme.internal/payments")
    assert changed and PW not in out
    assert "postgres://payments:[REDACTED:secret]@db.acme.internal/payments" in out
    plain = "see https://example.com/docs and git@github.com:org/repo.git"
    assert redact_text(plain) == (plain, False)
