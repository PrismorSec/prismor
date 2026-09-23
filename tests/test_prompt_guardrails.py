"""Prompt guardrails: resolution order and when the hook re-sends them."""
from prismor.runtime.guardrails import context_for, effective


def test_effective_and_delivery(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path))

    b = {
        "agents": {"*": [{"id": "o", "text": "org"}], "claude": [{"id": "a", "text": "agent"}, "plain"]},
        "sessions": {"s1": {"add": [{"id": "x", "text": "session"}], "mute": ["a"]}},
    }
    assert [g["text"] for g in effective(b, "claude", "s0")] == ["org", "agent", "plain"]
    assert [g["text"] for g in effective(b, "claude", "s1")] == ["org", "plain", "session"]
    assert effective(None, "claude", "s1") == []
    kw = dict(agent="claude", session_id="s1")
    assert "1. org" in context_for(b, agent_event="UserPromptSubmit", **kw)  # first sight
    assert context_for(b, agent_event="UserPromptSubmit", **kw) is None  # unchanged
    assert "org" in context_for(b, agent_event="SessionStart", **kw)  # always on start/compact
    b["sessions"]["s1"]["mute"] = []
    assert "updated" in context_for(b, agent_event="UserPromptSubmit", **kw)
    assert "removed" in context_for({}, agent_event="UserPromptSubmit", **kw)
    assert context_for({}, agent_event="UserPromptSubmit", agent="codex", session_id="new") is None
    assert context_for(b, agent_event="PreToolUse", **kw) is None


def test_hook_dispatch_delivers_one_json_object(tmp_path):
    """SessionStart stdout must be exactly one JSON object (Claude Code rejects
    two), and a later prompt re-sends the set only after it changes."""
    import json
    import os
    import subprocess
    import sys

    ws = tmp_path / "ws"
    (ws / ".prismor").mkdir(parents=True)
    policy = ws / ".prismor" / "policy.yaml"
    policy.write_text(
        "settings:\n  prompt_guardrails:\n    agents:\n      claude:\n"
        "        - {id: g1, text: \"Never push to main.\"}\n",
        encoding="utf-8",
    )
    env = {k: v for k, v in os.environ.items() if not k.startswith("PRISMOR_")}
    env["PRISMOR_HOME"] = str(tmp_path / "home")

    def dispatch(event):
        payload = {"hook_event_name": event, "session_id": "s1", "cwd": str(ws), "prompt": "hi", "source": "startup"}
        out = subprocess.run(
            [sys.executable, "-m", "prismor.runtime.cli", "hook-dispatch", "--agent", "claude", "--workspace", str(ws)],
            input=json.dumps(payload), capture_output=True, text=True, env=env, timeout=120,
        ).stdout
        return json.loads(out) if out.strip() else None  # raises on two objects

    start = dispatch("SessionStart")
    assert "1. Never push to main." in start["hookSpecificOutput"]["additionalContext"]
    assert dispatch("UserPromptSubmit") is None
    policy.write_text(policy.read_text().replace("Never push to main.", "Never force-push."), encoding="utf-8")
    ctx = dispatch("UserPromptSubmit")["hookSpecificOutput"]["additionalContext"]
    assert "updated" in ctx and "Never force-push." in ctx


def test_proxy_adds_guardrails_to_each_provider_system_prompt():
    from prismor.runtime.proxy import add_system_text

    anth = {"model": "m", "max_tokens": 5, "system": "be terse", "messages": []}
    add_system_text("anthropic", anth, "G")
    assert anth["system"] == "be terse\n\nG"
    blocks = {"system": [{"type": "text", "text": "x"}], "messages": []}
    add_system_text("anthropic", blocks, "G")
    assert blocks["system"][-1] == {"type": "text", "text": "G"}
    chat = {"messages": [{"role": "system", "content": "s"}, {"role": "user", "content": "u"}]}
    add_system_text("openai", chat, "G")
    assert [m["role"] for m in chat["messages"]] == ["system", "system", "user"]
    assert chat["messages"][1]["content"] == "G"
    resp = {"input": "hi"}
    add_system_text("openai", resp, "G")
    assert resp["instructions"] == "G"
    gem = {"contents": []}
    add_system_text("google", gem, "G")
    assert gem["systemInstruction"] == {"parts": [{"text": "G"}]}
    legacy = {"prompt": "Human: hi"}
    add_system_text("anthropic", legacy, "G")
    assert legacy == {"prompt": "Human: hi"}
