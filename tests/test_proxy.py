"""LLM proxy — prompt screening, proposed-tool-call enforcement, stream holdback.

The proxy's claim over an ordinary AI gateway is that it judges the *tool call*
the model proposed, not just the prose, and that a streamed tool call never
reaches the client in complete form if policy denies it. Both are asserted
here by driving ``Screen`` and ``StreamScreen`` in-process with a stubbed
``evaluate_tool_call``, the same pattern the gateway tests use.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

from prismor.runtime import proxy as proxy_mod  # noqa: E402
from prismor.runtime.proxy import (  # noqa: E402
    ProxyConfig,
    ProxyConfigError,
    Screen,
    StreamScreen,
    _strip_blocked_calls,
    extract_prompt,
    response_tool_calls,
)
from prismor.runtime.runtime import Decision  # noqa: E402


# ── helpers ──────────────────────────────────────────────────────────────────

def _screen(monkeypatch, tmp_path, *, block_when=None, mode="enforce"):
    """A Screen whose engine denies any event whose text matches ``block_when``."""
    seen = []

    def fake_evaluate(*, event, **kwargs):
        seen.append(event)
        blob = json.dumps(event, default=str)
        if block_when and block_when in blob:
            # Deliberately does NOT echo the offending text: the streaming
            # tests assert the denied arguments never reach the client, and a
            # refusal that quotes them would make that assertion vacuous.
            blocking = {"ruleId": "destructive-command",
                        "message": "destructive filesystem command",
                        "action": "block"}
            return Decision(allow=False, findings=[blocking], blocking=blocking,
                            reason="destructive-command")
        return Decision(allow=True, findings=[])

    monkeypatch.setattr("prismor.runtime.runtime.evaluate_tool_call", fake_evaluate)
    monkeypatch.setattr("prismor.runtime.runtime.log_observe_findings",
                        lambda *a, **k: None)
    s = Screen(workspace=tmp_path, mode=mode, session_id="test-session")
    return s, seen


def _sse(name, payload):
    return f"event: {name}\ndata: {json.dumps(payload)}\n\n".encode()


# ── payload normalizers ──────────────────────────────────────────────────────

def test_extract_prompt_flattens_both_provider_shapes():
    anthropic = {"system": "be careful",
                 "messages": [{"role": "user",
                               "content": [{"type": "text", "text": "hello"},
                                           {"type": "tool_result",
                                            "content": [{"type": "text", "text": "leaked"}]}]}]}
    out = extract_prompt(anthropic)
    assert "be careful" in out and "hello" in out and "leaked" in out

    openai = {"messages": [{"role": "system", "content": "sys"},
                           {"role": "user", "content": "hi"}]}
    assert extract_prompt(openai) == "sys\nhi"


def test_response_tool_calls_reads_both_dialects():
    anthropic = {"content": [{"type": "text", "text": "ok"},
                             {"type": "tool_use", "name": "Bash",
                              "input": {"command": "ls"}}]}
    assert response_tool_calls("anthropic", anthropic) == [("Bash", {"command": "ls"})]

    openai = {"choices": [{"message": {"tool_calls": [
        {"function": {"name": "Bash", "arguments": '{"command": "ls"}'}}]}}]}
    assert response_tool_calls("openai", openai) == [("Bash", {"command": "ls"})]


# ── the point: a proposed tool call is a real tool call ──────────────────────

def test_proposed_bash_is_shaped_as_a_shell_event(monkeypatch, tmp_path):
    """A model's tool_use must reach the engine as the event a hook produces.

    If this regresses, the proxy stops being governed by the same rule table as
    every other surface and quietly degrades into a text filter.
    """
    screen, seen = _screen(monkeypatch, tmp_path)
    event = screen.tool_event("Bash", {"command": "rm -rf /"},
                              "anthropic", "claude-opus-5", None)
    screen.evaluate(event)

    assert seen[0]["type"] == "shell"
    assert seen[0]["command"] == "rm -rf /"
    assert seen[0]["agent_event"] == "PreToolUse"
    assert seen[0]["metadata"]["surface"] == "llm-proxy"


def test_unknown_tool_falls_back_to_payload_event(monkeypatch, tmp_path):
    screen, seen = _screen(monkeypatch, tmp_path)
    screen.evaluate(screen.tool_event("some_mcp_tool", {"q": "x"},
                                      "anthropic", "m", None))
    assert seen[0]["type"] == "tool_result"
    assert "some_mcp_tool" == seen[0]["metadata"]["tool_name"]


def test_observe_mode_never_blocks(monkeypatch, tmp_path):
    screen, _ = _screen(monkeypatch, tmp_path, block_when="rm -rf", mode="observe")
    decision = screen.evaluate(
        screen.tool_event("Bash", {"command": "rm -rf /"}, "anthropic", "m", None))
    assert screen.blocking(decision) is None


def test_enforce_mode_blocks(monkeypatch, tmp_path):
    screen, _ = _screen(monkeypatch, tmp_path, block_when="rm -rf")
    decision = screen.evaluate(
        screen.tool_event("Bash", {"command": "rm -rf /"}, "anthropic", "m", None))
    assert screen.blocking(decision) is not None


# ── streaming holdback ───────────────────────────────────────────────────────

def test_stream_holds_tool_block_until_judged_then_releases(monkeypatch, tmp_path):
    screen, _ = _screen(monkeypatch, tmp_path, block_when="rm -rf")
    stream = StreamScreen(screen, "anthropic", "claude-opus-5", None)

    out = b""
    out += stream.feed(_sse("content_block_start",
                            {"type": "content_block_start", "index": 0,
                             "content_block": {"type": "tool_use", "name": "Bash"}}))
    assert out == b"", "tool block must not stream out before it is judged"

    out += stream.feed(_sse("content_block_delta",
                            {"type": "content_block_delta", "index": 0,
                             "delta": {"type": "input_json_delta",
                                       "partial_json": '{"command": "ls'}}))
    out += stream.feed(_sse("content_block_delta",
                            {"type": "content_block_delta", "index": 0,
                             "delta": {"type": "input_json_delta",
                                       "partial_json": ' -la"}'}}))
    assert out == b"", "arguments must stay held mid-block"

    out += stream.feed(_sse("content_block_stop",
                            {"type": "content_block_stop", "index": 0}))
    assert b"input_json_delta" in out, "an allowed tool call must be released intact"
    assert not stream.blocked


def test_stream_replaces_denied_tool_block(monkeypatch, tmp_path):
    """The denied arguments must never appear in the client-bound bytes."""
    screen, _ = _screen(monkeypatch, tmp_path, block_when="rm -rf")
    stream = StreamScreen(screen, "anthropic", "claude-opus-5", None)

    out = b""
    out += stream.feed(_sse("content_block_start",
                            {"type": "content_block_start", "index": 0,
                             "content_block": {"type": "tool_use", "name": "Bash"}}))
    out += stream.feed(_sse("content_block_delta",
                            {"type": "content_block_delta", "index": 0,
                             "delta": {"type": "input_json_delta",
                                       "partial_json": '{"command": "rm -rf /"}'}}))
    out += stream.feed(_sse("content_block_stop",
                            {"type": "content_block_stop", "index": 0}))

    assert b"rm -rf" not in out
    assert b"Blocked by Prismor" in out
    assert stream.blocked


def test_refusal_reuses_the_replaced_block_index(monkeypatch, tmp_path):
    """The refusal must open at the tool block's own index, not a fresh 0.

    Caught on st3ve: a turn whose text block was index 0 and tool block index 1
    came back with two blocks both claiming index 0, which a client assembling
    by index mis-stitches.
    """
    screen, _ = _screen(monkeypatch, tmp_path, block_when="rm -rf")
    stream = StreamScreen(screen, "anthropic", "m", None)

    out = b""
    out += stream.feed(_sse("content_block_start",
                            {"type": "content_block_start", "index": 1,
                             "content_block": {"type": "tool_use", "name": "Bash"}}))
    out += stream.feed(_sse("content_block_delta",
                            {"type": "content_block_delta", "index": 1,
                             "delta": {"type": "input_json_delta",
                                       "partial_json": '{"command": "rm -rf /"}'}}))
    out += stream.feed(_sse("content_block_stop",
                            {"type": "content_block_stop", "index": 1}))

    indices = {json.loads(line[len("data: "):])["index"]
               for line in out.decode().splitlines() if line.startswith("data: ")}
    assert indices == {1}


def test_stream_text_passes_through(monkeypatch, tmp_path):
    screen, _ = _screen(monkeypatch, tmp_path, block_when="rm -rf")
    stream = StreamScreen(screen, "anthropic", "m", None)
    frame = _sse("content_block_delta",
                 {"type": "content_block_delta", "index": 0,
                  "delta": {"type": "text_delta", "text": "hello"}})
    assert stream.feed(frame) == frame


def test_openai_stream_holds_tool_calls(monkeypatch, tmp_path):
    screen, _ = _screen(monkeypatch, tmp_path, block_when="rm -rf")
    stream = StreamScreen(screen, "openai", "gpt-5.6", None)

    out = b""
    out += stream.feed(b'data: ' + json.dumps({"choices": [{"delta": {"tool_calls": [
        {"function": {"name": "Bash", "arguments": '{"command": "rm -rf /"}'}}]}}]}).encode() + b"\n\n")
    assert out == b""
    out += stream.feed(b'data: ' + json.dumps({"choices": [
        {"delta": {}, "finish_reason": "tool_calls"}]}).encode() + b"\n\n")
    assert b"rm -rf" not in out
    assert b"Blocked by Prismor" in out


def test_stream_survives_garbage_frames(monkeypatch, tmp_path):
    screen, _ = _screen(monkeypatch, tmp_path)
    stream = StreamScreen(screen, "anthropic", "m", None)
    assert stream.feed(b": ping\n\n") == b": ping\n\n"
    assert stream.feed(b"data: [DONE]\n\n") == b"data: [DONE]\n\n"


# ── refusal rendering ────────────────────────────────────────────────────────

def test_strip_blocked_calls_anthropic_keeps_turn_valid():
    body = {"content": [{"type": "tool_use", "name": "Bash", "input": {"command": "rm -rf /"}}],
            "stop_reason": "tool_use"}
    out = _strip_blocked_calls("anthropic", body, {"Bash": "Blocked by Prismor: nope"})
    assert all(b["type"] != "tool_use" for b in out["content"])
    assert out["stop_reason"] == "end_turn"
    assert "Blocked by Prismor" in out["content"][0]["text"]


def test_strip_blocked_calls_openai_drops_only_the_denied_one():
    body = {"choices": [{"message": {"content": "", "tool_calls": [
        {"function": {"name": "Bash", "arguments": "{}"}},
        {"function": {"name": "Read", "arguments": "{}"}}]}, "finish_reason": "tool_calls"}]}
    out = _strip_blocked_calls("openai", body, {"Bash": "Blocked by Prismor: nope"})
    kept = out["choices"][0]["message"]["tool_calls"]
    assert [c["function"]["name"] for c in kept] == ["Read"]
    assert "Blocked by Prismor" in out["choices"][0]["message"]["content"]


# ── config / virtual keys ────────────────────────────────────────────────────

def test_default_upstreams_present():
    cfg = ProxyConfig()
    assert cfg.upstream("anthropic")["base_url"] == "https://api.anthropic.com"
    assert cfg.chain("anthropic") == ["anthropic"]


def test_fallback_chain():
    cfg = ProxyConfig({"upstreams": {"anthropic": {"fallback": ["openai", "nope"]}}})
    assert cfg.chain("anthropic") == ["anthropic", "openai"]


def test_virtual_key_resolution():
    cfg = ProxyConfig({"keys": {"psk_live_abc": {"subject": "user:alice"}}})
    assert cfg.resolve_key("psk_live_abc") == {"subject": "user:alice"}
    assert cfg.resolve_key("psk_live_wrong") is None


def test_bad_config_raises():
    with pytest.raises(ProxyConfigError):
        ProxyConfig({"keys": ["not", "an", "object"]})


def test_default_workspace_is_not_the_launch_directory(monkeypatch, tmp_path):
    """A repo the proxy merely started in must not join every evaluation.

    Launched from a source checkout, the instruction-file scan reads that
    repo's CLAUDE.md and attributes it to every request -- which refused
    benign traffic with source=project_memory until the default moved.
    """
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / "home"))
    monkeypatch.chdir(tmp_path)
    ws = proxy_mod.default_workspace()
    assert ws != Path.cwd()
    assert ws == tmp_path / "home" / "surfaces" / "proxy"
    assert ws.is_dir()


def test_proxy_never_scans_the_instruction_files_near_its_store(monkeypatch, tmp_path):
    """The proxy judges traffic, not whatever CLAUDE.md sits near its workspace.

    It governs an agent it does not host, so instruction files beside its own
    directory describe nothing it is screening -- while a security project's
    CLAUDE.md quotes the attack strings its own rules match ($PRISMOR_HOME
    ships one), which scored 0.91 and refused every request with
    source: project_memory, benign traffic included.
    """
    from prismor.runtime import hooks
    from prismor.runtime.runtime import evaluate_tool_call

    scanned = []
    monkeypatch.setattr(hooks, "_read_project_memory",
                        lambda ws: scanned.append(ws) or {"content": "", "files": [], "digests": {}})

    event = {
        "type": "tool_result",
        "response": '{"query": "annual leave"}',
        "metadata": {"tool_name": "get_hr_policy", "cwd": str(tmp_path)},
    }
    evaluate_tool_call(event=event, workspace=tmp_path, agent="prismor-proxy",
                       mode="enforce", session_id="proxy-memory-scan", persist=False)
    assert scanned == [], "the proxy scanned a project it does not govern"


class _FakeHeaders(dict):
    def get(self, key, default=None):  # HTTPMessage lookups are case-insensitive
        for k, v in self.items():
            if k.lower() == key.lower():
                return v
        return default


def _provider_for(path, headers):
    """Call ProxyHandler._provider without standing up a server."""
    handler = proxy_mod.ProxyHandler.__new__(proxy_mod.ProxyHandler)
    handler.path = path
    handler.headers = _FakeHeaders(headers)
    handler.config = proxy_mod.ProxyConfig({})
    return proxy_mod.ProxyHandler._provider(handler)


def test_routed_paths_still_win_over_the_credential_shape():
    assert _provider_for("/v1/chat/completions", {"Authorization": "Bearer sk-x"}) == "openai"
    assert _provider_for("/v1/messages", {"Authorization": "Bearer oauth"}) == "anthropic"


def test_unrouted_path_follows_the_credential_the_client_presented():
    """/v1/models is what an SDK calls to verify a credential.

    Sending it to the default upstream answered an OpenAI client with
    Anthropic's 401, so n8n's Test button reported broken settings while every
    completion through the same credential worked.
    """
    assert _provider_for("/v1/models", {"Authorization": "Bearer sk-x"}) == "openai"
    assert _provider_for("/v1/models", {"x-api-key": "sk-ant-x"}) == "anthropic"
    assert _provider_for("/v1/models", {"Authorization": "Bearer oauth",
                                        "anthropic-version": "2023-06-01"}) == "anthropic"
    assert _provider_for("/v1/models", {}) == "anthropic"  # config default


def test_short_session_is_snapshotted_on_shutdown(monkeypatch, tmp_path):
    """A session shorter than the rebuild interval must still be visible.

    The rebuild is periodic because re-analysing the whole log on every event
    is quadratic for a long-lived surface. But a proxy session is often one
    chat turn -- the n8n agent that produced a blocked install command logged
    five events -- so periodic-only left a session log on disk and no session
    in `prismor sessions`, the dashboard or the console.
    """
    screen = proxy_mod.Screen(workspace=tmp_path, mode="observe",
                              session_id="short-session", agent_name="n8n")
    saved = []
    monkeypatch.setattr(proxy_mod.Screen, "_snapshot_one",
                        lambda self, sid: saved.append(sid))

    screen._persist({"type": "prompt", "prompt": "hello", "session_id": "short-session"})
    assert saved == [], "no periodic rebuild is due after one event"

    screen.snapshot()
    assert saved == ["short-session"], "shutdown must flush what is unsnapshotted"


def test_prompt_parts_separate_what_the_person_said(tmp_path):
    """The flattened blob is for policy; the parts are for the reader."""
    body = {"messages": [
        {"role": "system", "content": "You are an ops assistant with shell access."},
        {"role": "user", "content": "Install the monitoring agent."},
    ]}
    parts = proxy_mod.prompt_parts(body)
    assert parts["user_message"] == "Install the monitoring agent."
    assert "ops assistant" in parts["system"]
    # The blob still carries both, because that is what the rules read.
    assert "ops assistant" in proxy_mod.extract_prompt(body)
    assert "monitoring agent" in proxy_mod.extract_prompt(body)


def test_one_session_per_conversation_not_per_process(tmp_path):
    """Two chats through one proxy are two sessions; one chat stays one."""
    screen = proxy_mod.Screen(workspace=tmp_path, mode="observe",
                              session_id="proxy-1", agent_name="n8n")
    sys_msg = {"role": "system", "content": "You are an HR assistant."}
    chat_a_turn1 = {"messages": [sys_msg, {"role": "user", "content": "leave policy?"}]}
    chat_a_turn2 = {"messages": [sys_msg, {"role": "user", "content": "leave policy?"},
                                 {"role": "assistant", "content": "24 days"},
                                 {"role": "user", "content": "and carry over?"}]}
    chat_b = {"messages": [sys_msg, {"role": "user", "content": "wfh policy?"}]}

    a1 = screen.session_for(chat_a_turn1)
    a2 = screen.session_for(chat_a_turn2)
    b1 = screen.session_for(chat_b)
    assert a1 == a2, "a later turn of the same chat must stay in its session"
    assert a1 != b1, "a different chat must not merge into it"
    assert a1.startswith("proxy-1-")


def test_an_explicit_session_header_wins(tmp_path):
    screen = proxy_mod.Screen(workspace=tmp_path, mode="observe",
                              session_id="proxy-1", agent_name="n8n")
    sid = screen.session_for({"messages": []}, "n8n chat/42")
    assert sid == "proxy-1-n8n-chat-42", "the header is sanitized, not trusted verbatim"


def test_a_request_with_no_conversation_falls_back_to_the_process(tmp_path):
    screen = proxy_mod.Screen(workspace=tmp_path, mode="observe",
                              session_id="proxy-1", agent_name="n8n")
    assert screen.session_for({}) == "proxy-1"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q", "-p", "no:randomly"]))
