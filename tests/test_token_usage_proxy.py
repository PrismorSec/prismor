"""record_llm_usage: the proxy lane's provider-agnostic token-usage normalizer.

Before this, the LLM proxy metered usage but the sink only understood Claude
Code transcripts, so every proxied call's tokens were dropped. These tests pin
the normalization for all four provider usage shapes and the stream-side
accumulation, by capturing the row that would be stored (no DB needed).
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

from prismor.runtime import token_usage as tu  # noqa: E402
from prismor.runtime import proxy as proxy_mod  # noqa: E402
from prismor.runtime.proxy import Screen, StreamScreen  # noqa: E402


@pytest.fixture
def captured_rows(monkeypatch):
    rows = []
    monkeypatch.setattr(tu, "_record",
                        lambda workspace, session_id, agent, row, **kw: rows.append(row))
    return rows


OPENAI_CHAT = dict(prompt_tokens=11, completion_tokens=7,
                   prompt_tokens_details={"cached_tokens": 4})
OPENAI_RESP = dict(input_tokens=20, output_tokens=5,
                   input_tokens_details={"cached_tokens": 8})
ANTHROPIC = dict(input_tokens=30, output_tokens=9,
                 cache_read_input_tokens=6, cache_creation_input_tokens=3)
GEMINI = dict(promptTokenCount=40, candidatesTokenCount=12,
              cachedContentTokenCount=5)


# OpenAI/Gemini count cached tokens inside the prompt total; Anthropic keeps
# them apart. Normalized buckets must be disjoint or cached input bills twice.
@pytest.mark.parametrize("usage,expect", [
    (OPENAI_CHAT, (7, 7, 4, 0)),
    (OPENAI_RESP, (12, 5, 8, 0)),
    (ANTHROPIC, (30, 9, 6, 3)),
    (GEMINI, (35, 12, 5, 0)),
    (dict(prompt_tokens=2, completion_tokens=1, prompt_tokens_details={"cached_tokens": 5}), (0, 1, 5, 0)),
])
def test_normalizes_each_provider_shape(captured_rows, usage, expect):
    tu.record_llm_usage(workspace=Path("/x"), session_id="s", agent="prismor-proxy",
                        model="m", usage=usage, message_id="mid")
    assert len(captured_rows) == 1
    r = captured_rows[0]
    got = (r["input_tokens"], r["output_tokens"],
           r["cache_read_tokens"], r["cache_creation_tokens"])
    assert got == expect


@pytest.mark.parametrize("usage,output,reasoning", [
    # OpenAI reasoning is already inside output tokens: report, don't re-bill.
    (dict(OPENAI_CHAT, completion_tokens_details={"reasoning_tokens": 3}), 7, 3),
    (dict(OPENAI_RESP, output_tokens_details={"reasoning_tokens": 2}), 5, 2),
    # Gemini thoughts are separate from candidates and billed as output.
    (dict(GEMINI, thoughtsTokenCount=6), 18, 6),
    (ANTHROPIC, 9, 0),
])
def test_reasoning_tokens(captured_rows, usage, output, reasoning):
    tu.record_llm_usage(workspace=Path("/x"), session_id="s", agent="a",
                        model="m", usage=usage, message_id="mid")
    r = captured_rows[0]
    assert (r["output_tokens"], r["reasoning_tokens"]) == (output, reasoning)


def test_anthropic_1h_cache_write(captured_rows):
    usage = dict(ANTHROPIC, cache_creation={"ephemeral_1h_input_tokens": 2})
    tu.record_llm_usage(workspace=Path("/x"), session_id="s", agent="a",
                        model="m", usage=usage, message_id="mid")
    assert captured_rows[0]["cache_1h_tokens"] == 2


def test_telemetry_record_carries_reasoning_and_1h(monkeypatch):
    from prismor.runtime import store
    from prismor.runtime.enterprise import identity, telemetry_spool
    spooled, stored = [], []
    monkeypatch.setattr(store, "record_token_usage", lambda **k: stored.append(k) or True)
    monkeypatch.setattr(identity, "is_enrolled", lambda: True)
    monkeypatch.setattr(telemetry_spool, "append", lambda recs: spooled.extend(recs))
    usage = dict(ANTHROPIC, cache_creation={"ephemeral_1h_input_tokens": 2})
    tu.record_llm_usage(workspace=Path("/x"), session_id="s", agent="a", model="claude-sonnet-4-5",
                        usage=usage, message_id="m1")
    tu.record_llm_usage(workspace=Path("/x"), session_id="s", agent="a", model="gemini-2.5-pro",
                        usage=dict(GEMINI, thoughtsTokenCount=6), message_id="m2")
    assert "reasoning_tokens" not in stored[0]  # not a store column
    assert spooled[0]["usage"]["cache_1h_tokens"] == 2
    assert spooled[1]["usage"]["reasoning_tokens"] == 6
    assert spooled[1]["usage"]["input_tokens"] == 35


@pytest.mark.parametrize("usage,message_id", [
    ({}, "mid"),            # empty usage block carries no counts
    (OPENAI_CHAT, ""),      # no id -> can't dedupe -> skip
    ("not-a-dict", "mid"),  # malformed
])
def test_skips_when_nothing_to_record(captured_rows, usage, message_id):
    tu.record_llm_usage(workspace=Path("/x"), session_id="s", agent="a",
                        model="m", usage=usage, message_id=message_id)
    assert captured_rows == []


# ── stream-side accumulation ─────────────────────────────────────────────────

def _stream(monkeypatch, provider):
    """A StreamScreen whose meter() call is captured instead of stored."""
    calls = []
    monkeypatch.setattr(tu, "record_llm_usage",
                        lambda **kw: calls.append(kw))
    # a permissive engine so text/tool frames pass without a real policy
    monkeypatch.setattr("prismor.runtime.runtime.evaluate_tool_call",
                        lambda **k: __import__("prismor.runtime.runtime", fromlist=["Decision"]).Decision(allow=True, findings=[]))
    monkeypatch.setattr("prismor.runtime.runtime.log_observe_findings", lambda *a, **k: None)
    screen = Screen(workspace=Path("/x"), mode="observe", session_id="sess")
    return StreamScreen(screen, provider, "model", None), calls


def _frame(obj):
    import json
    return b"data: " + json.dumps(obj).encode() + b"\n\n"


def test_openai_stream_meters_final_usage(monkeypatch):
    stream, calls = _stream(monkeypatch, "openai")
    stream.feed(_frame({"id": "chatcmpl-1", "choices": [{"delta": {"content": "hi"}}]}))
    stream.feed(_frame({"id": "chatcmpl-1", "choices": [],
                        "usage": {"prompt_tokens": 12, "completion_tokens": 3}}))
    stream.meter()
    assert len(calls) == 1
    assert calls[0]["usage"]["prompt_tokens"] == 12
    assert calls[0]["message_id"] == "chatcmpl-1"


def test_anthropic_stream_merges_start_and_delta_usage(monkeypatch):
    stream, calls = _stream(monkeypatch, "anthropic")
    stream.feed(_frame({"type": "message_start",
                        "message": {"id": "msg_1", "usage": {"input_tokens": 25, "output_tokens": 1}}}))
    stream.feed(_frame({"type": "message_delta", "usage": {"output_tokens": 18}}))
    stream.meter()
    assert len(calls) == 1
    u = calls[0]["usage"]
    assert u["input_tokens"] == 25 and u["output_tokens"] == 18
    assert calls[0]["message_id"] == "msg_1"


def test_stream_without_usage_records_nothing(monkeypatch):
    stream, calls = _stream(monkeypatch, "openai")
    stream.feed(_frame({"id": "c", "choices": [{"delta": {"content": "hi"}}]}))
    stream.meter()
    assert calls == []


def test_buffered_meter_uses_the_request_session_not_the_process(monkeypatch):
    # A buffered (non-streaming) response's tokens must land on the request's
    # conversation, not the proxy's pid-keyed process session.
    calls = []
    monkeypatch.setattr(tu, "record_llm_usage", lambda **kw: calls.append(kw))
    screen = Screen(workspace=Path("/x"), mode="observe", session_id="process-sess")
    body = {"id": "resp-1", "usage": {"prompt_tokens": 9, "completion_tokens": 4}}
    proxy_mod._meter(screen, body, "gpt-6-luna", "conversation-42")
    assert calls[0]["session_id"] == "conversation-42"
    # No per-request id falls back to the process session, as before.
    proxy_mod._meter(screen, body, "gpt-6-luna")
    assert calls[1]["session_id"] == "process-sess"


def test_proxy_usage_gets_a_timestamp(captured_rows):
    # An empty ts fell outside every `ts >= datetime('now', ...)` cost window.
    tu.record_llm_usage(workspace=Path("/x"), session_id="s", agent="a", model="m",
                        usage={"input_tokens": 3, "output_tokens": 1}, message_id="resp_1")
    assert captured_rows[0]["ts"]


def test_usage_record_carries_the_proxy_agent_name(monkeypatch):
    """#543: without agent_name every metered turn showed up in the console as a
    second, unnamed 'prismor-proxy' agent next to the --agent-name one."""
    from prismor.runtime import store
    from prismor.runtime.enterprise import identity, telemetry_spool
    spooled = []
    monkeypatch.setattr(store, "record_token_usage", lambda **k: True)
    monkeypatch.setattr(identity, "is_enrolled", lambda: True)
    monkeypatch.setattr(telemetry_spool, "append", lambda recs: spooled.extend(recs))
    tu.record_llm_usage(workspace=Path("/x"), session_id="s", agent="prismor-proxy",
                        agent_name="data-analyst", model="gpt-5-mini",
                        usage=OPENAI_CHAT, message_id="m1")
    assert [(r["agent"], r["agent_name"]) for r in spooled] == [("prismor-proxy", "data-analyst")]


def test_stream_meter_passes_the_screen_agent_name(monkeypatch):
    calls = []
    monkeypatch.setattr(tu, "record_llm_usage", lambda **kw: calls.append(kw))
    screen = Screen(workspace=Path("/x"), mode="observe", session_id="sess", agent_name="data-analyst")
    stream = StreamScreen(screen, "openai", "model", None)
    stream._usage = dict(OPENAI_CHAT)
    stream.meter()
    assert calls and calls[0]["agent_name"] == "data-analyst"
