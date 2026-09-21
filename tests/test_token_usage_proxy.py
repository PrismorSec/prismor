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
                        lambda workspace, session_id, agent, row: rows.append(row))
    return rows


OPENAI_CHAT = dict(prompt_tokens=11, completion_tokens=7,
                   prompt_tokens_details={"cached_tokens": 4})
OPENAI_RESP = dict(input_tokens=20, output_tokens=5,
                   input_tokens_details={"cached_tokens": 8})
ANTHROPIC = dict(input_tokens=30, output_tokens=9,
                 cache_read_input_tokens=6, cache_creation_input_tokens=3)
GEMINI = dict(promptTokenCount=40, candidatesTokenCount=12,
              cachedContentTokenCount=5)


@pytest.mark.parametrize("usage,expect", [
    (OPENAI_CHAT, (11, 7, 4, 0)),
    (OPENAI_RESP, (20, 5, 8, 0)),
    (ANTHROPIC, (30, 9, 6, 3)),
    (GEMINI, (40, 12, 5, 0)),
])
def test_normalizes_each_provider_shape(captured_rows, usage, expect):
    tu.record_llm_usage(workspace=Path("/x"), session_id="s", agent="prismor-proxy",
                        model="m", usage=usage, message_id="mid")
    assert len(captured_rows) == 1
    r = captured_rows[0]
    got = (r["input_tokens"], r["output_tokens"],
           r["cache_read_tokens"], r["cache_creation_tokens"])
    assert got == expect


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
