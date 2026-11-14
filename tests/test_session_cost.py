import json
from pathlib import Path

import pytest

from prismor.runtime import pricing, token_usage


def _claude_line(msg_id, model, inp, out, cread, ccreate, c1h=0):
    return json.dumps({
        "type": "assistant", "timestamp": "2026-09-14T00:00:00Z", "requestId": "req_" + msg_id,
        "message": {"id": msg_id, "model": model, "usage": {
            "input_tokens": inp, "output_tokens": out,
            "cache_read_input_tokens": cread, "cache_creation_input_tokens": ccreate,
            "cache_creation": {"ephemeral_5m_input_tokens": ccreate - c1h, "ephemeral_1h_input_tokens": c1h},
        }},
    })


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("PRISMOR_PRICING_OFFLINE", "1")
    pricing._table.cache_clear()
    return tmp_path


def test_litellm_feed_cached_12h(home, monkeypatch):
    import io, os, urllib.request
    calls = []
    feed = {"anthropic/claude-zeta-9": {"input_cost_per_token": 1e-6, "output_cost_per_token": 2e-6,
            "cache_read_input_token_cost": 1e-7, "cache_creation_input_token_cost": 1.25e-6}}
    monkeypatch.delenv("PRISMOR_PRICING_OFFLINE")
    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: (calls.append(1), io.BytesIO(json.dumps(feed).encode()))[1])
    cache = home / "home" / "pricing-cache.json"

    assert pricing._fetch_litellm(cache)["claude-zeta-9"]["cache_write"] == 1.25
    assert pricing._fetch_litellm(cache)["claude-zeta-9"]["input"] == 1.0   # served from cache
    assert len(calls) == 1
    os.utime(cache, (0, 0))                                                 # cache older than TTL
    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: (_ for _ in ()).throw(OSError("offline")))
    assert pricing._fetch_litellm(cache)["claude-zeta-9"]["input"] == 1.0   # stale cache beats no data
    pricing._table.cache_clear()
    assert pricing.price_for("claude-zeta-9-20270101")["output"] == 2.0


def test_claude_session_cost(home, monkeypatch):
    ws = home / "ws"
    ws.mkdir()
    transcript = home / "s1.jsonl"
    transcript.write_text("\n".join([
        json.dumps({"type": "user", "message": {"role": "user", "content": "hi"}}),
        _claude_line("m1", "claude-sonnet-5-20260101", 1_000_000, 0, 0, 0),
        _claude_line("m1", "claude-sonnet-5-20260101", 1_000_000, 0, 0, 0),   # same turn, two content lines
        _claude_line("m2", "claude-sonnet-5", 0, 100_000, 1_000_000, 1_000_000, c1h=1_000_000),
        _claude_line("m3", "mystery-model-9", 5, 5, 0, 0),
        _claude_line("m4", "<synthetic>", 0, 0, 0, 0),
        "not json",
    ]) + "\n")

    from prismor.runtime.enterprise import identity, telemetry_spool
    spooled = []
    monkeypatch.setattr(identity, "is_enrolled", lambda: True)
    monkeypatch.setattr(telemetry_spool, "append", lambda recs: spooled.extend(recs))

    assert token_usage.backfill_session(ws, "s1", str(transcript))
    assert token_usage.backfill_session(ws, "s1", str(transcript))   # rerun: nothing new to spool
    cost = token_usage.session_cost(ws, "s1")

    assert [r["type"] for r in spooled] == ["llm_usage"] * 3
    assert spooled[0]["event_id"] == "evt_usage_m1" and spooled[0]["provider"] == "anthropic"
    assert sum(r["cost_usd"] or 0 for r in spooled) == pytest.approx(cost["usd"])

    assert cost["known"] and cost["priced"]
    assert cost["turns"] == 3
    assert cost["unpriced"] == ["mystery-model-9"]
    # sonnet-5: in $2, out $10, cache read $0.2, 1h cache write $4 per 1M.
    assert cost["usd"] == pytest.approx(2 + 1.0 + 0.2 + 4)
    assert cost["tokens"]["cache_1h"] == 1_000_000

    assert token_usage.session_cost(ws, "nope")["known"] is False


def test_codex_deltas(home):
    ws = home / "ws"
    ws.mkdir()
    sid = "019cbcd0-d170-7a01-a89a-59bcd51a874f"
    path = home / f"rollout-2026-03-05T12-35-27-{sid}.jsonl"
    tc = json.dumps({"type": "turn_context", "payload": {"model": "gpt-5"}})
    def tc_line(total, last=None):
        return json.dumps({"timestamp": "t", "type": "event_msg", "payload": {"type": "token_count", "info": {
            "total_token_usage": total, "last_token_usage": last}}})
    t1 = {"input_tokens": 1000, "cached_input_tokens": 400, "cache_write_input_tokens": 0, "output_tokens": 100}
    t2 = {"input_tokens": 3000, "cached_input_tokens": 1400, "cache_write_input_tokens": 0, "output_tokens": 300}
    path.write_text("\n".join([tc, tc_line(None), tc_line(t1, t1), tc_line(t1, t1), tc_line(t2)]) + "\n")

    assert token_usage.backfill_session(ws, sid, str(path))
    cost = token_usage.session_cost(ws, sid)
    assert cost["turns"] == 2                      # repeated total ignored, missing last -> delta
    assert cost["tokens"] == {"input": 1600, "output": 300, "cache_read": 1400, "cache_5m": 0, "cache_1h": 0}
    assert cost["usd"] == pytest.approx((1600 * 1.25 + 300 * 10 + 1400 * 0.125) / 1e6)


def test_pricing_lookup(home):
    assert pricing.price_for("anthropic/claude-opus-4-8-20260401")["input"] == 5.0
    assert pricing.price_for("claude-opus-4-1")["input"] == 15.0
    assert pricing.price_for("claude-fable-5-1[1m]")["output"] == 50.0
    assert pricing.price_for("claude-opus-5-20261001")["cache_1h"] == 10.0
    assert pricing.price_for("gpt-9-nova") is None
    (Path(home / "home")).mkdir(exist_ok=True)
    (home / "home" / "pricing.json").write_text(json.dumps({"gpt-9": {"input": 1, "output": 2, "cache_read": 0, "cache_write": 0}}))
    pricing._table.cache_clear()
    assert pricing.price_for("gpt-9-nova")["output"] == 2


def test_subagent_transcripts_counted_at_final_usage(home):
    """Subagents write to <session>/subagents/agent-*.jsonl, one line per
    content block with output_tokens still growing: count the max, once."""
    ws = home / "ws"
    ws.mkdir()
    transcript = home / "s2.jsonl"
    transcript.write_text(_claude_line("m1", "claude-sonnet-5", 10, 5, 0, 0) + "\n")
    sub = home / "s2" / "subagents"
    sub.mkdir(parents=True)
    (sub / "agent-a1.jsonl").write_text("\n".join([
        _claude_line("sa1", "claude-sonnet-5", 7, 1, 100, 0),
        _claude_line("sa1", "claude-sonnet-5", 7, 40, 100, 0),
        _claude_line("sa1", "claude-sonnet-5", 7, 90, 100, 0),
    ]) + "\n")

    assert token_usage.backfill_session(ws, "s2", str(transcript))
    cost = token_usage.session_cost(ws, "s2")

    assert cost["turns"] == 2
    assert cost["tokens"]["output"] == 5 + 90
    assert cost["tokens"]["input"] == 10 + 7


def test_repeat_message_keeps_larger_counts(home):
    from prismor.runtime import store
    ws = home / "ws"
    ws.mkdir()
    row = dict(workspace=ws, session_id="s3", ts="2026-09-14T00:00:00Z", message_id="m",
               model="claude-sonnet-5", input_tokens=10, output_tokens=5,
               cache_read_tokens=0, cache_creation_tokens=0)
    assert store.record_token_usage(**row)
    assert not store.record_token_usage(**row)                          # same counts: no change
    assert store.record_token_usage(**{**row, "output_tokens": 50})     # grew
    assert not store.record_token_usage(**{**row, "output_tokens": 1})  # never shrinks
    assert store.get_sessions_token_usage(["s3"])["s3"]["by_model"]["claude-sonnet-5"]["output"] == 50


def test_token_stats_backfills_active_sessions(home, monkeypatch):
    """Hooks record only the turn before each tool call; a windowed total
    must read the transcripts first or it runs behind them."""
    from datetime import datetime, timezone
    ws = home / "ws"
    ws.mkdir()
    now = datetime.now(timezone.utc).isoformat()
    transcript = home / "s4.jsonl"
    transcript.write_text("\n".join(
        json.dumps({**json.loads(_claude_line(m, "claude-sonnet-5", 1, n, 0, 0)), "timestamp": now})
        for m, n in (("t1", 3), ("t2", 4))) + "\n")
    monkeypatch.setattr(token_usage.store, "get_active_sessions", lambda hours: [("s4", str(ws))])
    monkeypatch.setattr(token_usage, "find_transcript", lambda sid: transcript)

    assert token_usage.token_stats(None, hours=24)["outputTokens"] == 7
