"""Request-sized long-context pricing (#551)."""
import json

import pytest

from prismor.runtime import pricing, store, token_usage


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("PRISMOR_PRICING_OFFLINE", "1")
    # Deliberately synthetic rates, in USD/token as supplied by LiteLLM.
    rates = pricing._reduce_litellm({
        "tiered-model": {
            "input_cost_per_token": 1e-6,
            "output_cost_per_token": 2e-6,
            "cache_read_input_token_cost": 0.1e-6,
            "cache_creation_input_token_cost": 1.25e-6,
            "cache_creation_input_token_cost_above_1hr": 2e-6,
            "input_cost_per_token_above_200k_tokens": 2e-6,
            "output_cost_per_token_above_200k_tokens": 3e-6,
            "cache_read_input_token_cost_above_200k_tokens": 0.2e-6,
            "cache_creation_input_token_cost_above_200k_tokens": 2.5e-6,
            "cache_creation_input_token_cost_above_1hr_above_200k_tokens": 4e-6,
            "input_cost_per_token_above_200k_tokens_priority": 99e-6,  # service tier, not ours
        },
        "gpt-tiered": {  # OpenAI switches tiers above 272k
            "input_cost_per_token": 1e-6, "output_cost_per_token": 2e-6,
            "input_cost_per_token_above_272k_tokens": 2e-6,
            "output_cost_per_token_above_272k_tokens_flex": 99e-6,
        },
    })
    monkeypatch.setattr(pricing, "_table", lambda fetch=True: rates)
    return tmp_path


@pytest.mark.parametrize("model", ["tiered-model", "tiered-model[1m]"])
@pytest.mark.parametrize("input_tokens,expected", [
    (199_999, 0.199999), (200_000, 0.2), (200_001, 0.400002), (250_000, 0.5),
])
def test_tier_selected_by_request_input(workspace, model, input_tokens, expected):
    assert pricing.cost_usd({"input": input_tokens}, model) == pytest.approx(expected)


@pytest.mark.parametrize("input_tokens,expected", [(250_000, 0.25), (272_000, 0.272), (272_001, 0.544002)])
def test_threshold_comes_from_the_feed(workspace, input_tokens, expected):
    assert pricing.cost_usd({"input": input_tokens}, "gpt-tiered") == pytest.approx(expected)
    assert "output_long_context" not in pricing._table()["gpt-tiered"]  # _flex variant ignored


def test_cache_counts_towards_threshold_and_each_bucket_uses_its_rate(workspace):
    tokens = {"input": 50_000, "output": 10_000, "cache_read": 100_000,
              "cache_5m": 60_000, "cache_1h": 40_000}
    assert pricing.cost_usd(tokens, "tiered-model") == pytest.approx(
        0.1 + 0.03 + 0.02 + 0.15 + 0.16)


def test_output_does_not_select_the_input_tier(workspace):
    assert pricing.cost_usd({"input": 50_000, "output": 250_000}, "tiered-model") == pytest.approx(0.55)


def test_missing_tier_fields_keep_base_rates_and_zero_is_a_valid_rate(workspace):
    rate = pricing._table()["tiered-model"]
    assert rate["input_long_context"] == 2.0  # not the _priority variant
    for key in [k for k in rate if k.endswith("_long_context")]:
        del rate[key]
    assert pricing.cost_usd({"input": 250_000}, "tiered-model") == pytest.approx(0.25)
    rate["input_long_context"] = 0.0
    assert pricing.cost_usd({"input": 250_000}, "tiered-model") == 0.0


def _record(workspace, message_id, inp, *, model="tiered-model", session="s"):
    store.record_token_usage(
        workspace=workspace, session_id=session, message_id=message_id, model=model,
        ts="2026-10-15T00:00:00Z", input_tokens=inp, output_tokens=0, cache_read_tokens=0,
        cache_creation_tokens=0, cache_1h_tokens=0)


def _cost(workspace):
    return token_usage.sessions_cost(workspace, ["s"], backfill=False)["s"]


def test_many_small_requests_do_not_trigger_the_large_request_tier(workspace):
    for i in range(10):
        _record(workspace, f"m{i}", 50_000)
    result = _cost(workspace)
    assert result["usd"] == pytest.approx(0.5)
    assert result["turns"] == 10
    assert result["tokens"]["input"] == 500_000
    from prismor.runtime.cli import format_session_tokens
    rendered = format_session_tokens(dict(result, sessionId="s"))
    assert "$1.00" not in rendered
    assert rendered.count("$0.50") == 2  # session total and per-model total


def test_large_request_is_not_diluted_by_small_requests(workspace):
    _record(workspace, "large", 250_000)
    _record(workspace, "small", 50_000)
    assert _cost(workspace)["usd"] == pytest.approx(0.55)


def test_price_refresh_reprices_history(workspace):
    _record(workspace, "m", 250_000)
    assert _cost(workspace)["usd"] == pytest.approx(0.5)
    pricing._table()["tiered-model"]["input_long_context"] = 4.0  # e.g. a pricing.json fix
    assert _cost(workspace)["usd"] == pytest.approx(1.0)


def test_unknown_and_zero_cost_requests_remain_distinguishable(workspace):
    _record(workspace, "unknown", 1, model="unknown", session="unknown")
    pricing._table()["tiered-model"]["input_long_context"] = 0.0
    _record(workspace, "free", 250_000, session="free")
    result = token_usage.sessions_cost(workspace, ["unknown", "free", "absent"], backfill=False)
    assert result["unknown"]["known"] and not result["unknown"]["priced"]
    assert result["unknown"]["usd"] is None
    assert result["free"]["priced"] and result["free"]["usd"] == 0.0
    assert not result["absent"]["known"]


def test_proxy_telemetry_and_session_use_the_same_deduplicated_cost(workspace, monkeypatch):
    from prismor.runtime.enterprise import identity, telemetry_spool
    spooled = []
    monkeypatch.setattr(identity, "is_enrolled", lambda: True)
    monkeypatch.setattr(telemetry_spool, "append", lambda rows: spooled.extend(rows))
    for _ in range(2):
        token_usage.record_llm_usage(
            workspace=workspace, session_id="s", agent="prismor-proxy", model="tiered-model",
            message_id="m", usage={"input_tokens": 50_000, "output_tokens": 10_000,
                                   "cache_read_input_tokens": 200_000})
    assert len(spooled) == 1
    assert spooled[0]["cost_usd"] == pytest.approx(0.17)
    assert _cost(workspace)["usd"] == pytest.approx(spooled[0]["cost_usd"])
    assert _cost(workspace)["turns"] == 1


def test_transcript_backfill_uses_request_costs(workspace):
    path = workspace / "transcript.jsonl"
    path.write_text("\n".join(json.dumps({"type": "assistant", "message": {
        "id": f"m{i}", "model": "tiered-model[1m]", "usage": {
            "input_tokens": count, "output_tokens": 0}}})
        for i, count in enumerate((250_000, 50_000))) + "\n")
    assert token_usage.backfill_session(workspace, "s", str(path))
    assert token_usage.backfill_session(workspace, "s", str(path))
    assert _cost(workspace)["usd"] == pytest.approx(0.55)
    assert _cost(workspace)["turns"] == 2


@pytest.mark.parametrize("model,tokens,expected", [
    ("claude-opus-5-5", 300_000, 1.2),           # flat $4/M across the 1M window
    ("claude-haiku-5-5", 150_000, 0.075),        # >100k: $0.50/M
    ("gpt-6-astra", 300_000, 6.0),               # >272k: $20/M
    ("gemini-3.1-pro-preview", 250_000, 1.0),    # >200k: $4/M
])
def test_offline_snapshot_prices_current_models(tmp_path, monkeypatch, model, tokens, expected):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path))
    monkeypatch.setenv("PRISMOR_PRICING_OFFLINE", "1")
    pricing._table.cache_clear()
    assert pricing.cost_usd({"input": tokens}, model, fetch=False) == pytest.approx(expected)
    pricing._table.cache_clear()
