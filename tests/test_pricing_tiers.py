"""Request-sized pricing, including legacy rows without a recorded cost (#551)."""
import json
import sqlite3

import pytest

from prismor.runtime import pricing, store, token_usage


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("PRISMOR_PRICING_OFFLINE", "1")
    # Deliberately synthetic rates, in USD/token as supplied by LiteLLM.
    rates = pricing._reduce_litellm({"tiered-model": {
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
    }})
    monkeypatch.setattr(pricing, "_table", lambda fetch=True: rates)
    tmp_path.mkdir(exist_ok=True)
    return tmp_path


@pytest.mark.parametrize("model", ["tiered-model", "tiered-model[1m]"])
@pytest.mark.parametrize("input_tokens,expected", [
    (199_999, 0.199999), (200_000, 0.2), (200_001, 0.400002), (250_000, 0.5),
])
def test_tier_selected_by_request_input(workspace, model, input_tokens, expected):
    assert pricing.cost_usd({"input": input_tokens}, model) == pytest.approx(expected)


def test_cache_counts_towards_threshold_and_each_bucket_uses_its_rate(workspace):
    tokens = {"input": 50_000, "output": 10_000, "cache_read": 100_000,
              "cache_5m": 60_000, "cache_1h": 40_000}
    assert pricing.cost_usd(tokens, "tiered-model") == pytest.approx(
        0.1 + 0.03 + 0.02 + 0.15 + 0.16)


def test_output_does_not_select_the_input_tier(workspace):
    assert pricing.cost_usd({"input": 50_000, "output": 250_000}, "tiered-model") == pytest.approx(0.55)


def test_missing_tier_fields_keep_base_rates_and_zero_is_a_valid_rate(workspace):
    rate = pricing._table()["tiered-model"]
    for key in list(rate):
        if key.endswith("_above_200k"):
            del rate[key]
    assert pricing.cost_usd({"input": 250_000}, "tiered-model") == pytest.approx(0.25)
    rate["input_above_200k"] = 0.0
    assert pricing.cost_usd({"input": 250_000}, "tiered-model") == 0.0


def _record(workspace, message_id, inp, *, legacy=False, model="tiered-model", session="s"):
    row = dict(message_id=message_id, model=model, ts="2026-10-15T00:00:00Z",
               input_tokens=inp, output_tokens=0, cache_read_tokens=0,
               cache_creation_tokens=0, cache_1h_tokens=0)
    if legacy:
        store.record_token_usage(workspace=workspace, session_id=session, **row)
    else:
        token_usage._record(workspace, session, "claude", row)


def _cost(workspace):
    return token_usage.sessions_cost(workspace, ["s"], backfill=False)["s"]


@pytest.mark.parametrize("legacy", [False, True])
def test_many_small_requests_do_not_trigger_the_large_request_tier(workspace, legacy):
    for i in range(10):
        _record(workspace, f"m{i}", 50_000, legacy=legacy)
    result = _cost(workspace)
    assert result["usd"] == pytest.approx(0.5)
    assert result["turns"] == 10
    assert result["tokens"]["input"] == 500_000
    from prismor.runtime.cli import format_session_tokens
    rendered = format_session_tokens(dict(result, sessionId="s"))
    assert "tiered-model" in rendered
    assert "$1.00" not in rendered
    assert rendered.count("$0.50") == 2  # session total and per-model total


@pytest.mark.parametrize("legacy", [False, True])
def test_large_request_is_not_diluted_by_small_requests(workspace, legacy):
    _record(workspace, "large", 250_000, legacy=legacy)
    _record(workspace, "small", 50_000, legacy=legacy)
    assert _cost(workspace)["usd"] == pytest.approx(0.55)


def test_recorded_cost_is_stable_and_legacy_rows_are_priced_individually(workspace):
    _record(workspace, "new", 250_000)
    _record(workspace, "old", 50_000, legacy=True)
    # A price refresh must not reprice an already metered request.
    pricing._table()["tiered-model"]["input_above_200k"] = 9.0
    assert _cost(workspace)["usd"] == pytest.approx(0.55)


def test_pricing_failure_does_not_drop_usage(workspace, monkeypatch):
    with monkeypatch.context() as patch:
        def broken_price(*args, **kwargs):
            raise ValueError("malformed price override")
        patch.setattr(token_usage, "cost_usd", broken_price)
        _record(workspace, "m", 250_000)
    assert _cost(workspace)["turns"] == 1
    assert _cost(workspace)["usd"] == pytest.approx(0.5)


def test_unknown_model_can_be_priced_later(workspace):
    _record(workspace, "m", 250_000, model="new-model")
    assert not _cost(workspace)["priced"]
    pricing._table()["new-model"] = dict(pricing._table()["tiered-model"])
    assert _cost(workspace)["usd"] == pytest.approx(0.5)


def test_unknown_and_zero_cost_requests_remain_distinguishable(workspace):
    _record(workspace, "unknown", 1, model="unknown", session="unknown")
    pricing._table()["tiered-model"]["input_above_200k"] = 0.0
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


def test_existing_database_gets_nullable_cost_column(workspace):
    db = store.prismor_home() / "prismor.db"
    db.parent.mkdir(parents=True)
    with sqlite3.connect(db) as conn:
        conn.execute("""CREATE TABLE token_usage (
            message_id TEXT PRIMARY KEY, session_id TEXT, workspace_path TEXT, ts TEXT, model TEXT,
            input_tokens INTEGER, output_tokens INTEGER, cache_read_tokens INTEGER,
            cache_creation_tokens INTEGER, cache_1h_tokens INTEGER DEFAULT 0)""")
        conn.execute("INSERT INTO token_usage VALUES ('old', 's', '', '', 'tiered-model', 250000, 0, 0, 0, 0)")
    assert _cost(workspace)["usd"] == pytest.approx(0.5)
    with sqlite3.connect(db) as conn:
        assert conn.execute("SELECT cost_usd FROM token_usage").fetchone()[0] is None


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
