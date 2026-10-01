import pytest

from prismor.runtime import pricing


@pytest.fixture(autouse=True)
def offline(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path))
    monkeypatch.setenv("PRISMOR_PRICING_OFFLINE", "1")
    pricing._table.cache_clear()
    yield
    pricing._table.cache_clear()


@pytest.mark.parametrize("model", [
    "us.anthropic.claude-sonnet-4-5-20250929-v1:0",
    "eu.anthropic.claude-sonnet-4-5-20250929-v1:0",
    "apac.anthropic.claude-sonnet-4-5-20250929-v1:0",
    "global.anthropic.claude-sonnet-4-5-20250929-v1:0",
    "us-gov.anthropic.claude-sonnet-4-5-20250929-v1:0",
    "anthropic.claude-sonnet-4-5-20250929-v1:0",
    "bedrock/us-east-1/anthropic.claude-sonnet-4-5-20250929-v1:0",
    "claude-sonnet-4-5@20250929",
    "vertex_ai/claude-sonnet-4-5@20250929",
    "claude-sonnet-4-5-20250929",
])
def test_cloud_ids_normalize_to_first_party(model):
    assert pricing.normalize_model(model) == "claude-sonnet-4-5"
    assert pricing.price_for(model) == pricing.PRICES["claude-sonnet-4-5"]


def test_bedrock_version_suffix_only_after_a_date():
    assert pricing.normalize_model("anthropic.claude-v2:1") == "claude-v2:1"   # Claude 2.1, not "claude"


@pytest.mark.parametrize("model,base", [
    ("gpt-5-codex", "gpt-5"),                  # same-price variant still matches
    ("gpt-4o-2024-08-06", "gpt-4o"),           # dated snapshot
    ("gpt-4o-mini-2024-07-18", "gpt-4o-mini"),
    ("claude-opus-4-1", "claude-opus-4-1"),
    ("claude-opus-5[1m]", "claude-opus-5"),
])
def test_prefix_keeps_correct_matches(model, base):
    assert pricing.price_for(model) == pricing.PRICES[base]


@pytest.mark.parametrize("model", [
    "gpt-5.9",            # was gpt-5 (no "-" boundary)
    "claude-opus-4-10",   # was claude-opus-4-1 (no "-" boundary, $15 vs $5)
    "claude-opus-4-9",    # was claude-opus-4 (older, 3x price)
    "o3-pro",             # was o3 (10x cheaper)
    "o3-mini",            # was o3
    "gpt-4.1-mini",       # was gpt-4.1
    "gpt-5-pro",          # was gpt-5
    "gemini-2.5-flash-lite",  # was gemini-2.5-flash
    "my-azure-deployment",
])
def test_different_model_is_unpriced_not_guessed(model):
    assert pricing.price_for(model) is None


def test_bare_feed_key_wins_over_provider_prefixed_regional_rate():
    rate = lambda usd: {"input_cost_per_token": usd, "output_cost_per_token": usd}
    table = pricing._reduce_litellm({
        "azure/eu/gpt-5.1": rate(1.375e-6),
        "au.anthropic.claude-sonnet-4-5-20250929-v1:0": rate(3.3e-6),
        "gpt-5.1": rate(1.25e-6),
        "claude-sonnet-4-5": rate(3e-6),
    })
    assert table["gpt-5.1"]["input"] == 1.25
    assert table["claude-sonnet-4-5"]["input"] == 3.0
    assert table["au.anthropic.claude-sonnet-4-5-20250929-v1:0"]["input"] == 3.3   # exact regional id kept
