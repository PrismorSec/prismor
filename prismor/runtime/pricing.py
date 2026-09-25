"""Static per-model prices (USD per 1M tokens) for session cost estimates.

``cache_write`` is the 5-minute cache-creation rate; ``cache_1h`` the 1-hour
rate (defaults to 2x input when absent). Unknown model -> ``None`` (never $0) so callers can show
"unpriced" instead of a misleading zero.

Rates refresh from LiteLLM's public price file at most once per 12 hours
(cached at ``$PRISMOR_HOME/pricing-cache.json``; set ``PRISMOR_PRICING_OFFLINE=1``
to never fetch). Override or extend with ``$PRISMOR_HOME/pricing.json``
({model: {input, output, cache_read, cache_write, cache_1h}}, USD per 1M).
"""

from __future__ import annotations

import json
import os
import re
import time
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Optional

PRICING_URL = "https://raw.githubusercontent.com/BerriAI/litellm/main/model_prices_and_context_window.json"
PRICING_TTL_SECONDS = 12 * 3600
PRICING_TIMEOUT_SECONDS = 5

# Offline floor: a snapshot of LiteLLM's price file (USD per 1M, 2026-09-14).
# The live feed below overrides it; this only matters on a machine that never
# reaches the network.
PRICES: Dict[str, Dict[str, float]] = {
    "claude-opus-4": {"input": 15.0, "output": 75.0, "cache_read": 1.5, "cache_write": 18.75, "cache_1h": 30.0},
    "claude-opus-4-1": {"input": 15.0, "output": 75.0, "cache_read": 1.5, "cache_write": 18.75, "cache_1h": 30.0},
    "claude-opus-4-5": {"input": 5.0, "output": 25.0, "cache_read": 0.5, "cache_write": 6.25, "cache_1h": 10.0},
    "claude-opus-4-6": {"input": 5.0, "output": 25.0, "cache_read": 0.5, "cache_write": 6.25, "cache_1h": 10.0},
    "claude-opus-4-7": {"input": 5.0, "output": 25.0, "cache_read": 0.5, "cache_write": 6.25, "cache_1h": 10.0},
    "claude-opus-4-8": {"input": 5.0, "output": 25.0, "cache_read": 0.5, "cache_write": 6.25, "cache_1h": 10.0},
    "claude-opus-5": {"input": 5.0, "output": 25.0, "cache_read": 0.5, "cache_write": 6.25, "cache_1h": 10.0},
    "claude-fable-5-1": {"input": 10.0, "output": 50.0, "cache_read": 0.25, "cache_write": 12.5, "cache_1h": 20.0},
    "claude-sonnet-4": {"input": 3.0, "output": 15.0, "cache_read": 0.3, "cache_write": 3.75, "cache_1h": 6.0},
    "claude-sonnet-4-5": {"input": 3.0, "output": 15.0, "cache_read": 0.3, "cache_write": 3.75, "cache_1h": 6.0},
    "claude-sonnet-4-6": {"input": 3.0, "output": 15.0, "cache_read": 0.3, "cache_write": 3.75, "cache_1h": 6.0},
    "claude-sonnet-5": {"input": 2.0, "output": 10.0, "cache_read": 0.2, "cache_write": 2.5, "cache_1h": 4.0},
    "claude-haiku-4-5": {"input": 1.0, "output": 5.0, "cache_read": 0.1, "cache_write": 1.25, "cache_1h": 2.0},
    "gpt-5": {"input": 1.25, "output": 10.0, "cache_read": 0.125, "cache_write": 0.0},
    "gpt-5-mini": {"input": 0.25, "output": 2.0, "cache_read": 0.025, "cache_write": 0.0},
    "gpt-5-nano": {"input": 0.05, "output": 0.4, "cache_read": 0.005, "cache_write": 0.0},
    "gpt-5.1": {"input": 1.25, "output": 10.0, "cache_read": 0.125, "cache_write": 0.0},
    "gpt-5.2": {"input": 1.75, "output": 14.0, "cache_read": 0.175, "cache_write": 0.0},
    "gpt-5.5": {"input": 5.0, "output": 30.0, "cache_read": 0.5, "cache_write": 0.0},
    "gpt-4.1": {"input": 2.0, "output": 8.0, "cache_read": 0.5, "cache_write": 0.0},
    "gpt-4o": {"input": 2.5, "output": 10.0, "cache_read": 1.25, "cache_write": 0.0},
    "gpt-4o-mini": {"input": 0.15, "output": 0.6, "cache_read": 0.075, "cache_write": 0.0},
    "o3": {"input": 2.0, "output": 8.0, "cache_read": 0.5, "cache_write": 0.0},
    "o4-mini": {"input": 1.1, "output": 4.4, "cache_read": 0.275, "cache_write": 0.0},
    "gemini-2.5-pro": {"input": 1.25, "output": 10.0, "cache_read": 0.125, "cache_write": 0.0},
    "gemini-2.5-flash": {"input": 0.3, "output": 2.5, "cache_read": 0.03, "cache_write": 0.0},
}

CACHE_1H_INPUT_MULTIPLIER = 2.0


def _reduce_litellm(raw: Dict[str, Any]) -> Dict[str, Dict[str, float]]:
    """LiteLLM per-token USD -> our per-1M shape, keyed by normalized model id."""
    out: Dict[str, Dict[str, float]] = {}
    for key, v in raw.items():
        if not isinstance(v, dict) or v.get("input_cost_per_token") is None:
            continue
        per_m = lambda f: round(float(v.get(f) or 0) * 1_000_000, 6)
        rate = {
            "input": per_m("input_cost_per_token"), "output": per_m("output_cost_per_token"),
            "cache_read": per_m("cache_read_input_token_cost"), "cache_write": per_m("cache_creation_input_token_cost"),
        }
        if v.get("cache_creation_input_token_cost_above_1hr"):
            rate["cache_1h"] = per_m("cache_creation_input_token_cost_above_1hr")
        out.setdefault(normalize_model(key), rate)  # first (bare) key wins over provider-prefixed dupes
    return out


def _fetch_litellm(cache: Path) -> Dict[str, Dict[str, float]]:
    """Cached fetch: reuse the cache while it is younger than the TTL, refetch
    otherwise, and keep serving a stale cache when the network is down."""
    fresh = cache.is_file() and time.time() - cache.stat().st_mtime < PRICING_TTL_SECONDS
    if not fresh and not os.environ.get("PRISMOR_PRICING_OFFLINE"):
        try:
            import urllib.request
            with urllib.request.urlopen(PRICING_URL, timeout=PRICING_TIMEOUT_SECONDS) as resp:  # fixed or operator-configured URL  # nosec B310
                table = _reduce_litellm(json.loads(resp.read().decode("utf-8")))
            cache.parent.mkdir(parents=True, exist_ok=True)
            cache.write_text(json.dumps(table), encoding="utf-8")
            return table
        except Exception:
            pass
    try:
        return json.loads(cache.read_text(encoding="utf-8"))
    except Exception:
        return {}


@lru_cache(maxsize=2)
def _table(fetch: bool = True) -> Dict[str, Dict[str, float]]:
    """static snapshot < LiteLLM feed (12h cache) < $PRISMOR_HOME/pricing.json

    ``fetch=False`` reads the cache but never hits the network: for hook paths,
    where a tool call must not wait on a price refresh."""
    table = dict(PRICES)
    try:
        from prismor.runtime.store import prismor_home
        home = prismor_home()
    except Exception:
        return table
    cache = home / "pricing-cache.json"
    if fetch:
        table.update(_fetch_litellm(cache))
    else:
        try:
            table.update(json.loads(cache.read_text(encoding="utf-8")))
        except Exception:
            pass
    try:
        override = json.loads((home / "pricing.json").read_text(encoding="utf-8"))
        table.update({normalize_model(str(k)): v for k, v in override.items() if isinstance(v, dict)})
    except Exception:
        pass
    return table


def normalize_model(model: str) -> str:
    m = model.lower().split("/")[-1]            # anthropic/claude-x, gemini/gemini-x
    m = re.sub(r"\[.*?\]$", "", m)              # claude-opus-5[1m]
    m = re.sub(r"-\d{8}$", "", m)               # -20250514
    return m


def price_for(model: str, fetch: bool = True) -> Optional[Dict[str, float]]:
    table = _table(fetch)
    m = normalize_model(model or "")
    if m in table:
        return table[m]
    best = max((k for k in table if m.startswith(k)), key=len, default=None)
    return table[best] if best else None


def cost_usd(tokens: Dict[str, Any], model: str, fetch: bool = True) -> Optional[float]:
    """tokens: input, output, cache_read, cache_5m, cache_1h (missing -> 0)."""
    rate = price_for(model, fetch)
    if rate is None:
        return None
    t = {k: int(tokens.get(k) or 0) for k in ("input", "output", "cache_read", "cache_5m", "cache_1h")}
    return (
        t["input"] * rate["input"]
        + t["output"] * rate["output"]
        + t["cache_read"] * rate["cache_read"]
        + t["cache_5m"] * rate["cache_write"]
        + t["cache_1h"] * rate.get("cache_1h", rate["input"] * CACHE_1H_INPUT_MULTIPLIER)
    ) / 1_000_000


def fmt_usd(value: Optional[float]) -> str:
    if value is None:
        return "—"
    if value < 0.01:
        return "<$0.01"
    return f"${value:,.2f}"
