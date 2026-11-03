#!/usr/bin/env python3
"""Latency of the optional PII detector versus the default hook path.

The default policy leaves ``settings.pii.enabled`` false. This script times
that path, the regex fallback, and (when the extra and the spaCy model are
installed) a cold and a warm Presidio call. It does not print the sample text.

    python3 scripts/bench_pii.py
"""
from __future__ import annotations

import statistics
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from prismor.runtime.pii import PiiSettings, detect, reset_for_tests  # noqa: E402
from prismor.runtime.policy_engine import PolicyEngine  # noqa: E402

# A short prompt of the size a hook actually sees. No real personal data.
SAMPLE = (
    "Summarise the ticket. The caller Ada Lovelace asked for a copy of "
    "the discharge note to be sent to ada.lovelace@nhs.net and confirmed "
    "the callback number 202-418-1000. Reference 578-12-4456."
)
EVENT = {"type": "prompt", "prompt": SAMPLE, "agent_event": "prompt"}


def _ms(fn, repeats: int) -> float:
    samples = []
    for _ in range(repeats):
        start = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - start) * 1000)
    return statistics.median(samples)


def main() -> int:
    engine = PolicyEngine()
    # One untimed call so YAML load and rule compile are not in the number.
    engine.evaluate(EVENT, 0)
    disabled = _ms(lambda: engine.evaluate(EVENT, 0), 30)

    overlay = """
version: "1.0"
rules: []
settings:
  pii:
    enabled: true
    backend: regex
    action: observe
"""
    tmp = tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False)
    tmp.write(overlay)
    tmp.close()
    regex_engine = PolicyEngine(policy_path=Path(tmp.name))
    regex_engine.evaluate(EVENT, 0)
    regex_eval = _ms(lambda: regex_engine.evaluate(EVENT, 0), 30)
    settings = regex_engine.pii
    detect(SAMPLE, settings)
    regex_only = _ms(lambda: detect(SAMPLE, settings), 50)

    print("PII detector latency (median)")
    print(f"  sample: {len(SAMPLE)} characters")
    print(f"  evaluate, pii disabled:     {disabled:8.2f} ms")
    print(f"  evaluate, regex backend:    {regex_eval:8.2f} ms")
    print(f"  detect() regex only:        {regex_only:8.2f} ms")

    try:
        import importlib.util
        import presidio_analyzer  # noqa: F401
        import presidio_anonymizer  # noqa: F401
        if importlib.util.find_spec("en_core_web_sm") is None:
            raise RuntimeError("spaCy model en_core_web_sm is not installed")
    except Exception as exc:
        print(f"  presidio: not measured ({exc.__class__.__name__}: {exc})")
        print("  install: pip install \"prismor[pii]\" && python -m spacy download en_core_web_sm")
        return 0

    reset_for_tests()
    presidio = PiiSettings.from_mapping({
        "enabled": True,
        "backend": "presidio",
        "action": "observe",
        "score_threshold": 0.4,
    })
    presidio_overlay = """
version: "1.0"
rules: []
settings:
  pii:
    enabled: true
    backend: presidio
    action: observe
    score_threshold: 0.4
"""
    tmp2 = tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False)
    tmp2.write(presidio_overlay)
    tmp2.close()
    # Cold number is the detector only: policy compile is paid on the disabled
    # path too and was warmed out of that row.
    start = time.perf_counter()
    cold = detect(SAMPLE, presidio)
    cold_ms = (time.perf_counter() - start) * 1000
    presidio_engine = PolicyEngine(policy_path=Path(tmp2.name))
    presidio_engine.evaluate(EVENT, 0)
    warm_eval = _ms(lambda: presidio_engine.evaluate(EVENT, 0), 15)
    long_event = {
        "type": "prompt",
        "prompt": (SAMPLE + " Ordinary follow-up text.") * 40,
        "agent_event": "prompt",
    }
    long_event["prompt"] = long_event["prompt"][:4000]
    presidio_engine.evaluate(long_event, 0)
    warm_long = _ms(lambda: presidio_engine.evaluate(long_event, 0), 8)
    warm = _ms(lambda: detect(SAMPLE, presidio), 15)
    print(f"  presidio detect, cold:      {cold_ms:8.2f} ms  backend={cold.backend}")
    print(f"  presidio evaluate, warm:    {warm_eval:8.2f} ms  ({len(SAMPLE)} chars)")
    print(f"  presidio evaluate, warm:    {warm_long:8.2f} ms  (4000 chars)")
    print(f"  presidio warm detect():     {warm:8.2f} ms")
    if cold.fallback_reason:
        print(f"  fallback: {cold.fallback_reason}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
