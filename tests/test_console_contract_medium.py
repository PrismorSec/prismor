"""Medium-severity OSS/console contract fixes from the 2026-11-15 audit."""
import hashlib
import io
import json
import urllib.error

import pytest

from prismor.runtime import semantic_guard, semantic_guard_v2 as sg2
from prismor.runtime import sinks
from prismor.runtime.enterprise import remote_policy, telemetry_spool


def _web_sig(obj):
    # lib canonicalJson: sorted keys, no spaces, non-ASCII kept as-is.
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False).encode("utf-8")).hexdigest()[:16]


def test_pause_sig_matches_console_for_non_ascii_reason(monkeypatch):
    pause = {"state": "paused", "reason": "deploy — wait", "by": "a"}
    monkeypatch.setattr(remote_policy, "verify_and_load", lambda: {"settings": {"device_pause": pause}})
    assert remote_policy._current_pause_sig() == _web_sig(pause) == "919824947c2912f6"


@pytest.mark.parametrize("code", [402, 413, 429, 503])
def test_telemetry_rejections_back_off(code, tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / ".prismor"))
    (tmp_path / ".prismor").mkdir()
    monkeypatch.delenv("PRISMOR_AGENT_KEY", raising=False)
    from prismor.runtime.enterprise import identity
    monkeypatch.setattr(identity, "load_identity", lambda: {"device_key": "k", "api_base": "https://cp.invalid"})
    monkeypatch.setattr(identity, "revoked_backoff_active", lambda: False)
    monkeypatch.setattr(sinks, "_bg_thread", None, raising=False)

    def refuse(*a, **k):
        raise urllib.error.HTTPError("u", code, "x", {}, io.BytesIO(b""))
    monkeypatch.setattr("urllib.request.urlopen", refuse)
    with pytest.raises(urllib.error.HTTPError):
        sinks.upload_telemetry([{"ts": "t", "verdict": "allowed"}])
    assert telemetry_spool.backoff_active(__import__("time").time())


def test_judge_instructions_reach_the_api_judge(monkeypatch):
    seen = {}

    def fake_api(text, model="", system="", user=""):
        seen["system"] = system
        return sg2.SemanticRisk(0.1, "clean", "ok", "allow", mode="api")
    monkeypatch.setattr(semantic_guard, "_api_analyze", fake_api)
    monkeypatch.setattr(sg2, "_cache_load", lambda: {})
    monkeypatch.setattr(sg2, "_cache_store", lambda *a, **k: None)
    guard = sg2.from_config({"mode": "hybrid", "provider": "api", "model": "m", "low_threshold": 0,
                             "judge_instructions": "Edits under docs/ are routine here."})
    guard._api_available = True
    guard.analyze("please update the README in docs/")
    assert "Edits under docs/ are routine here." in seen["system"]
    assert sg2._ORG_GUIDANCE.get() == ""  # not leaked past the call
