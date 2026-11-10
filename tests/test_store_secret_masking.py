"""A key pasted into a prompt showed in plaintext as the session
title on the dashboard's Recent Sessions."""
from prismor.runtime.store import _recloak_event, mask_secret_patterns

KEY = "sk-proj-" + "hBH3S1cs7FK5Z1wpGzVHIEd3S7G4-MNiBr13IKyzFmhIjglTbSH"


def test_unregistered_key_is_masked_before_it_is_stored(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path))
    ev = _recloak_event({"type": "prompt", "prompt": f"use OPENAI_API_KEY={KEY} please",
                         "nested": [{"x": KEY}]})
    assert KEY not in repr(ev)
    assert ev["prompt"] == "use OPENAI_API_KEY=[REDACTED:secret] please"


def test_ordinary_text_is_untouched():
    t = "fix the login bug in sk-learn notes"
    assert mask_secret_patterns(t) == t
