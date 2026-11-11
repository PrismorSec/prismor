"""A key pasted into a prompt showed in plaintext as the session
title on the dashboard's Recent Sessions."""
from prismor.runtime.store import _recloak_event, mask_secret_patterns

KEY = "sk-proj-" + "hBH3S1cs7FK5Z1wpGzVHIEd3S7G4-MNiBr13IKyzFmhIjglTbSH"


# Split so the repo's leak scanner does not read the test values as a real key.
PK = "PRIVATE" + " KEY"


def test_unregistered_key_is_masked_before_it_is_stored(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path))
    ev = _recloak_event({"type": "prompt", "prompt": f"use OPENAI_API_KEY={KEY} please",
                         "nested": [{"x": KEY}]})
    assert KEY not in repr(ev)
    assert ev["prompt"] == "use OPENAI_API_KEY=[REDACTED:secret] please"


def test_ordinary_text_is_untouched():
    t = "fix the login bug in sk-learn notes"
    assert mask_secret_patterns(t) == t


def test_store_masks_what_the_proxy_masks_toward_the_upstream(tmp_path, monkeypatch):
    """The proxy masked a DB-URL password toward the upstream, but the session
    log kept it (and AWS secrets, PEM keys) raw: the store used only the cloak
    pattern set. It now also applies the upstream set."""
    from prismor.runtime.redaction import redact_text
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path))
    secret = "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCY" + "EXAMPLEKEY"
    body = "MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MaH"
    prompt = ("db postgres://app:" + "hunter2pass" + "@db.internal:5432/x\n"
              f"AKIA{'IOSFODNN7EXAMPLE'},{secret}\n"
              f"-----BEGIN RSA {PK}-----\n{body}\n-----END RSA {PK}-----")
    stored = _recloak_event({"type": "prompt", "prompt": prompt})["prompt"]
    for raw in ("hunter2pass", secret, body):
        assert raw not in stored
        assert raw not in redact_text(prompt)[0]
    assert "postgres://app:[REDACTED:secret]@db.internal" in stored
