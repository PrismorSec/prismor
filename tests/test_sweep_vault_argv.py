"""The sweep vault passphrase must not appear in openssl's argv (visible in ps)."""
import shutil
import subprocess

import pytest

from prismor.runtime import sweep

pytestmark = pytest.mark.skipif(shutil.which("openssl") is None, reason="needs openssl")


def test_passphrase_not_in_argv_and_roundtrips(monkeypatch):
    seen = []
    real = subprocess.run

    def spy(args, *a, **k):
        seen.append(list(args))
        return real(args, *a, **k)

    monkeypatch.setattr(sweep.subprocess, "run", spy)
    pw = "pw-not-in-argv-123"
    blob = sweep._vault_encrypt(b"hello", pw)
    assert sweep._vault_decrypt(blob, pw) == b"hello"
    with pytest.raises(RuntimeError):
        sweep._vault_decrypt(blob, "wrong-pass-456")
    assert seen and all(pw not in " ".join(a) for a in seen)
