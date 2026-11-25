"""Sweep vault: native AES (no openssl, no pass_fds), openssl-compatible, written
before any file is touched, BOM-aware."""
import os
import shutil
import subprocess

import pytest

from prismor.runtime import sweep


def test_roundtrip_and_wrong_pass_without_subprocess(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("vault crypto must not spawn a process")
    monkeypatch.setattr(sweep.subprocess, "run", boom)
    blob = sweep._vault_encrypt(b"hello", "pw-123")
    assert blob.startswith(b"Salted__")
    assert sweep._vault_decrypt(blob, "pw-123") == b"hello"
    with pytest.raises(RuntimeError):
        sweep._vault_decrypt(blob, "wrong-pass-456")


@pytest.mark.skipif(shutil.which("openssl") is None, reason="needs openssl")
def test_openssl_format_compatible(tmp_path):
    args = ["openssl", "enc", "-aes-256-cbc", "-pbkdf2"]
    env = {**os.environ, "PW": "compat-pw"}
    out = subprocess.run([*args, "-salt", "-pass", "env:PW"], input=b"legacy", capture_output=True, env=env)
    assert sweep._vault_decrypt(out.stdout, "compat-pw") == b"legacy"
    mine = sweep._vault_encrypt(b"new" * 100, "compat-pw")
    back = subprocess.run([*args, "-d", "-pass", "env:PW"], input=mine, capture_output=True, env=env)
    assert back.stdout == b"new" * 100


def _setup(tmp_path, monkeypatch):
    monkeypatch.setattr(sweep, "PRISMOR_HOME", tmp_path / "home")
    monkeypatch.setattr(sweep, "VAULT_PATH", tmp_path / "home" / "vault.enc")
    monkeypatch.setattr(sweep, "VAULT_SALT_PATH", tmp_path / "home" / "vault.salt")
    f = tmp_path / "leak.txt"
    f.write_bytes("key=AKI\x41IOSFODNN7EXAMPLE\r\n".encode("utf-16"))  # BOM'd UTF-16
    finding = {"File": str(f), "RuleID": "aws", "Secret": "AKI\x41IOSFODNN7EXAMPLE",
               "StartLine": 1, "StartColumn": 4, "EndColumn": 24}
    return f, finding


def test_redact_restore_utf16_roundtrip(tmp_path, monkeypatch):
    f, finding = _setup(tmp_path, monkeypatch)
    assert sweep.redact([finding], "pw-1234") == 1
    raw = f.read_bytes()
    assert raw[:2] == b"\xff\xfe" and "AKIA****".encode("utf-16-le") in raw
    assert sweep.restore("pw-1234", all_entries=True) == 1
    assert "AKI\x41IOSFODNN7EXAMPLE" in f.read_bytes().decode("utf-16")


def test_vault_failure_leaves_files_untouched(tmp_path, monkeypatch):
    f, finding = _setup(tmp_path, monkeypatch)
    before = f.read_bytes()
    monkeypatch.setattr(sweep, "_vault_encrypt", lambda *a: (_ for _ in ()).throw(OSError("pass_fds")))
    with pytest.raises(SystemExit):
        sweep.redact([finding], "pw-1234")
    assert f.read_bytes() == before
    assert not sweep.VAULT_PATH.exists()
