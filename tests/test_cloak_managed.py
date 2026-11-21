"""Org vault sync: the device half of the console's sealed push."""
import base64
import json
import os
import time

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from prismor.runtime.cloaking import managed
from prismor.runtime.cloaking.secrets_store import add_secret, secrets_dir
from prismor.runtime.cloaking.sources import load_sources

RAW = (serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def seal(value, dev_pub_b64, aad):
    """The console's seal (lib/managed-secrets.ts), in Python."""
    dev = base64.b64decode(dev_pub_b64)
    eph = X25519PrivateKey.generate()
    epk = eph.public_key().public_bytes(*RAW)
    shared = eph.exchange(X25519PublicKey.from_public_bytes(dev))
    key = HKDF(hashes.SHA256(), 32, epk + dev, b"prismor-managed-secret-v1").derive(shared)
    nonce = os.urandom(12)
    b64 = lambda b: base64.b64encode(b).decode()
    return {"epk": b64(epk), "nonce": b64(nonce), "ct": b64(AESGCM(key).encrypt(nonce, value.encode(), aad.encode()))}


class Console:
    def __init__(self):
        self.pub = None
        self.secrets = {}  # name -> (version, value)
        self.reports = []
        self.issued = time.time()
        self.device_id = "dev1"
        self.status = 200

    def __call__(self, ident, method, path, body=None, timeout=8):
        if path == "/api/devices/seal-key":
            self.pub = body["public_key"]
            return 200, {"ok": True}
        if method == "POST":
            self.reports.append(body["results"])
            return 200, {}
        if self.status != 200:
            return self.status, {}
        if not self.pub:
            return 409, {"error": "no_seal_key"}
        boxes = [{"name": n, "version": v, **seal(val, self.pub, f"{self.device_id}|{n}|{v}")}
                 for n, (v, val) in self.secrets.items()]
        payload = json.dumps({"device_id": self.device_id, "org_id": "org1", "issued_at": self.issued,
                              "sig": f"s{len(self.secrets)}{sum(v for v, _ in self.secrets.values())}",
                              "secrets": boxes})
        return 200, {"payload": payload, "signature": "good"}


@pytest.fixture
def console(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path))
    from prismor.runtime.enterprise import identity, remote_policy
    monkeypatch.setattr(identity, "load_identity", lambda: {"device_id": "dev1", "org_id": "org1", "device_key": "k"})
    monkeypatch.setattr(remote_policy, "_verify_signature", lambda payload, sig: sig == "good")
    c = Console()
    monkeypatch.setattr(managed, "_request", c)
    return c


def read(name):
    return (secrets_dir() / name).read_text()


def test_registers_key_then_stores_rotates_and_removes(console):
    console.secrets = {"STRIPE": (1, "v-one")}
    assert managed.sync() == [{"name": "STRIPE", "version": 1, "status": "stored"}]
    assert console.pub and read("STRIPE") == "v-one"
    assert load_sources()["STRIPE"] == {"ref": "prismor://STRIPE", "version": "1"}
    assert oct(managed.key_path().stat().st_mode & 0o777) == "0o600"
    assert console.reports[-1] == [{"name": "STRIPE", "version": 1, "status": "stored"}]

    assert managed.sync()[0]["status"] == "unchanged"
    console.secrets = {"STRIPE": (2, "v-two")}
    assert managed.sync()[0]["status"] == "stored" and read("STRIPE") == "v-two"

    console.secrets = {}
    assert managed.sync() == [{"name": "STRIPE", "status": "removed"}]
    assert not (secrets_dir() / "STRIPE").exists() and "STRIPE" not in load_sources()


def test_local_secret_wins_and_is_reported(console):
    add_secret("MINE", "local")
    console.secrets = {"MINE": (1, "org")}
    assert managed.sync()[0]["status"] == "conflict"
    assert read("MINE") == "local"
    assert console.reports[-1][0]["status"] == "conflict"
    console.secrets = {}
    managed.sync()
    assert read("MINE") == "local"  # never managed, never removed


def test_bad_signature_wrong_device_and_replay_change_nothing(console, monkeypatch):
    console.secrets = {"A": (1, "x")}
    managed.sync()
    console.secrets = {"A": (2, "y")}

    from prismor.runtime.enterprise import remote_policy
    monkeypatch.setattr(remote_policy, "_verify_signature", lambda p, s: False)
    with pytest.raises(managed.ManagedError, match="signature"):
        managed.sync()
    monkeypatch.setattr(remote_policy, "_verify_signature", lambda p, s: True)

    console.device_id = "dev2"
    with pytest.raises(managed.ManagedError, match="another device_id"):
        managed.sync()
    console.device_id = "dev1"

    console.issued -= 3600
    with pytest.raises(managed.ManagedError, match="older"):
        managed.sync()
    assert read("A") == "x"


def test_maybe_sync_skips_same_sig_and_backs_off(console, capsys):
    console.secrets = {"A": (1, "x")}
    managed.maybe_sync("anything")
    assert read("A") == "x"
    sig = managed.last_sig()
    calls = []
    orig = managed.sync
    managed.sync = lambda **kw: calls.append(1)
    try:
        managed.maybe_sync(sig)
        assert calls == []
    finally:
        managed.sync = orig

    console.status = 500
    managed.maybe_sync("new")
    assert "not synced" in capsys.readouterr().err
    console.status = 200
    console.secrets = {"A": (2, "y")}
    managed.maybe_sync("new")  # inside the retry window
    assert read("A") == "x"


def test_not_enrolled(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path))
    from prismor.runtime.enterprise import identity
    monkeypatch.setattr(identity, "load_identity", lambda: None)
    with pytest.raises(managed.ManagedError, match="not enrolled"):
        managed.sync()
    managed.maybe_sync("x")  # never raises


def test_sources_reject_and_skip_managed_refs(console):
    from prismor.runtime.cloaking import sources
    with pytest.raises(sources.SourceError, match="org console"):
        sources.add_from_ref("X", "prismor://X")
    console.secrets = {"A": (1, "x")}
    managed.sync()
    assert sources.sync() == []
