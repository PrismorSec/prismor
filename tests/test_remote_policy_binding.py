"""Signed remote policy: freshness and device binding inside the signed bytes.

A signature alone lets any older org-signed policy (e.g. one that paused
enforcement) be written back over the cache and accepted.
"""
import base64
import re
import time

import pytest

ed = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ed25519")
from cryptography.hazmat.primitives import serialization  # noqa: E402

from prismor.runtime.enterprise import identity as ident  # noqa: E402
from prismor.runtime.enterprise import remote_policy as rp  # noqa: E402


@pytest.fixture
def signer(tmp_path, monkeypatch):
    priv = ed.Ed25519PrivateKey.generate()
    pub = tmp_path / "pub.pem"
    pub.write_bytes(priv.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    monkeypatch.setattr(rp, "_public_key_path", lambda: pub)
    monkeypatch.setattr(rp, "_policy_home", lambda: tmp_path)
    monkeypatch.setattr(ident, "revoked_info", lambda: None)
    monkeypatch.setattr(ident, "load_identity", lambda: {"device_id": "dev-1", "org_id": "org-1"})

    def cache(yaml_text):
        (tmp_path / "remote-policy.yaml").write_text(yaml_text)
        (tmp_path / "remote-policy.yaml.sig").write_text(
            base64.b64encode(priv.sign(yaml_text.encode())).decode())
        rp.clear_policy_cache()
        return rp.verify_and_load()

    yield cache
    rp.clear_policy_cache()


def _doc(issued, *, device="dev-1", org="org-1", expires=None, state="resumed"):
    exp = f"\n  expires_at: {expires}" if expires is not None else ""
    return (f"version: '1.0'\n_signed:\n  device_id: {device}\n  org_id: {org}\n"
            f"  issued_at: {issued}{exp}\nsettings:\n  device_pause:\n    state: {state}\n")


def test_older_signed_policy_is_rejected(signer):
    now = int(time.time())
    assert signer(_doc(now)) is not None
    assert signer(_doc(now - 3600, state="paused")) is None


def test_newer_policy_still_applies(signer):
    now = int(time.time())
    assert signer(_doc(now - 10)) is not None
    assert signer(_doc(now)) is not None


def test_policy_for_another_device_is_rejected(signer):
    assert signer(_doc(int(time.time()), device="dev-2")) is None
    assert signer(_doc(int(time.time()), org="org-2")) is None


def test_expired_policy_is_rejected(signer):
    now = int(time.time())
    assert signer(_doc(now, expires=now - 1)) is None
    assert signer(_doc(now + 1, expires=now + 600)) is not None


def test_legacy_policy_without_signed_block_still_loads(signer):
    assert signer("version: '1.0'\nrules: []\n") is not None


def test_cache_files_are_self_protected():
    from pathlib import Path
    text = (Path(rp.__file__).parent.parent / "default_policy.yaml").read_text()
    pats = re.findall(r"- '(\(\^\|/\)\\\.prismor/remote-policy[^']*)'", text)
    assert pats, "remote-policy path rule missing"
    rx = re.compile(pats[0])
    for name in ("remote-policy.yaml", "remote-policy.yaml.sig",
                 "remote-policy.meta.json", "remote-policy.hwm.json"):
        assert rx.search(f"/home/u/.prismor/{name}")
