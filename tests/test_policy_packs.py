"""Policy packs: fetch pinned to a SHA, hash-locked, optionally signed, and
loaded as an add/tighten-only layer. Fully offline: the HTTP seam is mocked."""
import base64
import io
import json
import tarfile
from pathlib import Path

import pytest
import yaml

from prismor.runtime import policy_packs as pp
from prismor.runtime.cli import _policy_pack
from prismor.runtime.hooks import should_block
from prismor.runtime.policy_engine import PolicyEngine

FIXTURE = Path(__file__).parent / "fixtures" / "policy-pack"
SHA1 = "a" * 40
SHA2 = "b" * 40
PRE = {"agent_event": "PreToolUse", "type": "shell"}


def _tarball(files, prefix="repo-sha/packs/acme/"):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in files.items():
            info = tarfile.TarInfo(prefix + name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        link = tarfile.TarInfo(prefix + "evil.yaml")
        link.type, link.linkname = tarfile.SYMTYPE, "/etc/passwd"
        tf.addfile(link)
    return buf.getvalue()


def _fixture_files():
    return {p.name: p.read_bytes() for p in FIXTURE.iterdir()}


@pytest.fixture
def net(monkeypatch, tmp_path):
    """Fake GitHub: refs resolve via `state['sha']`, tarballs via `state['files']`."""
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / "home"))
    state = {"sha": SHA1, "files": _fixture_files(), "calls": []}

    def fake_get(url, accept="*/*"):
        state["calls"].append(url)
        assert url.startswith("https://")
        if url.startswith("https://api.github.com/"):
            return state["sha"].encode()
        assert url == f"https://codeload.github.com/acme/policies/tar.gz/{state['sha']}"
        return _tarball(state["files"])

    monkeypatch.setattr(pp, "_http_get", fake_get)
    return state


def _add(**kw):
    return pp.commit(pp.prepare("acme/policies@v1", subdir="packs/acme", **kw))


def _engine(tmp_path):
    return PolicyEngine(workspace=tmp_path)


def _blocks(engine, command):
    return should_block(engine.evaluate({"type": "shell", "command": command}, index=0), PRE)


def test_add_pins_sha_and_locks_hashes(net, tmp_path):
    entry = _add()
    assert entry["sha"] == SHA1 and entry["repo"] == "acme/policies" and entry["ref"] == "v1"
    assert set(entry["files"]) == {"prismor-pack.yaml", "rules.yaml"}  # symlink dropped
    lock = json.loads((pp.packs_dir() / pp.LOCK).read_text(encoding="utf-8"))
    assert lock["packs"]["acme-baseline"]["files"]["rules.yaml"] == pp._sha256(
        (FIXTURE / "rules.yaml").read_bytes())
    assert lock["packs"]["acme-baseline"]["fetched_at"]
    assert "https://api.github.com/repos/acme/policies/commits/v1" in net["calls"]


def test_pack_rules_load_and_tighten(net, tmp_path):
    before = _engine(tmp_path)
    assert not _blocks(before, "pg_dump -h prod.db mydb")
    _add()
    eng = _engine(tmp_path)
    assert eng.packs_loaded == ["acme-baseline"] and not eng.pack_errors
    hit = _blocks(eng, "pg_dump -h prod.db mydb")
    assert hit and hit["ruleId"] == "acme-no-prod-db-dump"
    sudo = next(r for r in eng.rules if r.id == "sudo-command")
    assert sudo.mode == "enforce" and sudo.severity == "HIGH"
    assert eng.decision_layer(sudo) == "pack"
    assert _blocks(eng, "doas rm file")  # the added pattern


def test_tampered_pack_is_not_loaded(net, tmp_path, capsys):
    _add()
    path = pp.packs_dir() / "acme-baseline" / "rules.yaml"
    path.write_text(path.read_text(encoding="utf-8") + "\n# edited\n", encoding="utf-8")
    eng = _engine(tmp_path)
    assert eng.packs_loaded == []
    assert eng.pack_errors and "failed verification" in eng.pack_errors[0]
    assert not any(r.id == "acme-no-prod-db-dump" for r in eng.rules)
    _policy_pack(type("A", (), {"pack_command": "list"})())
    assert "TAMPERED" in capsys.readouterr().out


@pytest.mark.parametrize("rule, why", [
    ({"id": "sudo-command", "enabled": False}, "collides with a built-in"),
    ({"id": "sudo-command", "mode": "observe"}, "only raise mode"),
    ({"id": "sudo-command", "severity": "LOW"}, "only raise severity"),
    ({"id": "sudo-command", "severity": "HIGH", "category": "x", "title": "t",
      "event_types": ["shell"], "patterns": ["x"], "action": "block"}, "collides with a built-in"),
    ({"id": "destructive-command", "add_patterns": ["x"]}, "floor/self-protection"),
    ({"id": "prismor-self-edit", "mode": "enforce"}, "floor/self-protection"),
])
def test_loosening_or_colliding_rules_are_rejected(net, rule, why):
    net["files"]["rules.yaml"] = yaml.safe_dump({"version": "1.0", "rules": [rule]}).encode()
    with pytest.raises(pp.PackError, match=why):
        _add()
    assert not (pp.packs_dir() / pp.LOCK).exists()


def test_settings_and_allowlists_are_rejected(net):
    net["files"]["rules.yaml"] = yaml.safe_dump({
        "version": "1.0", "rules": [], "settings": {"default_mode": "observe"},
        "allowlists": [{"id": "a", "rule_ids": ["*"], "patterns": [".*"]}]}).encode()
    with pytest.raises(pp.PackError, match="'settings:' is not allowed"):
        _add()


def test_engine_drops_bad_entry_even_if_store_is_edited_with_lock(net, tmp_path):
    # Someone rewrites the file AND the lock: the engine still refuses loosening.
    _add()
    path = pp.packs_dir() / "acme-baseline" / "rules.yaml"
    path.write_text(yaml.safe_dump({"version": "1.0", "rules": [
        {"id": "destructive-command", "enabled": False}]}), encoding="utf-8")
    lock = pp.read_lock()
    lock["packs"]["acme-baseline"]["files"]["rules.yaml"] = pp._sha256(path.read_bytes())
    pp._write_lock(lock)
    eng = _engine(tmp_path)
    assert any("floor/self-protection" in e for e in eng.pack_errors)
    assert _blocks(eng, "rm -rf /")


def _keypair():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = Ed25519PrivateKey.generate()
    pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    return key, pem


def _sign(files, key):
    sums = "".join(f"{pp._sha256(d)}  {n}\n" for n, d in sorted(files.items()))
    files[pp.SUMS] = sums.encode()
    files[pp.SIG] = base64.b64encode(key.sign(files[pp.SUMS]))


def test_signed_pack_verifies_with_pinned_key(net, tmp_path):
    key, pem = _keypair()
    _sign(net["files"], key)
    (tmp_path / "pub.pem").write_bytes(pem)
    entry = _add(key_path=str(tmp_path / "pub.pem"), require_signature=True)
    assert entry["signed"] and entry["key_pem"] == pem.decode()
    # Wrong key: refused.
    _, other = _keypair()
    (tmp_path / "other.pem").write_bytes(other)
    with pytest.raises(pp.PackError, match="signature check failed"):
        _add(key_path=str(tmp_path / "other.pem"))
    # A file the signature does not cover: refused.
    net["files"]["extra.yaml"] = b'version: "1.0"\nrules: []\n'
    with pytest.raises(pp.PackError, match="not covered"):
        _add(key_path=str(tmp_path / "pub.pem"))


def test_require_signature_refuses_unsigned(net, tmp_path):
    with pytest.raises(pp.PackError, match="require-signature"):
        _add(require_signature=True)
    _, pem = _keypair()
    (tmp_path / "pub.pem").write_bytes(pem)
    with pytest.raises(pp.PackError, match="unsigned"):
        _add(key_path=str(tmp_path / "pub.pem"))


def test_update_shows_rule_diff_and_remove(net, tmp_path, capsys):
    _add()
    net["sha"] = SHA2
    net["files"]["rules.yaml"] = yaml.safe_dump({"version": "1.0", "rules": [{
        "id": "acme-no-curl-pipe", "severity": "HIGH", "category": "remote_code",
        "title": "t", "event_types": ["shell"], "patterns": ["curl.*\\|\\s*sh"],
        "action": "block"}]}).encode()
    args = type("A", (), {"pack_command": "update", "name": "acme-baseline", "yes": True})()
    assert _policy_pack(args) == 0
    out = capsys.readouterr().out
    assert "+ acme-no-curl-pipe" in out and "- acme-no-prod-db-dump" in out and "- sudo-command" in out
    assert pp.read_lock()["packs"]["acme-baseline"]["sha"] == SHA2
    assert _policy_pack(type("A", (), {"pack_command": "remove", "name": "acme-baseline"})()) == 0
    assert _engine(tmp_path).packs_loaded == []


def test_spec_and_path_validation():
    with pytest.raises(pp.PackError):
        pp.parse_spec("not a spec")
    assert pp.parse_spec("o/r@v1.2") == ("o", "r", "v1.2")
    with pytest.raises(pp.PackError):
        pp._extract(_tarball({}), "../x")
    with pytest.raises(pp.PackError, match="non-HTTPS"):
        pp._http_get("http://example.invalid/x")


def test_agent_cannot_manage_packs_without_unlock(tmp_path):
    eng = _engine(tmp_path)
    for command in ("prismor policy pack add acme/policies@v1",
                    "prismor policy pack update --yes",
                    "prismor policy pack remove acme-baseline",
                    "rm -rf ~/.prismor/packs/acme-baseline",
                    "echo x > ~/.prismor/packs/packs.lock.json"):
        hit = _blocks(eng, command)
        assert hit and hit["ruleId"] in ("prismor-self-edit", "agent-config-tampering"), command
    for command in ("prismor policy pack list", "prismor policy pack show acme-baseline",
                    "cat ~/.prismor/packs/packs.lock.json"):
        assert not _blocks(eng, command), command
    findings = eng.evaluate({"type": "file_write", "path": "/home/u/.prismor/packs/x/rules.yaml"}, index=0)
    assert should_block(findings, {"agent_event": "PreToolUse", "type": "file_write"})
