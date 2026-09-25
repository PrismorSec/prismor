"""Tests for signed remote (org-managed) policy distribution.

Invariants:
  * A correctly-signed remote policy is applied (can add rules / settings).
  * A signed remote policy still CANNOT disable a non-overridable core rule.
  * A tampered / unsigned remote policy is ignored entirely (fail-closed).
"""
from __future__ import annotations

import base64
import json
import subprocess
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
PRIVATE_KEY = REPO_ROOT / "keys" / "private.pem"

pytestmark = pytest.mark.skipif(
    not PRIVATE_KEY.exists(),
    reason="signing key not available in this checkout",
)


def _sign(payload: bytes) -> str:
    """Detached Ed25519 signature over payload, base64-encoded (matches the
    format remote_policy expects in the .sig file).

    Ed25519 is a oneshot algorithm — openssl needs the message as a file (it
    must know the length up front), so we write a temp file rather than piping
    via stdin.
    """
    import tempfile
    with tempfile.NamedTemporaryFile() as pf:
        pf.write(payload)
        pf.flush()
        raw = subprocess.run(
            ["openssl", "pkeyutl", "-sign", "-inkey", str(PRIVATE_KEY),
             "-rawin", "-in", pf.name],
            capture_output=True, check=True,
        ).stdout
    return base64.b64encode(raw).decode("ascii")


def _write_remote(home: Path, yaml_text: str, sign_with: bytes | None = None):
    home.mkdir(parents=True, exist_ok=True)
    (home / "remote-policy.yaml").write_text(yaml_text, encoding="utf-8")
    payload = sign_with if sign_with is not None else yaml_text.encode("utf-8")
    (home / "remote-policy.yaml.sig").write_text(_sign(payload), encoding="utf-8")
    (home / "remote-policy.meta.json").write_text(
        json.dumps({"fetched_at": time.time(), "version": 7, "scope": "org"}),
        encoding="utf-8",
    )


REMOTE_POLICY = """
settings:
  block_categories: [prompt_injection, malicious_mcp]
  full_capture: true
rules:
  - id: destructive-command
    enabled: false          # <-- attempt to DISABLE a core rule (must be refused)
  - id: org-custom-block-curl-pipe-sh
    enabled: true
    severity: HIGH
    category: tool_call_abuse
    title: Org rule — curl piped to shell
    event_types: [shell]
    fields: [command]
    action: block
    patterns:
      - 'curl[^\\\\n]*\\\\|[^\\\\n]*sh'
"""


def _enroll():
    # Remote (org) policy only applies to org-managed workspaces, which requires
    # an enrolled device. With no managed_repo_patterns set, every workspace is
    # managed (default), so enrolling is enough to exercise remote-policy merge.
    from prismor.runtime.enterprise import identity
    identity.save_identity({"device_id": "d", "org_id": "o", "user_id": "u",
                            "device_key": "prism_dev_x", "api_base": "http://x"})


def test_signed_remote_policy_applies_but_cannot_weaken(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / ".prismor"))
    _write_remote(tmp_path / ".prismor", REMOTE_POLICY)
    _enroll()

    from prismor.runtime.policy_engine import PolicyEngine
    engine = PolicyEngine(workspace=tmp_path)

    rule_ids = {r.id for r in engine.rules}
    # The org's new rule was added.
    assert "org-custom-block-curl-pipe-sh" in rule_ids
    # The org's settings were applied (admin is authoritative for settings).
    assert "prompt_injection" in engine.block_categories
    assert "malicious_mcp" in engine.block_categories
    # full_capture surfaced for the sink to read.
    # (stored in compiled settings only if the engine tracks it; block_categories
    #  proves the settings merge ran.)
    # The non-overridable core rule is STILL enabled despite the disable attempt.
    assert "destructive-command" in rule_ids, "core rule must not be disable-able by remote policy"
    # Remote metadata is exposed.
    assert engine.remote_policy_meta.get("version") == 7


def test_tampered_remote_policy_is_ignored(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / ".prismor"))
    # Sign a DIFFERENT payload than what's on disk => signature won't match.
    _write_remote(tmp_path / ".prismor", REMOTE_POLICY, sign_with=b"a different document")
    _enroll()

    from prismor.runtime.policy_engine import PolicyEngine
    engine = PolicyEngine(workspace=tmp_path)
    rule_ids = {r.id for r in engine.rules}
    # The org rule must NOT have been applied — policy was rejected.
    assert "org-custom-block-curl-pipe-sh" not in rule_ids
    assert engine.remote_policy_meta == {}


def test_no_remote_policy_is_inert(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / ".prismor"))
    from prismor.runtime.policy_engine import PolicyEngine
    engine = PolicyEngine(workspace=tmp_path)
    # Default policy still loads; core rule present; no remote meta.
    assert any(r.id == "destructive-command" for r in engine.rules)
    assert engine.remote_policy_meta == {}
    # No remote controls without a policy.
    assert engine.agent_controls == {}


def test_revoked_device_ignores_cached_remote_policy(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / ".prismor"))
    _write_remote(tmp_path / ".prismor", REMOTE_POLICY)
    _enroll()
    from prismor.runtime.enterprise import identity, remote_policy
    identity.mark_revoked("policy fetch rejected (401)")
    assert remote_policy.verify_and_load() is None


AGENT_CONTROL_POLICY = """
settings:
  agent_controls:
    checkout-bot:
      enabled: false
    support-bot:
      enabled: true
      mode: enforce
rules: []
"""


def test_signed_agent_controls_reach_engine(tmp_path, monkeypatch):
    """settings.agent_controls in the verified signed policy is lifted onto the
    engine so the runtime can merge it with the local registry."""
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / ".prismor"))
    _write_remote(tmp_path / ".prismor", AGENT_CONTROL_POLICY)
    _enroll()

    from prismor.runtime.policy_engine import PolicyEngine
    engine = PolicyEngine(workspace=tmp_path)
    assert engine.agent_controls.get("checkout-bot", {}).get("enabled") is False
    assert engine.agent_controls.get("support-bot", {}).get("mode") == "enforce"


def test_agent_controls_sig_matches_server_format(tmp_path, monkeypatch):
    """_current_agent_controls_sig reproduces the server's agentControlsSig
    (sorted key:enabled:mode:iam → sha256 → 16 hex) so a control change triggers
    a re-pull; empty when there are no controls."""
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / ".prismor"))
    from prismor.runtime.enterprise import remote_policy

    _write_remote(tmp_path / ".prismor", AGENT_CONTROL_POLICY)
    _enroll()
    sig = remote_policy._current_agent_controls_sig()
    assert sig and len(sig) == 16

    # Reproduce the server side independently and compare.
    import hashlib
    lines = sorted([
        "checkout-bot:0::",
        "support-bot:1:enforce:",
    ])
    expected = hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()[:16]
    assert sig == expected

    # No controls → empty signature.
    _write_remote(tmp_path / ".prismor", "settings: {}\nrules: []\n")
    assert remote_policy._current_agent_controls_sig() == ""


TOOL_TAGS_POLICY = """
version: "1.0"
rules: []
settings:
  tool_tags:
    enabled: true
    mode: enforce
    tags:
      WebFetch: [untrusted_content]
    rules:
      - expr: untrusted_content then critical_action
        action: block
    agents:
      scraper:
        mode: enforce
        tags:
          Bash: [critical_action]
"""


def test_tool_tags_sig_matches_server_format(tmp_path, monkeypatch):
    """_current_tool_tags_sig reproduces the server's toolTagsSig (canonical
    JSON of settings.tool_tags -> sha256 -> 16 hex).

    This comparison did not exist: the server sent toolTagsSig from the start,
    nothing on the device read it, and the server hashed the DB ROWS - which the
    device never sees and so could never reproduce. Both sides now hash the
    resolved block, the way egressSig already did.
    """
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / ".prismor"))
    from prismor.runtime.enterprise import remote_policy

    _write_remote(tmp_path / ".prismor", TOOL_TAGS_POLICY)
    _enroll()
    sig = remote_policy._current_tool_tags_sig()
    assert sig and len(sig) == 16

    import hashlib
    import json as _json
    block = {
        "enabled": True,
        "mode": "enforce",
        "tags": {"WebFetch": ["untrusted_content"]},
        "rules": [{"expr": "untrusted_content then critical_action", "action": "block"}],
        "agents": {"scraper": {"mode": "enforce", "tags": {"Bash": ["critical_action"]}}},
    }
    blob = _json.dumps(block, sort_keys=True, separators=(",", ":"))
    assert sig == hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]

    # No tool-tag config -> empty signature, so an org that never enabled the
    # feature does not re-pull on every heartbeat.
    _write_remote(tmp_path / ".prismor", "version: \"1.0\"\nsettings: {}\nrules: []\n")
    assert remote_policy._current_tool_tags_sig() == ""


def test_tool_tags_sig_changes_when_an_agent_overlay_changes(tmp_path, monkeypatch):
    """Attaching a policy to an agent alters the bundle without bumping the
    profile version, so the signature has to move or the device never re-pulls."""
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / ".prismor"))
    from prismor.runtime.enterprise import remote_policy

    _write_remote(tmp_path / ".prismor", TOOL_TAGS_POLICY)
    _enroll()
    before = remote_policy._current_tool_tags_sig()

    _write_remote(tmp_path / ".prismor", TOOL_TAGS_POLICY.replace(
        "          Bash: [critical_action]",
        "          Bash: [critical_action, private_data]",
    ))
    assert remote_policy._current_tool_tags_sig() != before
 

def test_verify_and_load_memoization_avoids_repeated_verification(tmp_path, monkeypatch):
    """Calling verify_and_load multiple times on unchanged files must reuse the in-process
    memo, bypassing repeated signature checks and YAML parsing (#478)."""
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / ".prismor"))
    _write_remote(tmp_path / ".prismor", REMOTE_POLICY)
    _enroll()

    from unittest.mock import patch
    from prismor.runtime.enterprise import remote_policy

    remote_policy.clear_policy_cache()

    with patch.object(remote_policy, "_verify_signature", wraps=remote_policy._verify_signature) as mock_sig:
        
        p1 = remote_policy.verify_and_load()
        assert p1 is not None
        assert mock_sig.call_count == 1

        p2 = remote_policy.verify_and_load()
        p3 = remote_policy.verify_and_load()
        assert p2 == p1
        assert p3 == p1
        assert mock_sig.call_count == 1

        p1["mutated_field"] = True
        p4 = remote_policy.verify_and_load()
        assert "mutated_field" not in p4
        assert mock_sig.call_count == 1
     
        _write_remote(tmp_path / ".prismor", AGENT_CONTROL_POLICY)
        p5 = remote_policy.verify_and_load()
        assert p5 is not None
        assert mock_sig.call_count == 2
       
        remote_policy.clear_policy_cache()
        p6 = remote_policy.verify_and_load()
        assert p6 is not None
        assert mock_sig.call_count == 3
     
