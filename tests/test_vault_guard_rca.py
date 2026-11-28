"""prismor-vault-access findings say where the match was and why (RCA).

A real block (session 842acc46, 2026-11-26) showed only the first 220
characters of a long command and called it a vault read, while the vault path
sat in Prismor's own cloak wrapper that had failed to unwrap.
"""
import os
import tempfile
from pathlib import Path

import pytest

from prismor.runtime.policy_engine import PolicyEngine

HOOKS = "/Users/me/.local/pipx/venvs/prismor/lib/python3.14/site-packages/prismor/runtime/cloaking/hooks"


@pytest.fixture
def engine(monkeypatch):
    vault = Path(tempfile.mkdtemp(prefix="prismor-vault-"))
    monkeypatch.setenv("PRISMOR_SECRETS_DIR", str(vault))
    return PolicyEngine(), str(vault)


def _vault_hit(engine, cmd):
    findings = engine.evaluate({"type": "shell", "command": cmd}, 0)
    return next(f for f in findings if f["ruleId"] == "prismor-vault-access")


def test_evidence_is_centred_on_the_match(engine):
    eng, _ = engine
    cmd = "echo " + "x" * 600 + " && cat ~/.prismor/secrets/K && echo " + "y" * 600
    hit = _vault_hit(eng, cmd)
    assert ".prismor/secrets" in hit["evidence"]
    assert hit["evidence"].startswith("...") and hit["evidence"].endswith("...")
    assert hit["title"] == "Access to Prismor plaintext secret vault"


def test_failed_unwrap_is_named_but_still_blocked(engine):
    eng, vault = engine
    # Shaped like decloak.sh's eval wrapper, with the mangled byte that made
    # unwrap_decloak give up (U+FFFD inside $'...' is not a valid %q word).
    cmd = ("{ __prismor_cmd=$'echo \\'a �\\200\\224 b\\' >> m.md'; eval \"$__prismor_cmd\"$'\\n'; }"
           f" 2>&1 | PRISMOR_SECRETS_DIR={vault} PRISMOR_CLOAK_SESSION=s1 {HOOKS}/scrub-stream.sh; exit ${{PIPESTATUS[0]}}")
    hit = _vault_hit(eng, cmd)
    assert hit["action"] == "block"
    assert hit["title"] == "Prismor could not unwrap its own cloak wrapper"
    assert "cloak" in hit["guidance"]
    assert hit["evidence"].startswith("{ __prismor_cmd=")


def test_real_vault_read_inside_a_broken_wrapper_is_not_relabelled(engine):
    eng, vault = engine
    cmd = ("{ __prismor_cmd=$'cat ~/.prismor/secrets/K �'; eval \"$__prismor_cmd\"$'\\n'; }"
           f" 2>&1 | PRISMOR_SECRETS_DIR={vault} PRISMOR_CLOAK_SESSION=s1 {HOOKS}/scrub-stream.sh; exit ${{PIPESTATUS[0]}}")
    hit = _vault_hit(eng, cmd)
    assert hit["title"] == "Access to Prismor plaintext secret vault"
    assert "guidance" not in hit
