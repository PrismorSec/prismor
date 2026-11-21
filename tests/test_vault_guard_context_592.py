"""#592: prismor-vault-access ignores fixtures under another user's home.

The shell form of the vault guard used to fire on any mention of the vault's
directory name, so test fixtures and docs spelling a fake home
(`/home/u/.prismor/secrets`) were blocked like a real read. A mention under a
DIFFERENT, nonexistent home is now exempt; every form that can reach this
user's vault still fires, and anything ambiguous fails closed.
"""
import os
from pathlib import Path

import pytest

from prismor.runtime.hooks import should_block
from prismor.runtime.policy_engine import PolicyEngine

RULE = "prismor-vault-access"


@pytest.fixture
def home(tmp_path, monkeypatch):
    """A real (existing) home for the current user with the default vault."""
    h = tmp_path / "me"
    (h / ".prismor" / "secrets").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(h))
    monkeypatch.delenv("PRISMOR_SECRETS_DIR", raising=False)
    monkeypatch.delenv("PRISMOR_HOME", raising=False)
    return h


def vault_findings(command):
    findings = PolicyEngine().evaluate({"type": "shell", "command": command}, 0)
    return [f for f in findings if f.get("ruleId") == RULE]


def blocks(command):
    hits = vault_findings(command)
    for f in hits:
        f["mode"] = "enforce"
    event = {"type": "shell", "command": command, "agent_event": "PreToolUse"}
    return bool(hits) and should_block(hits, event) is not None


@pytest.mark.parametrize("command", [
    "cat ~/.prismor/secrets/x",
    "ls $HOME/.prismor/secrets",
    "ls ${HOME}/.prismor/secrets",
    'cat "$HOME/.prismor/secrets/openai"',
    "cat .prismor/secrets/x",
    "cd ~ && cat ./.prismor/secrets/x",
    # The decloak script pointed at the real vault.
    "echo '{}' | PRISMOR_SECRETS_DIR=$HOME/.prismor/secrets "
    "bash prismor/runtime/cloaking/hooks/decloak.sh",
    'python3 - <<\'EOF\'\nprint(open(os.path.expanduser("~/.prismor/secrets/k")).read())\nEOF',
    # grep is a text sink for other rules, but here the quoted path is read.
    'grep -r . "$HOME/.prismor/secrets"',
])
def test_real_vault_forms_still_block(home, command):
    assert vault_findings(command), command
    assert blocks(command), command


def test_real_home_absolute_path_blocks(home):
    assert blocks(f"cat {home}/.prismor/secrets/x")


def test_traversal_into_real_home_blocks(home):
    # /home/u/../<me> normalises to the real home.
    sneaky = f"/home/u/../..{home}/.prismor/secrets/x"
    assert blocks(f"cat {sneaky}")
    assert blocks(f"cat /home/u/.prismor/secrets/../../..{home}/.prismor/secrets/x")


@pytest.mark.parametrize("command", [
    "cat /home/*/.prismor/secrets/x",          # glob
    "cat /home/u?/.prismor/secrets/x",
    "cat /home/{u,me}/.prismor/secrets/x",     # brace expansion
    "cat /home/$USER/.prismor/secrets/x",      # variable
    "cat /home/u$(id -un)/.prismor/secrets/x", # substitution
    "cat /root/.prismor/secrets/x",            # not a /home or /Users home
    "cat /tmp/fake/.prismor/secrets/x",
    'cat /home/u"/".prismor/secrets/x',        # quote splicing
    "cat file:///home/u/.prismor/secrets/x",
    "cat /home/u/.prismor/secrets/../../../etc/passwd",  # leaves the fixture
])
def test_ambiguous_forms_fail_closed(home, command):
    assert blocks(command), command


@pytest.mark.parametrize("command", [
    "PRISMOR_SECRETS_DIR=/home/u/.prismor/secrets python3 -m pytest -q tests/",
    "cat /home/u/.prismor/secrets/openai",
    "ls /Users/someone-else/.prismor/secrets",
    "pytest --vault=/home/u/.prismor/secrets/ -k vault",
    "grep -n '/home/u/.prismor/secrets' tests/test_cloak.py",
])
def test_fixture_under_another_home_not_flagged(home, command):
    assert vault_findings(command) == [], command


def test_fixture_next_to_real_access_still_blocks(home):
    assert blocks("ls /home/u/.prismor/secrets; cat ~/.prismor/secrets/x")


def test_existing_foreign_vault_still_flagged(home, tmp_path, monkeypatch):
    # A vault that really exists under another home is somebody's secrets.
    import prismor.runtime.policy_engine as pe
    real_lexists = os.path.lexists
    monkeypatch.setattr(pe.os.path, "lexists",
                        lambda p: os.fspath(p).startswith("/home/u/") or real_lexists(p))
    assert blocks("cat /home/u/.prismor/secrets/x")


def test_symlinked_foreign_home_to_real_home_blocks(home, monkeypatch):
    import prismor.runtime.policy_engine as pe
    real_realpath = os.path.realpath

    def fake_realpath(p, *args, **kwargs):
        p = os.fspath(p)
        if p.startswith("/home/u/") or p == "/home/u":
            return str(home) + p[len("/home/u"):]
        return real_realpath(p, *args, **kwargs)

    monkeypatch.setattr(pe.os.path, "realpath", fake_realpath)
    assert blocks("cat /home/u/.prismor/secrets/x")


def test_prismor_home_override_under_fake_home_blocks(home, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", "/home/u/.prismor")
    assert blocks("cat /home/u/.prismor/secrets/x")


def test_custom_secrets_dir_still_blocks(home, tmp_path, monkeypatch):
    custom = tmp_path / "vault"
    monkeypatch.setenv("PRISMOR_SECRETS_DIR", str(custom))
    assert blocks(f"cat {custom}/k")
    # The default name stays guarded too (fail closed).
    assert blocks("cat ~/.prismor/secrets/k")


@pytest.mark.parametrize("command", [
    # Heredocs are not exempt: every one of these still blocks.
    "cat > x.py <<'EOF'\nopen('~/.prismor/secrets/k')\nEOF\npython3 x.py",
    # Unquoted delimiter: the substitution runs while the body is written.
    "cat > out.txt <<EOF\n$(cat ~/.prismor/secrets/k)\nEOF",
    # Heredoc written INTO the vault: the mention is the opener, not the body.
    "cat > ~/.prismor/secrets/k <<'EOF'\nx\nEOF",
])
def test_live_heredoc_forms_still_block(home, command):
    assert blocks(command), command


def test_guard_fails_closed_when_vault_path_unresolvable(home, monkeypatch):
    import prismor.runtime.cloaking.secrets_store as store

    def boom():
        raise RuntimeError("unresolvable")

    monkeypatch.setattr(store, "secrets_dir", boom)
    assert blocks("cat ~/.prismor/secrets/x")

