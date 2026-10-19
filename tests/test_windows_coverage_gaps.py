"""Coverage gaps found running agents on Windows against PR #652.

- git-remote-hijack: lease / -f / +refspec pushes to a protected branch.
- cloud-metadata, secret-file-shell-read and persistence-windows-autorun are
  recommended (so --recommended blocks them) but stay overridable.
"""
import re

import pytest
import yaml

from prismor.runtime import policy_engine
from prismor.runtime.setup_wizard import _annotate_rules

_RULES = {r["id"]: r for r in yaml.safe_load(policy_engine._DEFAULT_POLICY_PATH.read_text(encoding="utf-8"))["rules"]}


def _hits(rule_id, text):
    return any(re.search(p, text, re.IGNORECASE) for p in _RULES[rule_id]["patterns"])


@pytest.mark.parametrize("cmd", [
    "git push --force-with-lease origin main",
    "git push origin main:main --force-with-lease",
    "git push --force-with-lease=main:abc123 origin main",
    "git push --force-if-includes origin master",
    "git push -f origin main",
    "git push origin main -f",
    "git push -fu origin main",
    "git push origin +main",
    "git push origin +HEAD:main",
    "git push origin +refs/heads/main",
    "git push --force origin main",
    "git push --force",
    "cd repo && git push origin +release/2.1",
])
def test_force_push_to_protected_branch_matches(cmd):
    assert _hits("git-remote-hijack", cmd)


@pytest.mark.parametrize("cmd", [
    "git push --force-with-lease origin feature/login",
    "git push origin main",
    "git push -u origin main",
    "git push origin main --follow-tags",
    "git push origin feature -f",
    "git push origin +feature/x",
    "git push --force-with-lease",          # bare lease: branch unknown, stays quiet
    "git push origin main -n",
    "git commit -m 'force push to main later'",
    "git push origin HEAD:refs/for/main",
    "git push --set-upstream origin my-branch",
])
def test_ordinary_pushes_do_not_match(cmd):
    assert not _hits("git-remote-hijack", cmd)


def test_metadata_rules_are_recommended_and_stay_retunable():
    # Recommended so --recommended blocks IMDS, but not floor: the console must
    # still be able to observe, disable or narrow them (test_mcp_guardrails).
    for rid in ("cloud-metadata-ssrf", "mcp-arg-metadata-endpoint"):
        assert rid in policy_engine._RECOMMENDED_RULE_IDS
        assert not policy_engine.is_floor_protected_rule(rid, _RULES[rid])


def test_recommended_extras_are_recommended_but_not_floor():
    rows = _annotate_rules([dict(r) for r in _RULES.values()])
    by_id = {r["id"]: r for r in rows}
    for rid in policy_engine._RECOMMENDED_RULE_IDS:
        assert rid in _RULES, rid
        assert by_id[rid]["recommended"] and not by_id[rid]["floor"]
        assert not policy_engine.is_floor_protected_rule(rid, _RULES[rid])


# ── pause gate: same bar as `prismor unlock` ──────────────────────────────────

class _Stdin:
    def __init__(self, tty):
        self._tty = tty

    def isatty(self):
        return self._tty


def _gate(monkeypatch, tmp_path, *, tty, window=0, configured=False, verify=(True, "")):
    from prismor.runtime import cli, unlock
    monkeypatch.setattr(cli.sys, "stdin", _Stdin(tty))
    monkeypatch.setattr(unlock, "remaining_seconds", lambda *a, **k: window)
    monkeypatch.setattr(unlock, "is_configured", lambda: configured)
    monkeypatch.setattr(unlock, "verify", lambda pw: verify)
    monkeypatch.setattr("getpass.getpass", lambda prompt="": "typed")
    return cli._pause_refusal("pause-hard", tmp_path)


def test_pause_refused_without_terminal(monkeypatch, tmp_path):
    msg = _gate(monkeypatch, tmp_path, tty=False)
    assert msg and "needs a terminal" in msg


def test_pause_allowed_inside_unlock_window(monkeypatch, tmp_path):
    assert _gate(monkeypatch, tmp_path, tty=False, window=120) is None


def test_pause_at_terminal_without_password(monkeypatch, tmp_path):
    assert _gate(monkeypatch, tmp_path, tty=True) is None


def test_pause_at_terminal_checks_password(monkeypatch, tmp_path):
    assert _gate(monkeypatch, tmp_path, tty=True, configured=True, verify=(False, "Wrong password.")) == "Wrong password."
    assert _gate(monkeypatch, tmp_path, tty=True, configured=True, verify=(True, "")) is None


# ── --recommended actually enforces the new rules ─────────────────────────────

def test_recommended_selection_enforces_metadata_secret_read_and_autorun(tmp_path):
    from unittest import mock
    from prismor.runtime import setup_wizard
    from prismor.runtime.policy_engine import PolicyEngine

    rec = [r["id"] for r in setup_wizard._load_rules() if r["recommended"]]
    (tmp_path / ".prismor").mkdir()
    (tmp_path / ".prismor" / "policy.yaml").write_text(setup_wizard._render_selection_policy(rec), encoding="utf-8")
    with mock.patch("prismor.runtime.enterprise.workspace_scope.is_managed", return_value=False):
        eng = PolicyEngine(workspace=tmp_path, policy_path=tmp_path / ".prismor" / "policy.yaml")
    mode = {r.id: eng._resolve_mode(r) for r in eng.rules}
    for rid in ("cloud-metadata-ssrf", "mcp-arg-metadata-endpoint", "secret-file-shell-read",
                "persistence-windows-autorun", "git-remote-hijack"):
        assert mode[rid] == "enforce", (rid, mode[rid])
    # still opt-in: an ordinary non-recommended rule stays observe
    assert mode["persistence-systemd"] == "observe"
