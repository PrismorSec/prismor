"""A malformed agent config must fail loudly, never be silently replaced.

``install_hooks`` reads an agent's config, merges its own hook in, and writes
the result straight back. If the read fell back to ``{}`` on a parse error, a
config with a stray comma would come back containing nothing but Prismor's
hook — every one of the developer's own settings gone, with no error.

That is tolerable-ish when a human typed the command and can read the output.
It is not tolerable on the automated paths (`discover --fix`,
`ensure_global_coverage`), which is why the failure is typed.

Run: python3 -m pytest tests/test_hook_config_error.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO))

from prismor.runtime import hooks  # noqa: E402


@pytest.fixture()
def ws(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    workspace = tmp_path / "ws"
    workspace.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    return workspace, home


def test_missing_config_is_not_an_error(ws):
    """A fresh machine has no config yet — that is the normal install path."""
    assert hooks._read_json(ws[0] / "nope.json") == {}


def test_valid_config_reads_through(ws):
    p = ws[0] / "ok.json"
    p.write_text('{"hooks": {"PreToolUse": []}}', encoding="utf-8")
    assert hooks._read_json(p) == {"hooks": {"PreToolUse": []}}


@pytest.mark.parametrize("bad", [
    '{"hooks": }',                 # syntax error
    '{"hooks": [1,2,},',           # unbalanced
    'not json at all',             # plain text
])
def test_malformed_config_raises_a_typed_error(ws, bad):
    p = ws[0] / "broken.json"
    p.write_text(bad, encoding="utf-8")
    with pytest.raises(hooks.HookConfigError) as exc:
        hooks._read_json(p)
    assert "broken.json" in str(exc.value)


def test_install_hooks_does_not_clobber_a_broken_config(ws):
    """The whole point: the developer's file must survive untouched."""
    workspace, home = ws
    config = home / ".claude" / "settings.json"
    config.parent.mkdir(parents=True)
    original = '{"permissions": {"allow": ["Bash"]}, oops}'
    config.write_text(original, encoding="utf-8")

    with pytest.raises(hooks.HookConfigError):
        hooks.install_hooks(repo_root=workspace, workspace=workspace,
                            agent="claude", scope="global", mode="observe")

    assert config.read_text(encoding="utf-8") == original


def test_install_hooks_still_works_on_a_good_config(ws):
    workspace, home = ws
    config = home / ".claude" / "settings.json"
    config.parent.mkdir(parents=True)
    config.write_text('{"permissions": {"allow": ["Bash"]}}', encoding="utf-8")

    hooks.install_hooks(repo_root=workspace, workspace=workspace,
                        agent="claude", scope="global", mode="observe")

    written = json.loads(config.read_text(encoding="utf-8"))
    assert "hook-dispatch" in json.dumps(written)
    # The developer's own settings are preserved, not replaced.
    assert written["permissions"] == {"allow": ["Bash"]}


def test_ensure_global_coverage_survives_a_broken_config(ws, monkeypatch):
    """Self-heal runs unattended on the hot path — one broken config must not
    take down the dispatcher."""
    workspace, home = ws
    monkeypatch.setattr(hooks, "unguarded_agents", lambda w: ["claude"])
    config = home / ".claude" / "settings.json"
    config.parent.mkdir(parents=True)
    config.write_text("{oops", encoding="utf-8")

    repaired = hooks.ensure_global_coverage(repo_root=workspace, workspace=workspace)
    assert repaired == []
    assert config.read_text(encoding="utf-8") == "{oops"
