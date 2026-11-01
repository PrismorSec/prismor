"""Cloak install pins PRISMOR_SECRETS_DIR into the agent config only when it
was chosen on purpose.

Prismor's own settings.json `env` block exports PRISMOR_SECRETS_DIR into every
Claude Code shell, so `prismor setup` run from such a session with a sandbox
HOME baked the session's vault path into the sandbox's hooks. The hooks already
resolve ${PRISMOR_HOME:-$HOME/.prismor}/secrets at hook time.
"""
import json
from pathlib import Path

import pytest

from prismor.runtime.cloaking import install
from prismor.runtime.cloaking.secrets_store import pinned_secrets_dir


@pytest.fixture
def env(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    for k in ("PRISMOR_SECRETS_DIR", "PRISMOR_HOME", "AI_AGENT", "CLAUDECODE",
              "CODEX_THREAD_ID", "CODEX_SANDBOX", "CURSOR_AGENT", "GEMINI_CLI"):
        monkeypatch.delenv(k, raising=False)
    ws = tmp_path / "ws"
    ws.mkdir()
    return home, ws, tmp_path


def _settings_env(ws: Path) -> dict:
    return json.loads((ws / ".claude" / "settings.json").read_text()).get("env", {})


def test_default_location_is_not_pinned(env):
    home, ws, _ = env
    assert pinned_secrets_dir() is None
    install(workspace=ws, scope="project")
    assert "PRISMOR_SECRETS_DIR" not in _settings_env(ws)
    assert (home / ".prismor" / "secrets").is_dir()


def test_explicit_override_from_a_human_shell_is_pinned(env, monkeypatch):
    _, ws, tmp = env
    vault = tmp / "vault"
    monkeypatch.setenv("PRISMOR_SECRETS_DIR", str(vault))
    install(workspace=ws, scope="project")
    assert _settings_env(ws)["PRISMOR_SECRETS_DIR"] == str(vault)


def test_inherited_agent_session_vault_is_not_baked_into_another_home(env, monkeypatch):
    home, ws, tmp = env
    other_users_vault = tmp / "real-user" / ".prismor" / "secrets"
    monkeypatch.setenv("PRISMOR_SECRETS_DIR", str(other_users_vault))
    monkeypatch.setenv("CLAUDECODE", "1")
    install(workspace=ws, scope="project")
    assert "PRISMOR_SECRETS_DIR" not in _settings_env(ws)
    # The vault created is the sandbox HOME's, not the inherited one.
    assert (home / ".prismor" / "secrets").is_dir()
    assert not other_users_vault.exists()


def test_reinstall_drops_a_stale_pin_and_keeps_other_env(env):
    _, ws, _ = env
    settings = ws / ".claude" / "settings.json"
    settings.parent.mkdir(parents=True)
    settings.write_text(json.dumps({"env": {"PRISMOR_SECRETS_DIR": "/home/someone-else/.prismor/secrets",
                                            "KEEP": "1"}}))
    install(workspace=ws, scope="project")
    assert _settings_env(ws) == {"KEEP": "1"}


def test_hermes_config_follows_the_same_rule(env, monkeypatch):
    import yaml
    from prismor.runtime.cloaking import hermes_installer
    home, ws, tmp = env
    monkeypatch.setenv("PRISMOR_SECRETS_DIR", str(tmp / "inherited"))
    monkeypatch.setenv("CLAUDECODE", "1")
    cfg = home / ".hermes" / "config.yaml"
    monkeypatch.setattr(hermes_installer, "_hermes_config_path", lambda: cfg)
    monkeypatch.setattr(hermes_installer, "_plugin_install_dir", lambda: home / ".hermes" / "plugins" / "prismor")
    hermes_installer.install(workspace=ws, scope="user")
    data = yaml.safe_load(cfg.read_text()) if cfg.exists() else {}
    assert "PRISMOR_SECRETS_DIR" not in (data.get("env") or {})
