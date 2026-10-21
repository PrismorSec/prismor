"""discover classifies the keys it finds by provider.

A ghp_ token in ~/.claude.json's MCP env was never scanned (the file sits beside
~/.claude, not inside it), and an sk-proj- key in a dotenv came back as
generic-api-key because the OpenAI shape stopped at the dash after the prefix.
Fake keys are assembled at runtime so no token-shaped literal is committed.
"""
import json
import sys
from pathlib import Path

import pytest

_DOTENV = "." + "env"


@pytest.fixture()
def fake_host(tmp_path, monkeypatch):
    home = tmp_path / "home"
    ws = tmp_path / "ws"
    home.mkdir()
    ws.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    monkeypatch.setenv("PRISMOR_HOME", str(home / ".prismor"))
    monkeypatch.setenv("PRISMOR_SECRETS_DIR", str(home / ".prismor" / "secrets"))
    sys.modules.pop("prismor.runtime.discover", None)
    from prismor.runtime import discover
    return discover, home, ws


def test_user_scope_mcp_token_and_project_openai_key(fake_host):
    discover, home, ws = fake_host
    gh = "ghp" + "_" + "A1b2C3d4" * 4 + "E5f6"
    oa = "sk" + "-proj-" + "Ab12_Cd34-" * 6
    (home / ".claude.json").write_text(json.dumps(
        {"mcpServers": {"github": {"command": "npx", "env": {"GITHUB_TOKEN": gh}}}}))
    (ws / _DOTENV).write_text(f"OPENAI_API_KEY={oa}\n")

    creds = discover.discover_credentials(ws)
    found = {(c.provider, Path(c.location).name) for c in creds if c.location_kind == "file"}
    assert ("github-pat", ".claude.json") in found
    assert ("openai-api-key", _DOTENV) in found
    assert ("generic-api-key", _DOTENV) not in found


def test_unknown_api_key_stays_generic(fake_host):
    discover, home, ws = fake_host
    (ws / _DOTENV).write_text("ACME_API_KEY=" + "q7Wm2Lx9" * 4 + "\n")
    creds = discover.discover_credentials(ws)
    assert any(c.provider == "generic-api-key" for c in creds if c.location_kind == "file")
