import json
from pathlib import Path

from prismor.runtime import mcp_gateway


def test_claude_desktop_config_path_is_platform_specific(monkeypatch, tmp_path):
    monkeypatch.setattr(mcp_gateway.sys, "platform", "darwin")
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    assert mcp_gateway._claude_desktop_config_path() == tmp_path / "Library/Application Support/Claude/claude_desktop_config.json"


def test_migrate_config_keeps_non_mcp_settings_and_sets_workspace(tmp_path, monkeypatch):
    config = tmp_path / "claude_desktop_config.json"
    config.write_text(json.dumps({"preferences": {"theme": "dark"}, "mcpServers": {"demo": {"command": "demo"}}}))
    monkeypatch.setattr(mcp_gateway, "DEFAULT_GATEWAY_CONFIG", tmp_path / "gateway.json")

    result = mcp_gateway.migrate_config(config, "enforce", tmp_path)

    assert result.ok
    data = json.loads(config.read_text())
    assert data["preferences"] == {"theme": "dark"}
    assert data["mcpServers"]["prismor"]["args"][-2:] == ["--workspace", str(tmp_path)]
    assert json.loads((tmp_path / "gateway.json").read_text())["mcpServers"]["demo"] == {"command": "demo"}
    assert Path(str(config) + ".bak").exists()


def test_migration_refuses_to_overwrite_existing_backup(tmp_path, monkeypatch):
    config = tmp_path / "config.json"
    original = json.dumps({"mcpServers": {"demo": {"command": "demo"}}})
    config.write_text(original)
    Path(str(config) + ".bak").write_text("keep me")
    monkeypatch.setattr(mcp_gateway, "DEFAULT_GATEWAY_CONFIG", tmp_path / "gateway.json")

    result = mcp_gateway.migrate_config(config)

    assert result.status == "failed"
    assert config.read_text() == original
    assert Path(str(config) + ".bak").read_text() == "keep me"
    assert not (tmp_path / "gateway.json").exists()
