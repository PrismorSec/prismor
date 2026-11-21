"""Home-level agent definitions (~/.claude/agents, ~/.codex/agents) are
auto-loaded instruction files, so the memory scan must find them."""
from pathlib import Path

from prismor.runtime import hooks


def test_discovers_home_agent_definitions(tmp_path, monkeypatch):
    home, ws = tmp_path / "home", tmp_path / "elsewhere" / "repo"
    (home / ".claude" / "agents").mkdir(parents=True)
    (home / ".codex" / "agents").mkdir(parents=True)
    (ws / ".codex" / "agents").mkdir(parents=True)
    (home / ".claude" / "agents" / "reviewer.md").write_text("review")
    (home / ".codex" / "agents" / "explorer.toml").write_text('developer_instructions = "x"')
    (ws / ".codex" / "agents" / "worker.toml").write_text('developer_instructions = "y"')
    monkeypatch.setattr(Path, "home", lambda: home)
    monkeypatch.setattr(hooks, "_instructions_loaded_paths", lambda: [])
    found = {p.name for p in hooks._discover_memory_files(ws)}
    assert {"reviewer.md", "explorer.toml", "worker.toml"} <= found
