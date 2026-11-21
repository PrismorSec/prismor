"""The dashboard's MCP inventory carries the `discover mcp` footprint:
running copies, resident memory and recent-session use per server."""
from pathlib import Path

from prismor.runtime import discover, server
from prismor.runtime.discover import McpRecord


def _records():
    return [
        McpRecord(name="memory", agent="claude", source="~/.claude.json",
                  command=["npx", "-y", "@modelcontextprotocol/server-memory"]),
        McpRecord(name="github", agent="claude", source="~/.claude.json",
                  command=["npx", "-y", "@modelcontextprotocol/server-github"]),
    ]


def _fake_footprint(records, days=7):
    for r in records:
        if r.name == "memory":
            r.running, r.rss_mb, r.pids = 7, 268, [1, 2, 3, 4, 5, 6, 7]
            r.sessions_used, r.sessions_total, r.rarely_used = 0, 123, True


def test_inventory_has_footprint(monkeypatch, tmp_path):
    monkeypatch.setattr(discover, "discover_mcp", lambda ws: _records())
    monkeypatch.setattr(discover, "add_footprint", _fake_footprint)
    monkeypatch.setattr(server, "get_mcp_usage", lambda: {})
    servers = {s["name"]: s for s in server._enrich_mcp_inventory(Path(tmp_path), [], set())}
    assert servers["memory"]["footprint"] == {
        "copies": 7, "rss_mb": 268, "sessions_used": 0, "sessions_total": 123, "rarely_used": True}
    # Not running locally: no footprint, and pids never leave the server.
    assert servers["github"]["footprint"] is None
    assert "pids" not in servers["memory"]


def test_inventory_survives_footprint_failure(monkeypatch, tmp_path):
    def boom(records, days=7):
        raise RuntimeError("ps unavailable")
    monkeypatch.setattr(discover, "discover_mcp", lambda ws: _records())
    monkeypatch.setattr(discover, "add_footprint", boom)
    monkeypatch.setattr(server, "get_mcp_usage", lambda: {})
    servers = server._enrich_mcp_inventory(Path(tmp_path), [], set())
    assert {s["name"] for s in servers} == {"memory", "github"}
    assert all(s["footprint"] is None for s in servers)
