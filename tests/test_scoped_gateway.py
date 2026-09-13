"""Scoped agent must see through the Prismor MCP gateway to its upstreams.

The gateway aggregates every upstream MCP server under ONE server name, so the
only family discovery produced was ``mcp__prismor__*`` — token "prismor", which
no natural task prompt names. In static mode (no ANTHROPIC_API_KEY) that meant
every gatewayed MCP tool was denied by omission, whatever the task asked for.

The fix: ``discover_mcp_families`` expands a gateway server into per-upstream
families (``mcp__prismor__notes__*``), and ``_static_fallback_rules`` matches
individual MCP tools, not only ``__*`` families.
"""
from __future__ import annotations

import json

from prismor.runtime.scoped_agent import (
    _static_fallback_rules,
    _tool_matches,
    discover_mcp_families,
)


def test_static_fallback_allows_upstream_named_in_goal():
    fam = "mcp__prismor__notes__*"  # gateway-expanded family for the notes upstream
    rules = _static_fallback_rules("get the release notes", [fam])
    assert fam in rules["allowed_tools"]
    # the concrete tool the gateway exposes is covered by the allowed family
    assert _tool_matches("mcp__prismor__notes__fetch_notes", rules["allowed_tools"])
    assert rules["deny_network"] is False


def test_static_fallback_denies_unrelated_upstream():
    notes, pay = "mcp__prismor__notes__*", "mcp__prismor__payments__*"
    rules = _static_fallback_rules("get the release notes", [notes, pay])
    assert notes in rules["allowed_tools"]
    assert pay not in rules["deny_tools"]  # payments never named → no opinion, gateway screens it
    assert pay not in rules["inventory"]
    assert not _tool_matches("mcp__prismor__payments__charge_card", rules["allowed_tools"])


def test_static_fallback_matches_individual_mcp_tool():
    # even without family expansion, an individual gatewayed tool is matched by
    # its own name tokens (regression: the loop used to skip non-``__*`` tools).
    tool = "mcp__prismor__notes__fetch_notes"
    rules = _static_fallback_rules("fetch the notes", [tool])
    assert tool in rules["allowed_tools"]


def test_gateway_discovery_expands_to_upstream_families(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".prismor").mkdir(parents=True)
    ws = tmp_path / "ws"
    ws.mkdir()
    cfg = home / ".prismor" / "mcp-gateway.json"
    cfg.write_text(json.dumps({"mcpServers": {
        "notes": {"command": "python3", "args": ["notes.py"]},
        "payments": {"command": "python3", "args": ["pay.py"]},
    }}))
    (ws / ".mcp.json").write_text(json.dumps({"mcpServers": {
        "prismor": {"command": "prismor",
                    "args": ["mcp-gateway", "--config", str(cfg)]},
    }}))
    # keep it hermetic: no real ~/.claude.json for the claude branch
    import prismor.runtime.scoped_agent as sa
    monkeypatch.setattr(sa.Path, "home", staticmethod(lambda: home))

    fams = discover_mcp_families(ws)
    assert "mcp__prismor__notes__*" in fams
    assert "mcp__prismor__payments__*" in fams
    # the broad gateway family is replaced by the per-upstream ones
    assert "mcp__prismor__*" not in fams


if __name__ == "__main__":  # pragma: no cover - quick self-check
    test_static_fallback_allows_upstream_named_in_goal()
    test_static_fallback_denies_unrelated_upstream()
    test_static_fallback_matches_individual_mcp_tool()
    print("ok")
