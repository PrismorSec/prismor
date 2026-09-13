"""An MCP server the scope never saw must not be denied by omission.

Regression for the transcript where the Chrome connector was blocked:
``discover_mcp_families`` could not see ``claude-in-chrome`` (it is a host
extension, not an ``mcpServers`` entry), so no scope could allow it — and the
old escape hatch only fired when the scope mentioned *no* MCP at all. Twelve
other servers were discoverable, so the hatch never opened and every Chrome
tool was denied by a scope that had never heard of it.
"""
from __future__ import annotations

from pathlib import Path

from prismor.runtime import scoped_agent as sa

CHROME_TOOL = "mcp__claude-in-chrome__navigate"
CHROME_FAMILY = "mcp__claude-in-chrome__*"
POSTHOG_FAMILY = "mcp__plugin_posthog_posthog__*"


def _event(tool):
    return {"type": "tool", "metadata": {"tool_name": tool}}


def test_static_scope_records_inventory():
    rules = sa.synthesize_scoped_rules("look at the repo", ["Bash", "Read", POSTHOG_FAMILY], Path("."))
    assert rules["inventory"] == ["Bash", "Read", POSTHOG_FAMILY]


def test_undiscovered_family_falls_through_even_when_scope_names_other_mcp():
    rules = sa.synthesize_scoped_rules("look at the repo", ["Bash", "Read", POSTHOG_FAMILY], Path("."))
    assert POSTHOG_FAMILY in rules["deny_tools"]  # scope does have MCP opinions
    assert sa.check_scoped_rules(rules, _event(CHROME_TOOL), "s") is None


def test_discovered_but_unallowed_family_is_denied():
    rules = sa.synthesize_scoped_rules("look at the repo", ["Bash", "Read", CHROME_FAMILY], Path("."))
    finding = sa.check_scoped_rules(rules, _event(CHROME_TOOL), "s")
    assert finding is not None



def test_operator_edited_scope_stays_authoritative():
    rules = sa.synthesize_scoped_rules("look at the repo", ["Bash", "Read", POSTHOG_FAMILY], Path("."))
    rules["operator_edited"] = True
    assert sa.check_scoped_rules(rules, _event(CHROME_TOOL), "s") is not None


def test_merge_unions_inventory():
    a = sa.synthesize_scoped_rules("look", ["Bash", POSTHOG_FAMILY], Path("."))
    b = sa.synthesize_scoped_rules("look", ["Bash", CHROME_FAMILY], Path("."))
    assert sa.merge_scoped_rules(a, b)["inventory"] == ["Bash", POSTHOG_FAMILY, CHROME_FAMILY]


def test_pre_inventory_sidecar_keeps_old_behaviour():
    rules = {"allowed_tools": ["Bash"], "deny_tools": [POSTHOG_FAMILY]}
    assert sa.check_scoped_rules(rules, _event(CHROME_TOOL), "s") is not None
    rules = {"allowed_tools": ["Bash"], "deny_tools": []}
    assert sa.check_scoped_rules(rules, _event(CHROME_TOOL), "s") is None


def test_static_fallback_never_guesses_deny_network():
    rules = sa.synthesize_scoped_rules("check if we have any locally", ["Bash", "Read"], Path("."))
    assert rules["deny_network"] is False
    ev = {"type": "shell", "command": "gh api gists?per_page=100", "metadata": {"tool_name": "Bash"}}
    assert sa.check_scoped_rules(rules, ev, "s") is None
