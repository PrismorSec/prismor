"""Session scope must judge a mirrored built-in as the built-in it is.

When the built-ins are served through the MCP gateway, the same call reaches
the host's hook layer tagged ``mcp__<server>__Bash`` and the gateway tagged
``Bash``. Without aliasing, a scope that has never heard of that server denies
the first while the gateway allows the second: one call, two verdicts.
"""
import pytest

from prismor.runtime.scoped_agent import (
    BUILTIN_SCOPE_TOOLS,
    check_scoped_rules,
    native_alias,
    _static_fallback_rules,
)


def _ev(tool, type_="shell", **kw):
    return {"type": type_, "metadata": {"tool_name": tool}, **kw}


# ── alias resolution ─────────────────────────────────────────────────────────

@pytest.mark.parametrize("tag,expected", [
    ("mcp__prismor__Bash", "Bash"),
    ("mcp__builtins__Read", "Read"),
    ("mcp__any_server__Grep", "Grep"),
    ("mcp__prismor__WebFetch", "WebFetch"),
])
def test_mirrored_tags_resolve_to_their_builtin(tag, expected):
    assert native_alias(tag) == expected


@pytest.mark.parametrize("tag", [
    "Bash",                       # already native
    "mcp__posthog__exec",         # ordinary MCP tool
    "mcp__github__create_issue",
])
def test_non_mirrored_tags_have_no_alias(tag):
    assert native_alias(tag) is None


# ── the regression this fixes ────────────────────────────────────────────────

def test_allowlist_naming_bash_covers_mirrored_bash():
    """The scope the synthesiser writes names built-ins, never
    mcp__<server>__Bash — so without aliasing every mirrored call is denied by
    omission the moment the scope has any MCP opinion at all."""
    rules = {"allowed_tools": ["Bash", "Read", "Edit", "Write", "mcp__other__*"],
             "deny_tools": [], "allowed_paths": ["**"]}
    assert check_scoped_rules(rules, _ev("mcp__prismor__Bash")) is None
    assert check_scoped_rules(rules, _ev("mcp__prismor__Read", "file_read",
                                         path="/x/y.py")) is None


def test_denylist_naming_bash_still_blocks_mirrored_bash():
    """Aliasing must not become a bypass: moving Bash onto MCP cannot escape a
    deny written against Bash."""
    rules = {"allowed_tools": ["*"], "deny_tools": ["Bash"], "allowed_paths": ["**"]}
    finding = check_scoped_rules(rules, _ev("mcp__prismor__Bash"))
    assert finding is not None


def test_server_specific_deny_still_targets_one_copy():
    """An operator can still deny one server's mirrored tool without denying
    the native one."""
    rules = {"allowed_tools": ["Bash"], "deny_tools": ["mcp__prismor__Bash"],
             "allowed_paths": ["**"]}
    assert check_scoped_rules(rules, _ev("mcp__prismor__Bash")) is not None
    assert check_scoped_rules(rules, _ev("Bash")) is None


def test_ordinary_mcp_tools_are_unaffected():
    rules = {"allowed_tools": ["Bash", "mcp__other__*"], "deny_tools": [],
             "allowed_paths": ["**"]}
    assert check_scoped_rules(rules, _ev("mcp__posthog__exec")) is not None


# ── Glob/Grep are scopeable ──────────────────────────────────────────────────

def test_glob_and_grep_are_scope_tags():
    """Absent from this list they are denied by omission by every scope."""
    assert "Glob" in BUILTIN_SCOPE_TOOLS and "Grep" in BUILTIN_SCOPE_TOOLS


def test_static_fallback_allows_read_only_discovery():
    rules = _static_fallback_rules("summarize the readme", BUILTIN_SCOPE_TOOLS)
    for tool in ("Read", "Bash", "Glob", "Grep"):
        assert tool in rules["allowed_tools"], tool
    assert "WebFetch" in rules["allowed_tools"]


# ── the family-glob regression ───────────────────────────────────────────────

def test_family_glob_does_not_swallow_an_allowed_mirrored_builtin():
    """The synthesiser never names the mirror's server, so every scope denies
    ``mcp__prismor-tools__*`` — the static fallback denies everything it did
    not allow, and the LLM lists the unknown family too. That blanket entry
    must not cancel the built-ins the same scope allows by native name, or the
    agent is left with no tools at all (verified live: Claude Code with
    `prismor mirror on` could not read a file)."""
    rules = {"allowed_tools": ["Bash", "Read", "Glob", "Grep"],
             "deny_tools": ["Write", "Edit", "mcp__prismor-tools__*",
                            "mcp__prismor__*"],
             "allowed_paths": ["**"]}
    assert check_scoped_rules(rules, _ev("mcp__prismor-tools__Bash")) is None
    assert check_scoped_rules(rules, _ev("mcp__prismor-tools__Read", "file_read",
                                         path="/x/y.py")) is None
    # A built-in the scope did NOT allow stays denied.
    assert check_scoped_rules(rules, _ev("mcp__prismor-tools__Write",
                                         "file_write", path="/x/y.py")) is not None
    # An ordinary MCP tool behind a denied family stays denied.
    assert check_scoped_rules(rules, _ev("mcp__prismor__filesystem__read_text_file",
                                         "file_read", path="/x/y.py")) is not None


def test_exact_mcp_deny_still_beats_the_native_allow():
    """Narrowing the fix must not disarm a deliberate per-server deny."""
    rules = {"allowed_tools": ["Bash"],
             "deny_tools": ["mcp__prismor-tools__Bash", "mcp__prismor-tools__*"],
             "allowed_paths": ["**"]}
    assert check_scoped_rules(rules, _ev("mcp__prismor-tools__Bash")) is not None


# ── gateway-fronted servers stay reachable ───────────────────────────────────

def test_gateway_fronted_servers_get_their_own_families(tmp_path):
    """After `prismor mcp-gateway install` the workspace lists one server named
    `prismor`, so the only token a scope could match was "prismor" — no natural
    prompt widens to the servers behind it. Expand the gateway config instead."""
    import json as _json
    from prismor.runtime.scoped_agent import discover_mcp_families

    gw = tmp_path / "gw.json"
    gw.write_text(_json.dumps({"mcpServers": {"filesystem": {}, "memory": {}}}))
    (tmp_path / ".mcp.json").write_text(_json.dumps({"mcpServers": {
        "prismor": {"command": "prismor",
                    "args": ["mcp-gateway", "--config", str(gw), "--mode", "enforce"]},
        "prismor-tools": {"command": "python3",
                          "args": ["-m", "x", "mcp-gateway", "--mirror"]},
    }}))
    fams = discover_mcp_families(tmp_path)
    assert "mcp__prismor__filesystem__*" in fams
    assert "mcp__prismor__memory__*" in fams
    # The bare gateway family must not ride along: it would glob-deny the ones above.
    assert "mcp__prismor__*" not in fams
    # The mirror is not a fan-out point; it keeps its own family.
    assert "mcp__prismor-tools__*" in fams


def test_mirror_is_not_expanded_when_a_gateway_config_exists(tmp_path, monkeypatch):
    """A mirror entry carries no --config, so the upstream lookup falls back to
    ~/.prismor/mcp-gateway.json. On any machine that also runs the gateway that
    file exists, and expanding the mirror against it replaced
    ``mcp__prismor-tools__*`` with families the mirror does not serve — leaving
    every mirrored built-in matching no family, i.e. denied by omission.

    The test above only caught this where a real gateway config happened to be
    present, so it passed in CI and failed on a developer box. Force the
    condition with a fake HOME instead.
    """
    import json as _json
    from prismor.runtime.scoped_agent import discover_mcp_families

    home = tmp_path / "home"
    (home / ".prismor").mkdir(parents=True)
    (home / ".prismor" / "mcp-gateway.json").write_text(
        _json.dumps({"mcpServers": {"cfdocs": {}, "mslearn": {}}}))
    monkeypatch.setattr("pathlib.Path.home", classmethod(lambda cls: home))

    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / ".mcp.json").write_text(_json.dumps({"mcpServers": {
        "prismor-tools": {"command": "python3",
                          "args": ["-m", "x", "mcp-gateway", "--mirror"]},
    }}))

    fams = discover_mcp_families(ws)
    assert "mcp__prismor-tools__*" in fams
    # It must not inherit the gateway's upstreams, which it does not front.
    assert "mcp__prismor-tools__cfdocs__*" not in fams
    assert "mcp__prismor-tools__mslearn__*" not in fams


def test_gateway_without_config_still_expands_against_the_default(tmp_path, monkeypatch):
    """The --config fallback is load-bearing for a real gateway entry; only the
    mirror is exempt. Guards against fixing the mirror by breaking the default."""
    import json as _json
    from prismor.runtime.scoped_agent import discover_mcp_families

    home = tmp_path / "home"
    (home / ".prismor").mkdir(parents=True)
    (home / ".prismor" / "mcp-gateway.json").write_text(
        _json.dumps({"mcpServers": {"cfdocs": {}}}))
    monkeypatch.setattr("pathlib.Path.home", classmethod(lambda cls: home))

    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / ".mcp.json").write_text(_json.dumps({"mcpServers": {
        "prismor": {"command": "prismor", "args": ["mcp-gateway", "--mode", "enforce"]},
    }}))

    fams = discover_mcp_families(ws)
    assert "mcp__prismor__cfdocs__*" in fams
    assert "mcp__prismor__*" not in fams


def test_gateway_family_token_matches_the_fronted_server_name(tmp_path):
    from prismor.runtime.scoped_agent import _mcp_family_tokens
    assert "filesystem" in _mcp_family_tokens("mcp__prismor__filesystem__*")
