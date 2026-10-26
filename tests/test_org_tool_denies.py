"""Org signed-policy tool denies (settings.tool_denies) — Phase 2b enforcement.

An org admin denies a tool tag from the Prismor web console; it ships in the
signed policy as settings.tool_denies and the device runtime blocks matching
tool calls by scope. Device-scoped entries are pre-filtered to the device
server-side, so org/device always apply here; agent/session match on the
event's agent name / session id.
"""
from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / ".prismor"))
    from prismor.runtime import agents
    agents._CONFIG_CACHE.clear()
    yield


def _eval(tmp_path, monkeypatch, tool_denies, *, agent_name="codex", session_id="s1", tool="Bash"):
    from prismor.runtime import runtime
    from prismor.runtime.policy_engine import PolicyEngine

    real_init = PolicyEngine.__init__

    def fake_init(self, *a, **kw):
        real_init(self, *a, **kw)
        self.tool_denies = tool_denies

    monkeypatch.setattr(PolicyEngine, "__init__", fake_init)
    return runtime.evaluate_tool_call(
        event={"type": "shell", "agent_event": "PreToolUse", "command": "echo hi",
               "metadata": {"tool_name": tool}},
        workspace=tmp_path, agent="codex", agent_name=agent_name,
        mode="observe", session_id=session_id, persist=False,
    )


def test_org_scope_blocks_everyone(tmp_path, monkeypatch):
    d = _eval(tmp_path, monkeypatch, [{"id": "t1", "tool": "Bash", "action": "deny", "scope": "org"}])
    assert d.allow is False
    assert any(f.get("ruleId") == "org-tool-deny" for f in d.findings)


def test_agent_scope_matches_only_that_agent(tmp_path, monkeypatch):
    denies = [{"id": "t2", "tool": "Bash", "action": "deny", "scope": "agent", "scopeId": "codex"}]
    assert _eval(tmp_path, monkeypatch, denies, agent_name="codex").allow is False
    assert _eval(tmp_path, monkeypatch, denies, agent_name="claude").allow is True


def test_session_scope_matches_only_that_session(tmp_path, monkeypatch):
    denies = [{"id": "t3", "tool": "Bash", "action": "deny", "scope": "session", "scopeId": "s1"}]
    assert _eval(tmp_path, monkeypatch, denies, session_id="s1").allow is False
    assert _eval(tmp_path, monkeypatch, denies, session_id="s2").allow is True


def test_device_scope_applies_here_prefiltered(tmp_path, monkeypatch):
    # Device entries are pre-filtered to this device server-side, so scopeId is
    # not re-checked on the device — it always applies.
    d = _eval(tmp_path, monkeypatch, [{"id": "t4", "tool": "Bash", "action": "deny", "scope": "device", "scopeId": "whatever"}])
    assert d.allow is False


def test_different_tool_not_blocked(tmp_path, monkeypatch):
    denies = [{"id": "t5", "tool": "mcp__node_repl__js", "action": "deny", "scope": "org"}]
    assert _eval(tmp_path, monkeypatch, denies, tool="Bash").allow is True


def test_mcp_tag_blocked_verbatim(tmp_path, monkeypatch):
    denies = [{"id": "t6", "tool": "mcp__node_repl__js", "action": "deny", "scope": "org"}]
    assert _eval(tmp_path, monkeypatch, denies, tool="mcp__node_repl__js").allow is False


def test_non_deny_action_ignored(tmp_path, monkeypatch):
    denies = [{"id": "t7", "tool": "Bash", "action": "allow", "scope": "org"}]
    assert _eval(tmp_path, monkeypatch, denies).allow is True


def _eval_enforce(tmp_path, monkeypatch, tool_denies, *, session_id="s1", tool="Bash", event_type="shell", path=None):
    """Like _eval, but mode='enforce' — needed for scoped-agent findings, whose
    category ('scoped_agent') isn't exempt from the observe-mode downgrade that
    agent-control findings get (see runtime.py's per-agent observe override)."""
    from prismor.runtime import runtime
    from prismor.runtime.policy_engine import PolicyEngine

    real_init = PolicyEngine.__init__

    def fake_init(self, *a, **kw):
        real_init(self, *a, **kw)
        self.tool_denies = tool_denies

    monkeypatch.setattr(PolicyEngine, "__init__", fake_init)
    event = {"type": event_type, "agent_event": "PreToolUse", "metadata": {"tool_name": tool}}
    if path is not None:
        event["path"] = path
    return runtime.evaluate_tool_call(
        event=event, workspace=tmp_path, agent="codex", agent_name="codex",
        mode="enforce", session_id=session_id, persist=False,
    )


def test_org_allow_overrides_local_agent_deny(tmp_path, monkeypatch):
    """Org policy is authoritative: an org 'allow' row for a tool must lift a
    LOCAL .prismor/agents.yaml deny for that same tool, not just an org deny."""
    from prismor.runtime.agents import set_tool_policy
    set_tool_policy(tmp_path, "agent", "mcp__prismor-demo__create_draft", "deny", agent="codex")

    denies = [{"id": "a1", "tool": "mcp__prismor-demo__create_draft", "action": "deny", "scope": "session", "scopeId": "other"}]
    blocked = _eval(tmp_path, monkeypatch, denies, tool="mcp__prismor-demo__create_draft")
    assert blocked.allow is False
    assert any(f.get("ruleId") == "agent-tool-deny" for f in blocked.findings)

    allows = [{"id": "a2", "tool": "mcp__prismor-demo__create_draft", "action": "allow", "scope": "org"}]
    allowed = _eval(tmp_path, monkeypatch, allows, tool="mcp__prismor-demo__create_draft")
    assert allowed.allow is True
    assert not any(f.get("ruleId") == "agent-tool-deny" for f in allowed.findings)


def test_org_allow_overrides_session_scoped_deny(tmp_path, monkeypatch):
    """Org 'allow' must also lift a session-scoped rule that denies the tool."""
    from prismor.runtime.scoped_agent import save_scoped_rules
    save_scoped_rules(tmp_path, "s1", {
        "allowed_tools": ["Read"],
        "deny_tools": ["mcp__prismor-demo__create_draft"],
        "allowed_paths": ["**"],
        "deny_network": True,
    })

    blocked = _eval_enforce(tmp_path, monkeypatch, [], session_id="s1", tool="mcp__prismor-demo__create_draft")
    assert blocked.allow is False
    assert any(f.get("ruleId") == "scoped-agent" for f in blocked.findings)

    allows = [{"id": "a3", "tool": "mcp__prismor-demo__create_draft", "action": "allow", "scope": "session", "scopeId": "s1"}]
    allowed = _eval_enforce(tmp_path, monkeypatch, allows, session_id="s1", tool="mcp__prismor-demo__create_draft")
    assert allowed.allow is True
    assert not any(f.get("ruleId") == "scoped-agent" for f in allowed.findings)


def test_org_allow_does_not_lift_kill_switch(tmp_path, monkeypatch):
    """The agent kill switch stays an authoritative floor: an org tool-allow
    must not resurrect a disabled agent."""
    from prismor.runtime.agents import upsert_agent
    upsert_agent("codex", tmp_path, enabled=False)

    allows = [{"id": "a4", "tool": "Bash", "action": "allow", "scope": "org"}]
    d = _eval(tmp_path, monkeypatch, allows, tool="Bash")
    assert d.allow is False
    assert any(f.get("ruleId") == "agent-disabled" for f in d.findings)


def test_org_allow_does_not_lift_scoped_network_denial(tmp_path, monkeypatch):
    """A tool allow must not accidentally lift a network scoped finding — only
    the tool-access check for that same event."""
    from prismor.runtime.scoped_agent import save_scoped_rules
    save_scoped_rules(tmp_path, "s2", {
        "allowed_tools": ["*"],
        "deny_tools": [],
        "allowed_paths": ["**"],
        "deny_network": True,
    })
    from prismor.runtime import runtime
    from prismor.runtime.policy_engine import PolicyEngine

    real_init = PolicyEngine.__init__

    def fake_init(self, *a, **kw):
        real_init(self, *a, **kw)
        self.tool_denies = [{"id": "a5", "tool": "WebFetch", "action": "allow", "scope": "org"}]

    monkeypatch.setattr(PolicyEngine, "__init__", fake_init)
    d = runtime.evaluate_tool_call(
        event={"type": "network", "agent_event": "PreToolUse", "url": "https://example.com",
               "metadata": {"tool_name": "WebFetch"}},
        workspace=tmp_path, agent="codex", agent_name="codex",
        mode="enforce", session_id="s2", persist=False,
    )
    assert d.allow is False
    assert any(f.get("ruleId") == "scoped-agent" for f in d.findings)


def test_tool_denies_sig_matches_server_format(monkeypatch):
    # Reproduces lib/tool-policy.ts toolDeniesSig: sorted
    # id:tool:action:scope:scopeId lines -> sha256 -> 16 hex.
    import hashlib
    from prismor.runtime.enterprise import remote_policy as rp
    denies = [
        {"id": "b", "tool": "Bash", "action": "deny", "scope": "org", "scopeId": None},
        {"id": "a", "tool": "WebSearch", "action": "deny", "scope": "agent", "scopeId": "codex"},
    ]
    # Via monkeypatch: a bare assignment here left an org policy denying Bash in
    # place for the rest of the process, so every later shell event blocked.
    monkeypatch.setattr(rp, "verify_and_load", lambda: {"settings": {"tool_denies": denies}})
    lines = sorted([
        "b:Bash:deny:org:",
        "a:WebSearch:deny:agent:codex",
    ])
    expected = hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()[:16]
    assert rp._current_tool_denies_sig() == expected


def test_org_deny_copy_names_console_not_local_override(tmp_path, monkeypatch):
    from prismor.runtime.unblock import unblock_steps
    d = _eval(tmp_path, monkeypatch, [{"id": "t9", "tool": "Bash", "action": "deny", "scope": "org"}])
    f = next(f for f in d.findings if f.get("ruleId") == "org-tool-deny")
    assert "org org" not in f["title"] + f["evidence"]
    assert "MCP Hub" in f["remediation"] and "Tool Call panel" not in f["remediation"]
    steps = "\n".join(unblock_steps(f, workspace=tmp_path))
    assert "prismor allow" not in steps and "MCP Hub" in steps


# ── Server-wide MCP denies: one `mcp__<server>__*` entry switches off a whole
# MCP server (the console's Extensions "Off" switch). ──────────────────────

def test_mcp_server_tags_shapes():
    from prismor.runtime.scoped_agent import mcp_server_tags
    assert mcp_server_tags("mcp__posthog__exec") == ["mcp__posthog__*"]
    # Through the gateway the agent's hook sees the gateway's prefix too.
    assert mcp_server_tags("mcp__prismor__github__create_issue") == ["mcp__prismor__*", "mcp__github__*"]
    assert mcp_server_tags("mcp__prismor__status") == ["mcp__prismor__*"]
    assert mcp_server_tags("mcp__plugin_cloudflare_cloudflare-api__authenticate") == ["mcp__plugin_cloudflare_cloudflare-api__*"]
    for not_mcp in ("Bash", "Skill", "mcp__", "mcp__nameonly", "mcp____x", "xmcp__a__b"):
        assert mcp_server_tags(not_mcp) == [], not_mcp


def test_server_wide_deny_blocks_every_tool_of_that_server(tmp_path, monkeypatch):
    denies = [{"id": "f1", "tool": "mcp__posthog__*", "action": "deny", "scope": "org"}]
    for tool in ("mcp__posthog__exec", "mcp__posthog__query", "mcp__posthog__a__b"):
        d = _eval(tmp_path, monkeypatch, denies, tool=tool)
        assert d.allow is False, tool
        assert any(f.get("ruleId") == "org-tool-deny" for f in d.findings)


def test_server_wide_deny_leaves_other_servers_alone(tmp_path, monkeypatch):
    denies = [{"id": "f2", "tool": "mcp__posthog__*", "action": "deny", "scope": "org"}]
    # A lookalike prefix is a different server.
    for tool in ("mcp__posthog2__exec", "mcp__post__exec", "mcp__github__echo", "Bash"):
        assert _eval(tmp_path, monkeypatch, denies, tool=tool).allow is True, tool


def test_server_wide_deny_catches_gateway_routed_call_at_the_hook(tmp_path, monkeypatch):
    denies = [{"id": "f3", "tool": "mcp__github__*", "action": "deny", "scope": "org"}]
    assert _eval(tmp_path, monkeypatch, denies, tool="mcp__prismor__github__create_issue").allow is False
    # The gateway's own tools are not the github server.
    assert _eval(tmp_path, monkeypatch, denies, tool="mcp__prismor__status").allow is True


def test_server_wide_deny_respects_scope(tmp_path, monkeypatch):
    denies = [{"id": "f4", "tool": "mcp__posthog__*", "action": "deny", "scope": "agent", "scopeId": "codex"}]
    assert _eval(tmp_path, monkeypatch, denies, agent_name="codex", tool="mcp__posthog__exec").allow is False
    assert _eval(tmp_path, monkeypatch, denies, agent_name="claude", tool="mcp__posthog__exec").allow is True


def test_server_wide_step_up_asks(tmp_path, monkeypatch):
    denies = [{"id": "f5", "tool": "mcp__posthog__*", "action": "step_up", "scope": "org"}]
    d = _eval(tmp_path, monkeypatch, denies, tool="mcp__posthog__exec")
    assert any("step" in str(f.get("ruleId") or "") or f.get("step_up") for f in d.findings), d.findings


def test_server_wide_allow_does_not_lift_a_deny(tmp_path, monkeypatch):
    """Allows stay exact-match: a server-wide tag may only tighten."""
    from prismor.runtime.agents import set_tool_policy
    set_tool_policy(tmp_path, "agent", "mcp__posthog__exec", "deny", agent="codex")
    allows = [{"id": "f6", "tool": "mcp__posthog__*", "action": "allow", "scope": "org"}]
    assert _eval(tmp_path, monkeypatch, allows, tool="mcp__posthog__exec").allow is False


def test_local_agent_deny_accepts_server_wide_tag(tmp_path, monkeypatch):
    from prismor.runtime.agents import set_tool_policy
    set_tool_policy(tmp_path, "agent", "mcp__posthog__*", "deny", agent="codex")
    assert _eval(tmp_path, monkeypatch, [], tool="mcp__posthog__exec").allow is False
    assert _eval(tmp_path, monkeypatch, [], tool="mcp__github__echo").allow is True


def test_server_wide_tag_never_inventoried(tmp_path, monkeypatch):
    """Families are permissions, not tools the agent holds."""
    from prismor.runtime import agents
    captured = {}
    monkeypatch.setattr(
        agents, "record_seen",
        lambda name, framework, workspace, tools, session_id: captured.update(tools=tools),
    )
    from prismor.runtime import runtime
    runtime.evaluate_tool_call(
        event={"type": "mcp", "agent_event": "PreToolUse", "metadata": {"tool_name": "mcp__prismor__github__x"}},
        workspace=tmp_path, agent="claude", agent_name="claude", mode="observe",
        session_id="s1", persist=False,
    )
    assert [t["name"] for t in captured.get("tools", [])] == ["mcp__prismor__github__x"]


def test_tag_matches_rules():
    from prismor.runtime.scoped_agent import tag_matches
    fam = lambda tool: [tool] + __import__("prismor.runtime.scoped_agent", fromlist=["x"]).mcp_server_tags(tool)
    assert tag_matches("Bash", ["Bash"])
    assert not tag_matches("Bash", ["Read"])
    assert not tag_matches(None, ["Bash"]) and not tag_matches("", ["Bash"])
    # Plugin-provided server: Claude Code names it plugin_<plugin>_<server>.
    assert tag_matches("mcp__posthog__*", fam("mcp__plugin_posthog_posthog__exec"))
    # Connector with spaces/dots in its configured name.
    assert tag_matches("mcp__claude.ai Gmail__*", fam("mcp__claude_ai_Gmail__send_message"))
    # Lookalikes are different servers.
    assert not tag_matches("mcp__posthog__*", fam("mcp__posthog2__exec"))
    assert not tag_matches("mcp__posthog__*", fam("mcp__xposthog__exec"))
    assert not tag_matches("mcp__hog__*", fam("mcp__posthog__exec"))
    # A family entry never matches a non-MCP tool, nor is "mcp____*" anything.
    assert not tag_matches("mcp__Bash__*", fam("Bash"))
    assert not tag_matches("mcp____*", fam("mcp__a__b"))


def test_server_wide_deny_catches_plugin_and_connector_names(tmp_path, monkeypatch):
    denies = [{"id": "f7", "tool": "mcp__posthog__*", "action": "deny", "scope": "org"},
              {"id": "f8", "tool": "mcp__claude.ai Gmail__*", "action": "deny", "scope": "org"}]
    assert _eval(tmp_path, monkeypatch, denies, tool="mcp__plugin_posthog_posthog__exec").allow is False
    assert _eval(tmp_path, monkeypatch, denies, tool="mcp__claude_ai_Gmail__send_message").allow is False
    assert _eval(tmp_path, monkeypatch, denies, tool="mcp__claude_ai_Slack__post").allow is True
