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
