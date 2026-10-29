"""Tests for org (remote) per-agent control merge (prismor/runtime/agents.py) and the
end-to-end kill-switch through evaluate_tool_call.

The org controls arrive in the verified signed policy's settings.agent_controls
(PolicyEngine.agent_controls) and merge tighten-only with the local agents.yaml.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from prismor.runtime import agents


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / ".prismor"))
    agents._CONFIG_CACHE.clear()
    yield


def _local(workspace: Path, name: str, **fields):
    agents.upsert_agent(name, workspace, framework="openai-agents", **fields)


# ── merge precedence matrix ────────────────────────────────────────────────

def test_remote_disable_cannot_be_locally_reenabled(tmp_path):
    _local(tmp_path, "bot", enabled=True)
    ctl = agents.resolve_agent_control("bot", tmp_path, remote_controls={"bot": {"enabled": False}})
    assert ctl.enabled is False
    assert ctl.disabled_by == "org"


def test_local_disable_holds_even_if_remote_enabled(tmp_path):
    _local(tmp_path, "bot", enabled=False)
    ctl = agents.resolve_agent_control("bot", tmp_path, remote_controls={"bot": {"enabled": True}})
    assert ctl.enabled is False
    assert ctl.disabled_by == "local"


def test_disabled_by_both(tmp_path):
    _local(tmp_path, "bot", enabled=False)
    ctl = agents.resolve_agent_control("bot", tmp_path, remote_controls={"bot": {"enabled": False}})
    assert ctl.enabled is False and ctl.disabled_by == "both"


def test_remote_mode_wins_over_local(tmp_path):
    _local(tmp_path, "bot", mode="observe")
    ctl = agents.resolve_agent_control("bot", tmp_path, remote_controls={"bot": {"enabled": True, "mode": "enforce"}})
    assert ctl.mode == "enforce"


def test_remote_only_agent_not_in_local_registry(tmp_path):
    # An org can control an agent this machine has never registered locally.
    ctl = agents.resolve_agent_control("ghost", tmp_path, remote_controls={"ghost": {"enabled": False}})
    assert ctl.enabled is False and ctl.disabled_by == "org"


def test_iam_profile_remote_then_local_fallback(tmp_path):
    _local(tmp_path, "bot", iam_profile="local-ro")
    assert agents.resolve_agent_control("bot", tmp_path, remote_controls={"bot": {"enabled": True, "iam_profile": "org-ro"}}).iam_profile == "org-ro"
    assert agents.resolve_agent_control("bot", tmp_path, remote_controls={"bot": {"enabled": True}}).iam_profile == "local-ro"


def test_unregistered_agent_is_permissive(tmp_path):
    ctl = agents.resolve_agent_control("nobody", tmp_path, remote_controls={})
    assert ctl.enabled is True and ctl.mode is None and ctl.disabled_by is None


# ── end-to-end: a remote kill-switch blocks a benign call ──────────────────

def test_remote_killswitch_blocks_via_evaluate_tool_call(tmp_path, monkeypatch):
    """A managed workspace whose signed policy disables 'checkout-bot' → every
    tool call from that instance is blocked, even a benign one."""
    from prismor.runtime import runtime
    from prismor.runtime.policy_engine import PolicyEngine

    # Force the engine to look managed and carry the org control, without a real
    # enrolled device / signed policy.
    real_init = PolicyEngine.__init__

    def fake_init(self, *a, **kw):
        real_init(self, *a, **kw)
        self.workspace_managed = True
        self.agent_controls = {"checkout-bot": {"enabled": False}}

    monkeypatch.setattr(PolicyEngine, "__init__", fake_init)

    d = runtime.evaluate_tool_call(
        event={"type": "shell", "agent_event": "PreToolUse", "command": "echo hello", "metadata": {"tool_name": "Bash"}},
        workspace=tmp_path, agent="openai-agents", agent_name="checkout-bot",
        mode="observe", session_id="s1", persist=False,
    )
    assert d.allow is False
    assert any(f.get("ruleId") == "agent-disabled" for f in d.findings)
    disabled = next(f for f in d.findings if f.get("ruleId") == "agent-disabled")
    assert "org" in disabled["evidence"] or "control plane" in disabled["evidence"]


def test_unmanaged_workspace_ignores_remote_controls(tmp_path, monkeypatch):
    """A personal (unmanaged) workspace never carries agent_controls, so a
    remote pause has no effect there."""
    from prismor.runtime import runtime
    from prismor.runtime.policy_engine import PolicyEngine

    real_init = PolicyEngine.__init__

    def fake_init(self, *a, **kw):
        real_init(self, *a, **kw)
        self.workspace_managed = False
        self.agent_controls = {}  # unmanaged → no remote overlay merged

    monkeypatch.setattr(PolicyEngine, "__init__", fake_init)

    d = runtime.evaluate_tool_call(
        event={"type": "shell", "agent_event": "PreToolUse", "command": "echo hi", "metadata": {"tool_name": "Bash"}},
        workspace=tmp_path, agent="openai-agents", agent_name="checkout-bot",
        mode="observe", session_id="s2", persist=False,
    )
    assert not any(f.get("ruleId") == "agent-disabled" for f in d.findings)


# ── tool-tag deny lists (dashboard "Apply a rule" — session/agent/global) ──

def test_set_tool_policy_agent_scope(tmp_path):
    agents.set_tool_policy(tmp_path, "agent", "Bash", "deny", agent="codex")
    assert "Bash" in agents.resolve_agent_control("codex", tmp_path).deny_tools
    # other agents unaffected
    assert "Bash" not in agents.resolve_agent_control("claude", tmp_path).deny_tools
    # allow lifts it
    agents.set_tool_policy(tmp_path, "agent", "Bash", "allow", agent="codex")
    assert "Bash" not in agents.resolve_agent_control("codex", tmp_path).deny_tools


def test_set_tool_policy_global_applies_to_all(tmp_path):
    agents.set_tool_policy(tmp_path, "global", "mcp__node_repl__js", "deny")
    for name in ("claude", "codex", "never-registered"):
        assert "mcp__node_repl__js" in agents.resolve_agent_control(name, tmp_path).deny_tools
    agents.set_tool_policy(tmp_path, "global", "mcp__node_repl__js", "allow")
    assert "mcp__node_repl__js" not in agents.resolve_agent_control("claude", tmp_path).deny_tools


def test_agent_tool_deny_blocks_via_evaluate_tool_call(tmp_path, monkeypatch):
    """Denying a tool for one agent blocks that tool even in observe mode."""
    from prismor.runtime import runtime
    from prismor.runtime.policy_engine import PolicyEngine
    real_init = PolicyEngine.__init__
    def fake_init(self, *a, **kw):
        real_init(self, *a, **kw)
    monkeypatch.setattr(PolicyEngine, "__init__", fake_init)

    agents.set_tool_policy(tmp_path, "agent", "Bash", "deny", agent="codex")
    d = runtime.evaluate_tool_call(
        event={"type": "shell", "agent_event": "PreToolUse", "command": "echo hi",
               "metadata": {"tool_name": "Bash"}},
        workspace=tmp_path, agent="codex", agent_name="codex",
        mode="observe", session_id="s1", persist=False,
    )
    assert d.allow is False
    assert any(f.get("ruleId") == "agent-tool-deny" for f in d.findings)
    # a different tool from the same agent is still allowed
    d2 = runtime.evaluate_tool_call(
        event={"type": "file_read", "agent_event": "PreToolUse", "path": "x.py",
               "metadata": {"tool_name": "Read"}},
        workspace=tmp_path, agent="codex", agent_name="codex",
        mode="observe", session_id="s1", persist=False,
    )
    assert d2.allow is True


def test_global_tool_deny_blocks_unregistered_agent(tmp_path):
    from prismor.runtime import runtime
    agents.set_tool_policy(tmp_path, "global", "mcp__node_repl__js", "deny")
    d = runtime.evaluate_tool_call(
        event={"type": "tool_result", "agent_event": "PreToolUse", "response": "{}",
               "metadata": {"tool_name": "mcp__node_repl__js"}},
        workspace=tmp_path, agent="cursor", agent_name="cursor",
        mode="observe", session_id="s1", persist=False,
    )
    assert d.allow is False
    assert any(f.get("ruleId") == "agent-tool-deny" for f in d.findings)


def test_org_observe_pin_suppression_is_visible(tmp_path, monkeypatch, capsys):
    """#256: an org per-agent observe pin outranks --mode enforce. The block is
    still dropped, but stderr and the audit verdict must say it was suppressed
    instead of looking like an ordinary warn."""
    from prismor.runtime import runtime
    from prismor.runtime.enterprise.audit_trail import _verdict
    from prismor.runtime.policy_engine import PolicyEngine

    real_init = PolicyEngine.__init__

    def fake_init(self, *a, **kw):
        real_init(self, *a, **kw)
        self.workspace_managed = True
        self.agent_controls = {"checkout-bot": {"mode": "observe"}}

    monkeypatch.setattr(PolicyEngine, "__init__", fake_init)
    event = {"type": "shell", "agent_event": "PreToolUse", "command": "rm -rf ~/",
             "metadata": {"tool_name": "Bash"}}

    blocked = runtime.evaluate_tool_call(
        event=dict(event), workspace=tmp_path, agent="openai-agents", agent_name="other-bot",
        mode="enforce", session_id="s3", persist=False,
    )
    assert blocked.allow is False  # sanity: this command blocks without the pin
    capsys.readouterr()

    d = runtime.evaluate_tool_call(
        event=dict(event), workspace=tmp_path, agent="openai-agents", agent_name="checkout-bot",
        mode="enforce", session_id="s4", persist=False,
    )
    assert d.allow is True
    assert any("checkout-bot" in (f.get("suppressedBy") or "") for f in d.findings)
    assert "suppressed by org per-agent control 'checkout-bot'" in capsys.readouterr().err
    assert _verdict(d.findings, d.blocking) == "suppressed"
