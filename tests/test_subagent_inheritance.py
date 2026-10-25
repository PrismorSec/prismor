"""A subagent runs on its parent's authority: the parent's per-agent controls
(pause, mode, denied/asked tools, IAM profile, org agent-scoped denies) apply
on top of the subagent's own, and nothing set for the subagent loosens them."""
from __future__ import annotations

import pytest

from prismor.runtime import agents, runtime
from prismor.runtime.agents import AgentControl, inherit_control
from prismor.runtime.policy_engine import PolicyEngine
from prismor.runtime.subagent_context import running


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / ".prismor"))
    agents._CONFIG_CACHE.clear()
    yield


def _call(ws, *, agent_name="researcher", tool="fetch_url", parent="support-bot", sub=True, mode="observe"):
    meta = {"tool_name": tool}
    if sub:
        meta.update(subagent_id="researcher:c1", subagent_type="researcher")
        if parent:
            meta["parent_agent_name"] = parent
    return runtime.evaluate_tool_call(
        event={"type": "shell", "agent_event": "PreToolUse", "command": "https://x.test", "metadata": meta},
        workspace=ws, agent="openai-agents", agent_name=agent_name,
        mode=mode, session_id="s1", persist=False,
    )


def _rules(d):
    return {f.get("ruleId") for f in d.findings}


# ── the merge ────────────────────────────────────────────────────────────────

def test_merge_only_tightens():
    child = AgentControl(name="researcher", mode="observe", org_mode="observe",
                         deny_tools=("a",), ask_tools=("b", "c"), iam_profile="reader")
    parent = AgentControl(name="support-bot", enabled=False, mode="enforce",
                          deny_tools=("c",), ask_tools=("d",), iam_profile="ops")
    m = inherit_control(child, parent)
    assert m.enabled is False and m.disabled_by == "parent agent support-bot"
    assert m.mode == "enforce"
    assert m.org_mode is None                 # the subagent's org observe does not survive
    assert m.deny_tools == ("a", "c")
    assert m.ask_tools == ("b", "d")          # c is denied, so not merely asked
    assert m.iam_profile == "reader" and m.parent_iam_profiles == ("ops",)


def test_observe_survives_only_when_both_agree():
    obs = AgentControl(name="x", mode="observe", org_mode="observe")
    inherit = AgentControl(name="p")           # parent follows the global mode
    assert inherit_control(obs, inherit).mode is None
    assert inherit_control(obs, inherit).org_mode is None
    assert inherit_control(obs, AgentControl(name="p", mode="observe", org_mode="observe")).mode == "observe"


def test_profiles_accumulate_down_a_chain():
    grand = AgentControl(name="g", iam_profile="g-prof")
    mid = inherit_control(AgentControl(name="m", iam_profile="m-prof"), grand)
    leaf = inherit_control(AgentControl(name="l"), mid)
    assert set(leaf.parent_iam_profiles) == {"m-prof", "g-prof"}


# ── end to end through evaluate_tool_call ───────────────────────────────────

def test_paused_parent_stops_its_subagent(tmp_path):
    agents.upsert_agent("support-bot", tmp_path, framework="openai-agents", enabled=False)
    d = _call(tmp_path)
    assert d.allow is False and "agent-disabled" in _rules(d)
    disabled = next(f for f in d.findings if f["ruleId"] == "agent-disabled")
    assert "subagent of 'support-bot'" in disabled["evidence"]
    # The same agent outside the parent (not a subagent call) is not paused.
    assert "agent-disabled" not in _rules(_call(tmp_path, sub=False))


def test_parent_tool_deny_applies_to_subagent(tmp_path):
    agents.set_tool_policy(tmp_path, "agent", "fetch_url", "deny", agent="support-bot")
    assert _call(tmp_path).allow is False
    assert "agent-tool-deny" in _rules(_call(tmp_path))
    assert _call(tmp_path, sub=False).allow is True


def test_subagent_own_enabled_row_cannot_undo_parent_pause(tmp_path):
    agents.upsert_agent("support-bot", tmp_path, framework="openai-agents", enabled=False)
    agents.upsert_agent("researcher", tmp_path, framework="openai-agents", enabled=True)
    assert _call(tmp_path).allow is False


def test_parent_found_from_running_tool_when_not_named(tmp_path):
    """Adapters using subagent_context need not name the parent: the agent
    whose guarded tool is running is it."""
    agents.upsert_agent("support-bot", tmp_path, framework="openai-agents", enabled=False)
    with running("support-bot", "c1"):
        d = _call(tmp_path, parent=None)
    assert d.allow is False and "agent-disabled" in _rules(d)
    assert _call(tmp_path, parent=None).allow is True   # no running parent, nothing inherited


def test_same_name_is_not_its_own_parent(tmp_path):
    agents.upsert_agent("support-bot", tmp_path, framework="openai-agents", enabled=True)
    d = _call(tmp_path, agent_name="support-bot", parent="support-bot")
    assert d.allow is True


def test_org_pause_and_agent_scoped_deny_reach_the_subagent(tmp_path, monkeypatch):
    real_init = PolicyEngine.__init__

    def managed(self, *a, **kw):
        real_init(self, *a, **kw)
        self.workspace_managed = True
        self.agent_controls = {"support-bot": {"enabled": False}}

    monkeypatch.setattr(PolicyEngine, "__init__", managed)
    d = _call(tmp_path)
    assert d.allow is False and "agent-disabled" in _rules(d)


def test_subagent_scoped_org_allow_cannot_lift_parent_deny(tmp_path, monkeypatch):
    """An org allow scoped to the subagent's own name does not lift a deny
    its parent carries; the parent's allow does."""
    agents.set_tool_policy(tmp_path, "agent", "fetch_url", "deny", agent="support-bot")
    real_init = PolicyEngine.__init__
    allow_for = {"who": "researcher"}

    def with_allow(self, *a, **kw):
        real_init(self, *a, **kw)
        self.tool_denies = [{"tool": "fetch_url", "action": "allow", "scope": "agent", "scopeId": allow_for["who"]}]

    monkeypatch.setattr(PolicyEngine, "__init__", with_allow)
    assert _call(tmp_path).allow is False
    allow_for["who"] = "support-bot"
    assert _call(tmp_path).allow is True


def test_parent_iam_profile_applies_to_subagent(tmp_path):
    iam_dir = tmp_path / ".prismor"
    iam_dir.mkdir(parents=True, exist_ok=True)
    (iam_dir / "iam.yaml").write_text(
        "agents:\n"
        "  ops:\n"
        "    deny_tools: [fetch_url]\n"
        "    allowed_paths: ['**']\n", encoding="utf-8")
    agents.upsert_agent("support-bot", tmp_path, framework="openai-agents", iam_profile="ops")
    # IAM findings follow the mode (unlike pause / tool deny), so enforce here.
    d = _call(tmp_path, mode="enforce")
    assert d.allow is False and any(str(r).startswith("iam") for r in _rules(d))
    assert not any(str(r).startswith("iam") for r in _rules(_call(tmp_path, sub=False, mode="enforce")))


def test_project_registration_does_not_drop_global_controls(tmp_path):
    """Auto-registration writes framework/last_seen into the project
    agents.yaml; that entry used to replace the global one wholesale, so a
    global pause or deny list vanished once the agent ran in a repo."""
    home = tmp_path / ".prismor"            # PRISMOR_HOME: the global file
    home.mkdir(parents=True, exist_ok=True)
    (home / "agents.yaml").write_text(
        "agents:\n  support-bot:\n    enabled: false\n    deny_tools: [lookup]\n"
        "global_deny_tools: [rm]\n", encoding="utf-8")
    repo = tmp_path / "repo"                # a project with its own agents.yaml
    repo.mkdir()
    agents.upsert_agent("support-bot", repo, framework="agno", last_seen="now",
                        deny_tools=["shell"])
    project = repo / ".prismor" / "agents.yaml"
    project.write_text(project.read_text() + "global_deny_tools: [curl]\n")
    agents._CONFIG_CACHE.clear()
    ctl = agents.resolve_agent_control("support-bot", repo)
    assert ctl.enabled is False
    assert set(ctl.deny_tools) >= {"lookup", "shell", "rm", "curl"}
