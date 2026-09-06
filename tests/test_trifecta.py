"""Tool-combination governance — unit + end-to-end tests (customizable tags).

Covers the tagging + per-session ledger (prismor.runtime.trifecta) and the
forbidden-combination enforcement wired into PolicyEngine.evaluate.
"""
import uuid
from pathlib import Path

import pytest

from prismor.runtime.trifecta import (
    UNTRUSTED, CRITICAL, classify_tool_tags, TagLedger, normalize_incompatible,
    TOOL_TAG_DEFAULTS, tool_tags_for_agent,
)
from prismor.runtime.runtime import evaluate_tool_call
from prismor.runtime.policy_engine import (
    _NON_OVERRIDABLE_RULE_IDS, _CORE_BLOCK_CATEGORIES,
)


def _ev(tool, etype, **extra):
    e = {"type": etype, "agent_event": "PreToolUse", "metadata": {"tool_name": tool}}
    e.update(extra)
    return e


# ── tagging ───────────────────────────────────────────────────────────────────

def test_explicit_tags_win_and_support_lists():
    tt = {"tags": {"mcp__Custom__x": ["private_data", "external_comms"]}}
    assert classify_tool_tags(_ev("mcp__Custom__x", "tool_result"), "tool_result", set(), tt) == \
        {"private_data", "external_comms"}


def test_glob_tag_mapping():
    tt = {"tags": {"mcp__*__read_customers": "private_data"}}
    assert classify_tool_tags(_ev("mcp__crm__read_customers", "tool_result"), "tool_result", set(), tt) == \
        {"private_data"}


def test_builtin_defaults():
    assert classify_tool_tags(_ev("WebFetch", "network"), "network", set(), {}) == {UNTRUSTED}
    assert classify_tool_tags(_ev("mcp__Gmail__send_email", "network"), "network", set(), {}) == {CRITICAL}


def test_inference_fallback():
    tt = {"defaults_enabled": False}
    assert classify_tool_tags(_ev("w", "file_write"), "file_write", set(), tt) == {CRITICAL}
    assert classify_tool_tags(_ev("mcp__crm__x", "tool_result"), "tool_result", set(), tt) == {UNTRUSTED}
    assert classify_tool_tags(_ev("x", "shell"), "shell", {"destructive_command"}, tt) == {CRITICAL}


def test_local_unmapped_tool_result_is_not_untrusted():
    """Grep/Glob/Task reach policy as `tool_result` (hooks._unmapped_tool_event).

    Tagging those untrusted made the first search in a session complete
    `untrusted_content then critical_action` on the next shell call.
    """
    tt = {"defaults_enabled": False}
    assert classify_tool_tags(_ev("Grep", "tool_result"), "tool_result", set(), tt) == set()
    assert classify_tool_tags(_ev("Glob", "tool_result"), "tool_result", set(), tt) == set()
    # An MCP result over the same event type still carries the tag.
    ev = _ev("anything", "tool_result", mcp_server="crm")
    assert classify_tool_tags(ev, "tool_result", set(), tt) == {UNTRUSTED}


def test_workspace_read_is_trusted_but_outside_read_is_not(tmp_path):
    """The read-then-anything cliff: a workspace read must not taint a session."""
    tt = {"defaults_enabled": False}
    (tmp_path / "src").mkdir()
    inside = tmp_path / "src" / "app.py"
    inside.write_text("x = 1")

    ev_in = _ev("Read", "file_read", path=str(inside))
    assert classify_tool_tags(ev_in, "file_read", set(), tt, workspace=tmp_path) == set()

    ev_out = _ev("Read", "file_read", path=str(Path.home() / ".ssh" / "id_rsa"))
    assert classify_tool_tags(ev_out, "file_read", set(), tt, workspace=tmp_path) == {UNTRUSTED}

    # Relative paths resolve against the workspace, so they stay trusted.
    ev_rel = _ev("Read", "file_read", path="src/app.py")
    assert classify_tool_tags(ev_rel, "file_read", set(), tt, workspace=tmp_path) == set()

    # Traversal out of the workspace is external even when written relatively.
    ev_esc = _ev("Read", "file_read", path="../../etc/passwd")
    assert classify_tool_tags(ev_esc, "file_read", set(), tt, workspace=tmp_path) == {UNTRUSTED}

    # No workspace to resolve against -> not external (never re-arm the cliff).
    assert classify_tool_tags(ev_out, "file_read", set(), tt) == set()

    # A sibling directory sharing a name prefix is outside, not inside.
    sibling = tmp_path.parent / (tmp_path.name + "-other")
    sibling.mkdir()
    (sibling / "notes.md").write_text("hi")
    ev_sib = _ev("Read", "file_read", path=str(sibling / "notes.md"))
    assert classify_tool_tags(ev_sib, "file_read", set(), tt, workspace=tmp_path) == {UNTRUSTED}

    # A symlink inside the workspace pointing out of it is external: both sides
    # resolve, so the link target is what gets classified.
    link = tmp_path / "escape.py"
    try:
        link.symlink_to(Path("/etc/hosts"))
    except (OSError, NotImplementedError):
        return
    ev_link = _ev("Read", "file_read", path=str(link))
    assert classify_tool_tags(ev_link, "file_read", set(), tt, workspace=tmp_path) == {UNTRUSTED}


def test_webfetch_stays_untrusted_after_the_narrowing():
    """The narrowing must not cost the tools the trifecta rule exists for."""
    assert classify_tool_tags(_ev("WebFetch", "tool_result"), "tool_result", set(), {}) == {UNTRUSTED}
    assert classify_tool_tags(_ev("WebSearch", "tool_result"), "tool_result", set(), {}) == {UNTRUSTED}


def test_neutral_returns_empty():
    tt = {"defaults_enabled": False, "inference_enabled": False}
    assert classify_tool_tags(_ev("mystery", "prompt"), "prompt", set(), tt) == set()


def test_defaults_and_normalize_incompatible():
    for _, _, tags in TOOL_TAG_DEFAULTS:
        assert tags and all(isinstance(t, str) for t in tags)
    # unset -> default red/blue pair; single-tag "sets" dropped
    assert normalize_incompatible(None) == [{UNTRUSTED, CRITICAL}]
    assert normalize_incompatible([["a"]]) == [{UNTRUSTED, CRITICAL}]
    assert normalize_incompatible([["a", "b"], ["c", "d", "e"]]) == [{"a", "b"}, {"c", "d", "e"}]


# ── ledger ────────────────────────────────────────────────────────────────────

def test_ledger_completes_two_tag(tmp_path):
    sid = "s-" + uuid.uuid4().hex
    led = TagLedger(tmp_path, sid)
    rules = [{"a", "b"}]
    assert led.completes({"a"}, rules, 0) is None        # only 1 of 2 present
    led.record({"a"}, 0, "toolA")
    done = led.completes({"b"}, rules, 1)                 # 2nd call (index 1) completes it
    assert done and done["set"] == ["a", "b"] and done["this_call_tags"] == ["b"]
    assert done["introduced_by"]["a"]["tool"] == "toolA"


def test_ledger_completes_three_tag_and_persists(tmp_path):
    sid = "s-" + uuid.uuid4().hex
    rules = [{"a", "b", "c"}]
    led = TagLedger(tmp_path, sid)
    led.record({"a"}, 0, "tA"); led.record({"b"}, 1, "tB")
    # a fresh instance reloads state (separate process in real use)
    led2 = TagLedger(tmp_path, sid)
    assert led2.completes({"a"}, rules, 2) is None        # 'a' already prior, no new completion
    assert led2.completes({"c"}, rules, 2)["set"] == ["a", "b", "c"]  # 'c' (index 2) completes the trio


def test_completes_ignores_current_index_rerecord(tmp_path):
    # The current call's tag may already be recorded at current_index (pre-pass) —
    # it must still count as new, not "already seen".
    sid = "s-" + uuid.uuid4().hex
    led = TagLedger(tmp_path, sid)
    led.record({"a"}, 0, "tA")
    led.record({"b"}, 1, "tB")            # simulate pre-pass recording current call's tag
    done = led.completes({"b"}, [{"a", "b"}], 1)  # authoritative pass, same index 1
    assert done and done["set"] == ["a", "b"]


# ── end-to-end enforcement ────────────────────────────────────────────────────

def _workspace(tmp_path, mode, tags=None, incompatible=None):
    import yaml
    ws = tmp_path / f"ws-{mode}-{uuid.uuid4().hex[:6]}"
    (ws / ".prismor").mkdir(parents=True)
    policy = {"version": "1.0", "settings": {"tool_tags": {
        "enabled": True, "mode": mode,
        "tags": tags or {"mcp__Gmail__read_email": ["untrusted_content"],
                         "mcp__Gmail__send_email": ["critical_action"]},
        "incompatible": incompatible or [["untrusted_content", "critical_action"]],
    }}}
    (ws / ".prismor" / "policy.yaml").write_text(yaml.safe_dump(policy))
    return ws


@pytest.fixture(autouse=True)
def _isolate_home(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / "home"))


def _call(ws, sid, tool, etype="network"):
    return evaluate_tool_call(event=_ev(tool, etype), workspace=ws, agent="claude",
                              mode="enforce", session_id=sid, persist=True)


def test_combination_blocks_in_enforce(tmp_path):
    ws = _workspace(tmp_path, "enforce")
    sid = "s-" + uuid.uuid4().hex
    assert _call(ws, sid, "mcp__Gmail__read_email", "tool_result").allow is True
    d = _call(ws, sid, "mcp__Gmail__send_email", "network")
    assert d.allow is False and d.blocking["category"] == "lethal_trifecta"


def test_all_untrusted_allowed(tmp_path):
    ws = _workspace(tmp_path, "enforce")
    sid = "s-" + uuid.uuid4().hex
    assert _call(ws, sid, "mcp__Gmail__read_email", "tool_result").allow is True
    assert _call(ws, sid, "WebFetch", "network").allow is True


def test_three_tag_rule_blocks_on_completion(tmp_path):
    tags = {"mcp__web__fetch": ["untrusted_content"],
            "mcp__crm__read": ["private_data"],
            "mcp__x__post": ["external_comms"]}
    rule = [["untrusted_content", "private_data", "external_comms"]]
    ws = _workspace(tmp_path, "enforce", tags=tags, incompatible=rule)
    sid = "s-" + uuid.uuid4().hex
    assert _call(ws, sid, "mcp__web__fetch", "tool_result").allow is True   # 1/3
    assert _call(ws, sid, "mcp__crm__read", "tool_result").allow is True    # 2/3
    d = _call(ws, sid, "mcp__x__post", "network")                           # 3/3 completes
    assert d.allow is False and d.blocking["category"] == "lethal_trifecta"


def test_observe_logs_but_does_not_block(tmp_path):
    ws = _workspace(tmp_path, "observe")
    sid = "s-" + uuid.uuid4().hex
    _call(ws, sid, "mcp__Gmail__read_email", "tool_result")
    d = _call(ws, sid, "mcp__Gmail__send_email", "network")
    assert d.allow is True
    assert any(f.get("category") == "lethal_trifecta" for f in d.findings)


def test_floor_protected():
    assert "tool-category-crossover" in _NON_OVERRIDABLE_RULE_IDS
    assert "lethal_trifecta" in _CORE_BLOCK_CATEGORIES


# ── regression: a blocked call must not poison the ledger ────────────────────
# One denied critical call used to record its tags, marking the forbidden set
# "already complete" — so every LATER critical call sailed through
# (completes() exempted fully-seen sets). Found live-testing the MCP gateway.

def test_blocked_call_does_not_poison_ledger(tmp_path):
    ws = _workspace(tmp_path, "enforce")
    sid = "s-" + uuid.uuid4().hex
    assert _call(ws, sid, "mcp__Gmail__read_email", "tool_result").allow is True
    assert _call(ws, sid, "mcp__Gmail__send_email", "network").allow is False
    # The denied call's critical_action tag must not be in the ledger...
    ledger = TagLedger(ws, sid)
    assert CRITICAL not in ledger.seen
    # ...and a SECOND critical call is still blocked, not waved through.
    d = _call(ws, sid, "mcp__Gmail__send_email", "network")
    assert d.allow is False and d.blocking["category"] == "lethal_trifecta"


def test_completed_set_stays_restricted(tmp_path):
    # A single dual-tagged call completes the set alone and executes in
    # observe... simulate a ledger that already holds the full set: every
    # subsequent call carrying a set tag must still fire, not slip through.
    ws = _workspace(tmp_path, "observe")
    sid = "s-" + uuid.uuid4().hex
    _call(ws, sid, "mcp__Gmail__read_email", "tool_result")
    _call(ws, sid, "mcp__Gmail__send_email", "network")  # observed, recorded
    ledger = TagLedger(ws, sid)
    assert UNTRUSTED in ledger.seen and CRITICAL in ledger.seen
    d = _call(ws, sid, "mcp__Gmail__send_email", "network")
    assert any(f.get("category") == "lethal_trifecta" for f in d.findings)


# ── per-agent overlays (a policy attached to one agent) ───────────────────────
#
# A policy attached to an agent in the control plane ships as
# settings.tool_tags.agents[<name>], mirroring settings.egress.agents. The
# invariant worth pinning is that it can only ever TIGHTEN: an agent's name
# arrives in the event, asserted by its own process, so a permissive overlay
# would let a compromised agent name itself out of the fleet's policy.

def _base_tt():
    return {
        "enabled": True,
        "mode": "observe",
        "tags": {"WebFetch": ["untrusted_content"]},
        "rules": [{"expr": "untrusted_content then critical_action", "action": "block"}],
        "agents": {
            "scraper": {
                "mode": "enforce",
                "tags": {"Bash": ["critical_action"]},
                "rules": [{"expr": "private_data with external_comms", "action": "block"}],
            }
        },
    }


def test_overlay_untouched_for_other_agents():
    tt = _base_tt()
    for name in ("", "some-other-agent"):
        got = tool_tags_for_agent(tt, name)
        assert got["mode"] == "observe"
        assert sorted(got["tags"]) == ["WebFetch"]
        assert len(got["rules"]) == 1


def test_overlay_adds_tags_rules_and_escalates_mode():
    got = tool_tags_for_agent(_base_tt(), "scraper")
    assert got["mode"] == "enforce"
    assert sorted(got["tags"]) == ["Bash", "WebFetch"]
    assert len(got["rules"]) == 2


def test_overlay_cannot_lower_the_mode():
    tt = _base_tt()
    tt["mode"] = "enforce"
    tt["agents"] = {"scraper": {"mode": "observe"}}
    assert tool_tags_for_agent(tt, "scraper")["mode"] == "enforce"


def test_overlay_cannot_remove_a_tag():
    tt = _base_tt()
    tt["agents"] = {"scraper": {"tags": {"WebFetch": []}}}
    assert tool_tags_for_agent(tt, "scraper")["tags"]["WebFetch"] == ["untrusted_content"]


def test_overlay_cannot_drop_a_rule():
    tt = _base_tt()
    tt["agents"] = {"scraper": {"rules": []}}
    assert len(tool_tags_for_agent(tt, "scraper")["rules"]) == 1


def test_overlay_unions_tags_for_the_same_tool():
    tt = _base_tt()
    tt["agents"] = {"scraper": {"tags": {"WebFetch": ["private_data"]}}}
    assert tool_tags_for_agent(tt, "scraper")["tags"]["WebFetch"] == [
        "private_data", "untrusted_content",
    ]


def test_malformed_overlay_is_ignored_not_fatal():
    for agents in (None, [], "nope", {"scraper": "nope"}, {"scraper": {}}):
        tt = _base_tt()
        tt["agents"] = agents
        got = tool_tags_for_agent(tt, "scraper")
        assert got["mode"] == "observe"
        assert sorted(got["tags"]) == ["WebFetch"]


def _validate(tmp_path, tool_tags):
    """Lint a minimally-valid policy carrying this settings.tool_tags block."""
    import yaml
    from prismor.runtime.policy_engine import validate_policy
    f = tmp_path / "policy.yaml"
    f.write_text(yaml.safe_dump({"version": "1.0", "rules": [], "settings": {"tool_tags": tool_tags}}))
    return validate_policy(f)


def test_lint_walks_agent_overlays(tmp_path):
    # A broken rule hidden inside an overlay is exactly as broken as one in the
    # fleet block, and much easier to miss.
    errs = _validate(tmp_path, {
        "agents": {
            "scraper": {
                "mode": "sometimes",
                "rules": ["untrusted_content then then"],
                "incompatible": [["only_one"]],
            }
        }
    })
    joined = "\n".join(errs)
    assert "settings.tool_tags.agents.scraper.mode" in joined
    assert "settings.tool_tags.agents.scraper.rules[0]" in joined
    assert "settings.tool_tags.agents.scraper.incompatible[0]" in joined


def test_lint_rejects_a_non_map_agents_block(tmp_path):
    errs = _validate(tmp_path, {"agents": ["nope"]})
    assert any("settings.tool_tags.agents" in e for e in errs)


def test_lint_accepts_a_valid_overlay(tmp_path):
    errs = _validate(tmp_path, {
        "agents": {
            "scraper": {
                "mode": "enforce",
                "rules": ["untrusted_content then critical_action"],
                "incompatible": [["private_data", "external_comms"]],
            }
        }
    })
    assert [e for e in errs if "tool_tags" in e] == []
