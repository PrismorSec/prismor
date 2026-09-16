"""A machine-synthesized capability scope must not hard-block (issue #257).

`scoped-agent` was the largest single source of blocks on both agent paths
measured, and the only measured cause of blocking a *legitimate* action: in
enforce mode the no-injection utility control fell from 100% to 33.3% success.

The signal for a synthesized scope is "the synthesizer did not anticipate this
tool", not "this call is hostile". Those escalate, and degrade to a warning
where nothing can ask a human. An operator-authored denial still hard-blocks.
"""
from prismor.runtime.scoped_agent import _scoped_finding, check_scoped_rules

BASH_EVENT = {
    "type": "shell",
    "agent_event": "PreToolUse",
    "command": "touch ./marker",
    "metadata": {"tool_name": "Bash"},
}


# ── the finding itself ────────────────────────────────────────────────────

def test_synthesized_scope_escalates_rather_than_blocks():
    f = _scoped_finding("s1", "Tool 'Bash' is not in scope", "shell", synthesized=True)
    assert f["action"] == "step_up"
    assert f["softFailOpen"] is True
    assert f["scopeSource"] == "synthesized"
    assert f["severity"] == "MEDIUM"


def test_operator_scope_still_hard_blocks():
    f = _scoped_finding("s1", "Tool 'Bash' is explicitly denied", "shell", synthesized=False)
    assert f["action"] == "block"
    assert f["softFailOpen"] is False
    assert f["scopeSource"] == "operator"
    assert f["severity"] == "HIGH"


def test_default_is_the_strict_behaviour():
    """Provenance must be opt-in: anything not marked synthesized keeps blocking."""
    f = _scoped_finding("s1", "denied", "shell")
    assert f["action"] == "block"
    assert f["softFailOpen"] is False


# ── provenance threading through check_scoped_rules ───────────────────────

def test_synthesized_rules_produce_a_soft_finding():
    rules = {"source": "synthesized", "allowed_tools": ["Read"], "deny_tools": ["Bash"]}
    f = check_scoped_rules(rules, BASH_EVENT, session_id="s1")
    assert f is not None
    assert f["action"] == "step_up"
    assert f["softFailOpen"] is True


def test_operator_rules_produce_a_hard_finding():
    rules = {"source": "operator", "allowed_tools": ["Read"], "deny_tools": ["Bash"]}
    f = check_scoped_rules(rules, BASH_EVENT, session_id="s1")
    assert f is not None
    assert f["action"] == "block"
    assert f["softFailOpen"] is False


def test_legacy_rules_without_source_keep_blocking():
    """Scopes written before provenance existed must not silently soften."""
    rules = {"allowed_tools": ["Read"], "deny_tools": ["Bash"]}
    f = check_scoped_rules(rules, BASH_EVENT, session_id="s1")
    assert f is not None
    assert f["action"] == "block"


def test_allowed_tool_is_still_allowed():
    rules = {"source": "synthesized", "allowed_tools": ["Bash"], "deny_tools": []}
    assert check_scoped_rules(rules, BASH_EVENT, session_id="s1") is None


def test_paused_scope_never_fires():
    rules = {"source": "synthesized", "paused": True,
             "allowed_tools": ["Read"], "deny_tools": ["Bash"]}
    assert check_scoped_rules(rules, BASH_EVENT, session_id="s1") is None


# ── synthesis stamps provenance ───────────────────────────────────────────

def test_static_fallback_marks_itself_synthesized():
    from prismor.runtime.scoped_agent import _static_fallback_rules

    rules = _static_fallback_rules("add a docstring to utils.py", ["Bash", "Read", "Edit"])
    assert rules.get("source") == "synthesized", (
        "a predicted scope must declare itself, or it inherits operator-strength enforcement"
    )


# ── the utility-control regression, end to end ────────────────────────────

def test_synthesized_miss_does_not_block_a_legitimate_call(tmp_path, monkeypatch, capsys):
    """The measured failure: a legitimate request denied because the synthesized
    scope omitted Bash. It must now proceed, with a warning."""
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / ".prismor"))
    from prismor.runtime import agents, scoped_agent

    agents._CONFIG_CACHE.clear()
    scoped_agent.save_scoped_rules(
        tmp_path, "sess-util",
        {"source": "synthesized", "allowed_tools": ["Read"], "deny_tools": ["Bash"]},
    )
    rules = scoped_agent.load_scoped_rules(tmp_path, "sess-util")
    finding = check_scoped_rules(rules, BASH_EVENT, session_id="sess-util")

    # It is still reported — the operator should see the scope was wrong …
    assert finding is not None
    # … but it must not be a hard denial on a surface with no human to ask.
    assert finding["action"] == "step_up"
    assert finding["softFailOpen"] is True
