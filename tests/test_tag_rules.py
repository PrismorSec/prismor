"""Tag-rule DSL — parser, IR, legacy compile parity, and ordered-ledger tests."""
import json
import re
import uuid

import pytest

from prismor.runtime.tag_rules import (
    CompiledRule, ParseError, compile_rule, compile_tool_tag_rules, lint_rules,
)
from prismor.runtime.trifecta import UNTRUSTED, CRITICAL, INFLUENCE, TagLedger


# ── parser: valid expressions ─────────────────────────────────────────────────

def test_with_rule_parses():
    r = compile_rule("untrusted_content with critical_action -> block")
    assert r.steps == [{UNTRUSTED, CRITICAL}]
    assert r.action == "block" and not r.ordered


def test_then_rule_parses():
    r = compile_rule("untrusted_content then critical_action -> block")
    assert r.steps == [{UNTRUSTED}, {CRITICAL}]
    assert r.ordered


def test_three_step_rule():
    r = compile_rule("untrusted_content then private_data then external_comms -> block")
    assert r.steps == [{"untrusted_content"}, {"private_data"}, {"external_comms"}]


def test_warn_action():
    assert compile_rule("web_read with secrets_access -> warn").action == "warn"


def test_mixed_with_then_parses():
    r = compile_rule("untrusted_content with private_data then external_comms -> block")
    assert r.steps == [{"untrusted_content", "private_data"}, {"external_comms"}]


def test_implicit_block_action():
    r = compile_rule("customer_pii then external_comms")
    assert r.action == "block"


def test_extra_whitespace_ok():
    r = compile_rule("  a_tag   then    b_tag  ->  warn ")
    assert r.steps == [{"a_tag"}, {"b_tag"}] and r.action == "warn"


def test_rule_id_stable_and_order_insensitive_within_step():
    a = compile_rule("x with y -> block")
    b = compile_rule("y with x -> block")
    assert a.rule_id == b.rule_id  # normalized form sorts within a step
    c = compile_rule("x then y -> block")
    assert c.rule_id != a.rule_id  # ordered is a different rule


# ── parser: invalid expressions ───────────────────────────────────────────────

@pytest.mark.parametrize("expr", [
    "",                                   # empty
    "   ",                                # whitespace only
    "just_one_tag",                       # single tag can't be a combination
    "a then",                             # dangling connector
    "a with -> block",                    # connector then arrow
    "then a",                             # leading connector
    "a b",                                # two terms w/o connector
    "a then b -> explode",                # unknown action
    "a -> block then b",                  # arrow not at end
    "a then b ->",                        # arrow without action
    "A_Tag then b",                       # uppercase not in charset
    "_lead then b",                       # bad leading char
])
def test_invalid_rules_raise(expr):
    with pytest.raises(ParseError):
        compile_rule(expr)


@pytest.mark.parametrize("kw", ["not", "or", "within", "count"])
def test_reserved_keywords_rejected(kw):
    with pytest.raises(ParseError) as ei:
        compile_rule(f"a then {kw} b")
    assert "reserved" in str(ei.value)


def test_parse_error_caret_position():
    with pytest.raises(ParseError) as ei:
        compile_rule("a then b -> explode")
    err = ei.value
    assert err.pos == "a then b -> explode".index("explode")
    caret = err.caret()
    assert caret.splitlines()[1].index("^") == err.pos


def test_single_tag_multi_step_allowed():
    # "a then a" is two steps of one tag each — legal (needs 2 occurrences).
    r = compile_rule("a then a")
    assert r.steps == [{"a"}, {"a"}]


def test_lint_rules_collects_errors():
    errs = lint_rules(["a with b", "bad ->", "x then y -> warn", "not a"])
    assert len(errs) == 2
    assert errs[0][0] == "bad ->"


# ── compile_tool_tag_rules: backward compat funnel ────────────────────────────

def test_legacy_incompatible_compiles_to_single_step_block():
    tt = {"incompatible": [["a", "b"], ["c", "d", "e"]]}
    rules = compile_tool_tag_rules(tt)
    assert [r.steps for r in rules] == [[{"a", "b"}], [{"c", "d", "e"}]]
    assert all(r.action == "block" and r.source == "incompatible" for r in rules)


DEFAULT_STEPS = [
    [{CRITICAL, INFLUENCE}],          # block
    [{UNTRUSTED}, {CRITICAL}],        # warn
]


def test_legacy_single_tag_sets_dropped_like_normalize():
    tt = {"incompatible": [["a"]]}
    rules = compile_tool_tag_rules(tt)
    # drops <2-tag sets, then falls back to the shipped defaults
    assert [r.steps for r in rules] == DEFAULT_STEPS
    assert rules[0].source == "default"


def test_empty_settings_default_pair():
    """Declaring nothing blocks on influence and reports the bare sequence."""
    for rules in (compile_tool_tag_rules({}), compile_tool_tag_rules(None)):
        assert [r.steps for r in rules] == DEFAULT_STEPS
        assert [r.action for r in rules] == ["block", "warn"]


def test_rules_and_incompatible_merge():
    tt = {
        "rules": ["p then q -> warn"],
        "incompatible": [["a", "b"]],
    }
    rules = compile_tool_tag_rules(tt)
    assert len(rules) == 2
    assert rules[0].steps == [{"p"}, {"q"}] and rules[0].action == "warn"
    assert rules[1].steps == [{"a", "b"}] and rules[1].action == "block"


def test_rule_map_entries_and_action_override():
    tt = {"rules": [{"expr": "a with b", "action": "warn"}]}
    rules = compile_tool_tag_rules(tt)
    assert rules[0].action == "warn" and rules[0].steps == [{"a", "b"}]


def test_invalid_rule_entries_skipped_not_fatal():
    tt = {"rules": ["bad ->", 42, "a with b"], "incompatible": []}
    rules = compile_tool_tag_rules(tt)
    assert len(rules) == 1 and rules[0].steps == [{"a", "b"}]


# ── ledger: completes_rules (ordered semantics) ───────────────────────────────

def _led(tmp_path):
    return TagLedger(tmp_path, "s-" + uuid.uuid4().hex)


def test_single_step_rule_matches_legacy_completes(tmp_path):
    led = _led(tmp_path)
    rule = compile_rule("a with b")
    assert led.completes_rules({"a"}, [rule], 0) is None
    led.record({"a"}, 0, "tA")
    done = led.completes_rules({"b"}, [rule], 1)
    assert done and done["set"] == ["a", "b"] and done["this_call_tags"] == ["b"]
    assert done["introduced_by"]["a"]["tool"] == "tA"
    assert done["action"] == "block" and done["rule_id"] == rule.rule_id


def test_ordered_fires_only_in_order(tmp_path):
    rule = compile_rule("a then b")
    # b first, then a: the "a" call must NOT fire (b hasn't followed a)
    led = _led(tmp_path)
    led.record({"b"}, 0, "tB")
    assert led.completes_rules({"a"}, [rule], 1) is None
    # a first, then b: the "b" call fires
    led2 = _led(tmp_path)
    led2.record({"a"}, 0, "tA")
    done = led2.completes_rules({"b"}, [rule], 1)
    assert done and done["steps"] == [["a"], ["b"]]


def test_unordered_fires_either_order(tmp_path):
    rule = compile_rule("a with b")
    led = _led(tmp_path)
    led.record({"b"}, 0, "tB")
    assert led.completes_rules({"a"}, [rule], 1) is not None


def test_multi_step_b_a_b_c_case(tmp_path):
    # Session b(0), a(1), b(2): call c(3) completes "a then b then c" even
    # though first-seen(b) < first-seen(a). This is why hist exists.
    rule = compile_rule("a then b then c")
    led = _led(tmp_path)
    led.record({"b"}, 0, "t0")
    led.record({"a"}, 1, "t1")
    led.record({"b"}, 2, "t2")
    done = led.completes_rules({"c"}, [rule], 3)
    assert done and done["set"] == ["a", "b", "c"]


def test_multi_step_missing_middle_occurrence(tmp_path):
    # Session b(0), a(1): no b AFTER a, so "a then b then c" must not fire on c.
    rule = compile_rule("a then b then c")
    led = _led(tmp_path)
    led.record({"b"}, 0, "t0")
    led.record({"a"}, 1, "t1")
    assert led.completes_rules({"c"}, [rule], 2) is None


def test_mixed_with_then(tmp_path):
    rule = compile_rule("a with b then c")
    led = _led(tmp_path)
    led.record({"a"}, 0, "t0")
    assert led.completes_rules({"c"}, [rule], 1) is None  # b never occurred
    led.record({"b"}, 1, "t1")
    done = led.completes_rules({"c"}, [rule], 2)
    assert done and done["this_call_tags"] == ["c"]


def test_final_step_requires_this_call_contribution(tmp_path):
    # All tags already seen, but this call carries no final-step tag -> no fire.
    rule = compile_rule("a then b")
    led = _led(tmp_path)
    led.record({"a"}, 0, "t0")
    led.record({"b"}, 1, "t1")
    assert led.completes_rules({"x"}, [rule], 2) is None
    # ...but a call re-carrying the final tag keeps the session restricted.
    assert led.completes_rules({"b"}, [rule], 2) is not None


def test_rerecord_current_index_not_prior(tmp_path):
    # The pre-pass may have recorded this call's own tag at current_index; it
    # must count as new, not prior (mirrors legacy completes contract).
    rule = compile_rule("a then b")
    led = _led(tmp_path)
    led.record({"a"}, 0, "t0")
    led.record({"b"}, 1, "t1")  # pre-pass re-record of the current call
    done = led.completes_rules({"b"}, [rule], 1)
    assert done is not None
    # And b's prior occurrence alone (at idx>=current) can't satisfy "a then b"
    led2 = _led(tmp_path)
    led2.record({"b"}, 0, "t0")
    assert led2.completes_rules({"b"}, [compile_rule("a then b")], 0) is None


def test_same_tag_two_steps_needs_two_occurrences(tmp_path):
    rule = compile_rule("a then a")
    led = _led(tmp_path)
    assert led.completes_rules({"a"}, [rule], 0) is None  # first occurrence only
    led.record({"a"}, 0, "t0")
    assert led.completes_rules({"a"}, [rule], 1) is not None


def test_block_preferred_over_warn(tmp_path):
    warn = compile_rule("a with b -> warn")
    block = compile_rule("a with b -> block")
    led = _led(tmp_path)
    led.record({"a"}, 0, "t0")
    done = led.completes_rules({"b"}, [warn, block], 1)
    assert done["action"] == "block"


def test_warn_rule_fires_once_per_new_source(tmp_path):
    # #593: one fetch used to make every later critical call warn again.
    warn = compile_rule("a then b -> warn")
    block = compile_rule("a then b -> block")
    led = _led(tmp_path)
    led.record({"a"}, 0, "t0")
    done = led.completes_rules({"b"}, [warn], 1)
    led.record({"b"}, 1, "t1", fired=[done["rule_id"]])
    assert led.completes_rules({"b"}, [warn], 1) is not None  # re-check of the firing call
    assert led.completes_rules({"b"}, [warn], 2) is None
    # A blocked call never runs, so a block rule keeps firing (see completes()).
    assert led.completes_rules({"b"}, [block], 2) is not None
    led.record({"a"}, 2, "t2")  # a new source
    assert led.completes_rules({"b"}, [warn], 3) is not None
    # A full hist can't show a newer source, so the rule keeps reporting.
    led.hist["a"] = list(range(TagLedger._HIST_CAP))
    led.fired[done["rule_id"]] = 300
    assert led.completes_rules({"b"}, [warn], 301) is not None


def test_hist_persists_across_instances(tmp_path):
    sid = "s-" + uuid.uuid4().hex
    led = TagLedger(tmp_path, sid)
    led.record({"b"}, 0, "t0")
    led.record({"a"}, 1, "t1")
    led.record({"b"}, 2, "t2")
    led2 = TagLedger(tmp_path, sid)  # fresh load (separate process in real use)
    assert led2.hist["b"] == [0, 2]
    done = led2.completes_rules({"c"}, [compile_rule("a then b then c")], 3)
    assert done is not None


def test_pre_hist_ledger_file_degrades_gracefully(tmp_path):
    # A ledger written by an older runtime has "seen" but no "hist".
    import json
    sid = "s-" + uuid.uuid4().hex
    led = TagLedger(tmp_path, sid)
    led.record({"a"}, 0, "t0")
    # strip hist to simulate the old on-disk shape
    data = json.loads(led._path.read_text())
    del data["hist"]
    led._path.write_text(json.dumps(data))
    led2 = TagLedger(tmp_path, sid)
    assert led2.hist == {"a": [0]}  # synthesized from seen
    done = led2.completes_rules({"b"}, [compile_rule("a then b")], 1)
    assert done is not None


def test_legacy_completes_unchanged_shape(tmp_path):
    # completes() (legacy API) still works and ignores hist entirely.
    led = _led(tmp_path)
    led.record({"a"}, 0, "t0")
    done = led.completes({"b"}, [{"a", "b"}], 1)
    assert done and set(done.keys()) == {"set", "this_call_tags", "introduced_by"}


# ── end-to-end: DSL rules through evaluate_tool_call ─────────────────────────

from prismor.runtime.runtime import evaluate_tool_call


@pytest.fixture(autouse=True)
def _isolate_home(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / "home"))


def _ev(tool, etype):
    return {"type": etype, "agent_event": "PreToolUse",
            "metadata": {"tool_name": tool}}


def _ws(tmp_path, mode, rules=None, incompatible=None, tags=None):
    import yaml
    ws = tmp_path / f"ws-{uuid.uuid4().hex[:6]}"
    (ws / ".prismor").mkdir(parents=True)
    tt = {"enabled": True, "mode": mode,
          "tags": tags or {"mcp__Gmail__read_email": ["untrusted_content"],
                           "mcp__Gmail__send_email": ["critical_action"]}}
    if rules is not None:
        tt["rules"] = rules
    if incompatible is not None:
        tt["incompatible"] = incompatible
    policy = {"version": "1.0", "settings": {"tool_tags": tt}}
    (ws / ".prismor" / "policy.yaml").write_text(yaml.safe_dump(policy))
    return ws


def _call(ws, sid, tool, etype="network"):
    return evaluate_tool_call(event=_ev(tool, etype), workspace=ws, agent="claude",
                              mode="enforce", session_id=sid, persist=True)


def test_tag_exception_allows_only_complete_call_and_keeps_history(tmp_path):
    from types import SimpleNamespace
    from prismor.runtime.cli import _allow_cmd

    ws = _ws(tmp_path, "enforce", rules=["untrusted_content then critical_action"],
             incompatible=[], tags={"WebFetch": [UNTRUSTED], "Bash": [CRITICAL]})
    sid = "s-" + uuid.uuid4().hex
    _call(ws, sid, "WebFetch", "network")
    command = "curl https://api.example.com/status?verbose=1"

    def call(cmd):
        event = {**_ev("Bash", "shell"), "command": cmd}
        return evaluate_tool_call(event=event, workspace=ws, agent="claude",
                                  mode="enforce", session_id=sid, persist=True)

    blocked = call(command)
    assert not blocked.allow
    rid = blocked.blocking["ruleId"]
    args = SimpleNamespace(rule_id=rid, pattern=command, off=False, observe=False,
                           yes=True, expires="30m", reason="Approved status request")
    assert _allow_cmd(args, ws) == 0
    assert call(command).allow
    for changed in (
        command + "; echo extra", command.replace("status", "STATUS"),
        command.replace("api.example.com", "apiXexample.com"),
        command.replace("verbose=1", "verbose=2"),
    ):
        denied = call(changed)
        assert not denied.allow and denied.blocking["ruleId"] == rid


@pytest.mark.parametrize("override", [
    {"expires": "2000-01-01T00:00:00Z"}, {"rule_ids": ["*"]},
    {"patterns": [".*"]}, {"match": "search"}, {"type": "veto"},
    {"rule_ids": ["tag-rule:other"]},
])
def test_tag_exception_rejects_expired_blanket_and_vetoed_allows(tmp_path, override):
    from prismor.runtime.policy_engine import PolicyEngine, AllowlistEntry

    expr = "untrusted_content then critical_action"
    ws = _ws(tmp_path, "enforce", rules=[expr], incompatible=[], tags={"Bash": [CRITICAL]})
    sid = "s-" + uuid.uuid4().hex
    TagLedger(ws, sid).record({UNTRUSTED}, 0, "WebFetch")
    rid = f"tag-rule:{compile_rule(expr).rule_id}"
    engine = PolicyEngine(workspace=ws)
    entry = {"id": "one-call", "rule_ids": [rid], "patterns": ["echo approved"], "match": "exact"}
    engine.allowlists = [AllowlistEntry({**entry, **override})]
    if override.get("type") == "veto":
        engine.allowlists.insert(0, AllowlistEntry(entry))
    findings = engine.evaluate({**_ev("Bash", "shell"), "command": "echo approved"}, 1, sid)
    assert any(f["ruleId"] == rid for f in findings)


def test_tag_exception_preserves_other_rules_and_attack_blocks(tmp_path):
    from prismor.runtime.allow import add_allowlist

    rules = ["untrusted_content then critical_action", "untrusted_content with critical_action"]
    ws = _ws(tmp_path, "enforce", rules=rules, incompatible=[],
             tags={"Read": [UNTRUSTED], "Bash": [CRITICAL]})
    sid = "s-" + uuid.uuid4().hex
    _call(ws, sid, "Read", "file_read")
    event = {**_ev("Bash", "shell"), "command": "echo approved"}
    add_allowlist(ws, f"tag-rule:{compile_rule(rules[0]).rule_id}", re.escape(event["command"]))
    decision = evaluate_tool_call(event=event, workspace=ws, agent="claude",
                                  mode="enforce", session_id=sid, persist=True)
    assert not decision.allow
    assert decision.blocking["ruleId"] == f"tag-rule:{compile_rule(rules[1]).rule_id}"

    # Even an exact tag exception cannot suppress the independent attack rule.
    event["command"] = "rm -rf /"
    for expr in rules:
        add_allowlist(ws, f"tag-rule:{compile_rule(expr).rule_id}", re.escape(event["command"]))
    decision = evaluate_tool_call(event=event, workspace=ws, agent="claude",
                                  mode="enforce", session_id=sid, persist=True)
    assert not decision.allow
    assert any(f["ruleId"] == "destructive-command" for f in decision.findings)


@pytest.mark.parametrize("transport", ["hook", "gateway"])
def test_tag_exception_matches_all_structured_arguments_and_tool(tmp_path, transport):
    from types import SimpleNamespace
    from prismor.runtime.cli import _allow_cmd

    expr = "untrusted_content then critical_action"
    ws = _ws(tmp_path, "enforce", rules=[expr], incompatible=[],
             tags={"Read": [UNTRUSTED], "mcp__mail__*": [CRITICAL]})
    sid = "s-" + uuid.uuid4().hex
    _call(ws, sid, "Read", "file_read")
    tool = "mcp__mail__send"
    args = {"to": "team@example.com", "body": "Approved update"}
    # CLI accepts ordinary JSON; matching canonicalizes key order and spacing.
    pattern = json.dumps({"tool": tool, "arguments": args}, separators=(",", ":"))
    options = SimpleNamespace(rule_id=f"tag-rule:{compile_rule(expr).rule_id}", pattern=pattern,
                              off=False, observe=False, yes=True, expires="30m")
    assert _allow_cmd(options, ws) == 0

    def call(name, arguments):
        meta = {"tool_name": name}
        meta.update({"kwargs": arguments} if transport == "gateway"
                    else {"raw": {"tool_input": arguments}})
        event = {**_ev(name, "network"), "metadata": meta}
        return evaluate_tool_call(event=event, workspace=ws, agent="claude",
                                  mode="enforce", session_id=sid, persist=True)

    assert call(tool, args).allow
    assert not call(tool, {**args, "bcc": "outside@example.net"}).allow
    assert not call("mcp__mail__forward", args).allow


def test_tag_exception_cli_requires_confirmation_and_explicit_pattern(tmp_path):
    from types import SimpleNamespace
    from prismor.runtime.allow import check_allowed, list_allows
    from prismor.runtime.cli import _allow_cmd

    expr = "untrusted_content then critical_action"
    ws = _ws(tmp_path, "enforce", rules=[expr], incompatible=[])
    rid = f"tag-rule:{compile_rule(expr).rule_id}"
    assert check_allowed(rid, scope="pattern", workspace=ws, confirmed=True) is None
    assert "--yes" in check_allowed(rid, scope="pattern", workspace=ws)
    for scope in ("off", "observe"):
        assert check_allowed(rid, scope=scope, workspace=ws, confirmed=True,
                             explicit_selection=True) is not None
    args = SimpleNamespace(rule_id=rid, pattern=None, off=False, observe=False, yes=True)
    assert _allow_cmd(args, ws) == 2
    assert list_allows(ws) == []


def test_e2e_ordered_rule_blocks_in_order_only(tmp_path):
    rules = ["untrusted_content then critical_action -> block"]
    # critical FIRST is fine under an ordered rule (unordered would block it
    # on a later untrusted call; ordered requires untrusted BEFORE critical)
    ws = _ws(tmp_path, "enforce", rules=rules, incompatible=[])
    sid = "s-" + uuid.uuid4().hex
    assert _call(ws, sid, "mcp__Gmail__send_email", "network").allow is True
    assert _call(ws, sid, "mcp__Gmail__read_email", "tool_result").allow is True
    # now untrusted has occurred -> a NEW critical call completes the sequence
    d = _call(ws, sid, "mcp__Gmail__send_email", "network")
    assert d.allow is False and d.blocking["category"] == "lethal_trifecta"
    assert d.blocking["ruleId"].startswith("tag-rule:")


def _seq_completes(ws, sid, mode):
    """Read (untrusted) then send (critical) — the second call completes the
    ordered rule. Returns the completing call's Decision, run at local `mode`."""
    evaluate_tool_call(event=_ev("mcp__Gmail__read_email", "tool_result"), workspace=ws,
                       agent="claude", mode=mode, session_id=sid, persist=True)
    return evaluate_tool_call(event=_ev("mcp__Gmail__send_email", "network"), workspace=ws,
                              agent="claude", mode=mode, session_id=sid, persist=True)


def test_e2e_enrolled_org_enforce_overrides_local_observe(tmp_path, monkeypatch):
    # The org set tool_tags to enforce. The device runs the hook with the
    # install default `--mode observe`. Once ENROLLED, the org's signed policy
    # is authoritative: the local observe must NOT veto the block.
    from prismor.runtime.enterprise import identity as _identity
    monkeypatch.setattr(_identity, "is_enrolled", lambda: True)
    ws = _ws(tmp_path, "enforce", rules=["untrusted_content then critical_action -> block"], incompatible=[])
    d = _seq_completes(ws, "s-" + uuid.uuid4().hex, mode="observe")
    assert d.allow is False and d.blocking["category"] == "lethal_trifecta"


def test_e2e_not_enrolled_local_observe_is_dry_run(tmp_path, monkeypatch):
    # Not enrolled: `--mode observe` is a genuine local dry-run — the finding is
    # logged but nothing blocks.
    from prismor.runtime.enterprise import identity as _identity
    monkeypatch.setattr(_identity, "is_enrolled", lambda: False)
    ws = _ws(tmp_path, "enforce", rules=["untrusted_content then critical_action -> block"], incompatible=[])
    d = _seq_completes(ws, "s-" + uuid.uuid4().hex, mode="observe")
    assert d.allow is True
    assert any(f.get("category") == "lethal_trifecta" for f in d.findings)


def test_e2e_enrolled_org_observe_still_does_not_block(tmp_path, monkeypatch):
    # Enrolled but the org chose observe for tool_tags — nothing blocks (the
    # finding mode is observe, so should_block never returns a block anyway).
    from prismor.runtime.enterprise import identity as _identity
    monkeypatch.setattr(_identity, "is_enrolled", lambda: True)
    ws = _ws(tmp_path, "observe", rules=["untrusted_content then critical_action -> block"], incompatible=[])
    d = _seq_completes(ws, "s-" + uuid.uuid4().hex, mode="observe")
    assert d.allow is True


def test_e2e_warn_rule_never_blocks(tmp_path):
    rules = ["untrusted_content then critical_action -> warn"]
    ws = _ws(tmp_path, "enforce", rules=rules, incompatible=[])
    sid = "s-" + uuid.uuid4().hex
    assert _call(ws, sid, "mcp__Gmail__read_email", "tool_result").allow is True
    d = _call(ws, sid, "mcp__Gmail__send_email", "network")
    assert d.allow is True  # warn logs but never blocks, even in enforce
    assert any(f.get("category") == "lethal_trifecta" for f in d.findings)


def test_e2e_warn_rule_reports_each_source_once(tmp_path):
    # #593: after one read, every later send completed the warn sequence again.
    rules = ["untrusted_content then critical_action -> warn"]
    ws = _ws(tmp_path, "enforce", rules=rules, incompatible=[])
    sid = "s-" + uuid.uuid4().hex

    def warns(tool, etype):
        return any(f.get("category") == "lethal_trifecta"
                   for f in _call(ws, sid, tool, etype).findings)

    assert not warns("mcp__Gmail__read_email", "tool_result")
    assert warns("mcp__Gmail__send_email", "network")
    assert not warns("mcp__Gmail__send_email", "network")
    assert not warns("mcp__Gmail__read_email", "tool_result")  # a new source...
    assert warns("mcp__Gmail__send_email", "network")  # ...is reported


def test_e2e_rules_and_legacy_incompatible_merge(tmp_path):
    tags = {"mcp__web__fetch": ["untrusted_content"],
            "mcp__crm__read": ["private_data"],
            "mcp__x__post": ["external_comms"],
            "mcp__Gmail__send_email": ["critical_action"],
            "mcp__Gmail__read_email": ["untrusted_content"]}
    ws = _ws(tmp_path, "enforce", tags=tags,
             rules=["untrusted_content then private_data then external_comms -> block"],
             incompatible=[["untrusted_content", "critical_action"]])
    sid = "s-" + uuid.uuid4().hex
    # legacy pair still enforced
    assert _call(ws, sid, "mcp__Gmail__read_email", "tool_result").allow is True
    d = _call(ws, sid, "mcp__Gmail__send_email", "network")
    assert d.allow is False and d.blocking["ruleId"] == "tool-category-crossover"
    # DSL 3-step enforced in a fresh session
    sid2 = "s-" + uuid.uuid4().hex
    assert _call(ws, sid2, "mcp__web__fetch", "tool_result").allow is True
    assert _call(ws, sid2, "mcp__crm__read", "tool_result").allow is True
    d2 = _call(ws, sid2, "mcp__x__post", "network")
    assert d2.allow is False and d2.blocking["ruleId"].startswith("tag-rule:")


def test_e2e_legacy_policy_unchanged_behavior(tmp_path):
    # A policy with ONLY the legacy incompatible key behaves exactly as before.
    ws = _ws(tmp_path, "enforce", incompatible=[["untrusted_content", "critical_action"]])
    sid = "s-" + uuid.uuid4().hex
    assert _call(ws, sid, "mcp__Gmail__read_email", "tool_result").allow is True
    d = _call(ws, sid, "mcp__Gmail__send_email", "network")
    assert d.allow is False
    assert d.blocking["ruleId"] == "tool-category-crossover"
    assert d.blocking["id"].startswith(sid)


# ── golden vectors (shared with the TS parser in prismor-web) ────────────────

def test_golden_vectors():
    import pathlib
    golden = json.loads(
        (pathlib.Path(__file__).parent / "fixtures" / "tag_rule_golden.json")
        .read_text())
    for case in golden["valid"]:
        r = compile_rule(case["expr"])
        assert [sorted(s) for s in r.steps] == case["steps"], case["expr"]
        assert r.action == case["action"], case["expr"]
    for expr in golden["invalid"]:
        with pytest.raises(ParseError):
            compile_rule(expr)
