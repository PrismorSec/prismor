"""Tests for eval-time rule exemptions (prismor/runtime/runtime._apply_rule_exemptions)
and the re-pull signature (prismor/runtime/enterprise/remote_policy).

An exemption {ruleId, scope, scopeId, action, expires} relaxes ('allow' → drop)
or downgrades ('flag' → warn, non-blocking) a finding for the current
user/device/session. Core/floor rules can never be exempted.
"""
from __future__ import annotations

from prismor.runtime.runtime import _apply_rule_exemptions
from prismor.runtime.principal import Subject


def _finding(rule_id, category="tool_call_abuse", mode="enforce"):
    return {"ruleId": rule_id, "category": category, "mode": mode, "title": rule_id}


SUBJ = Subject(source="device", user_id="alice", team_id=None, org_id="o1")


def test_no_exemptions_is_passthrough():
    fs = [_finding("curl-pipe-sh")]
    assert _apply_rule_exemptions(fs, None, session_id="s1", subject=SUBJ) == fs
    assert _apply_rule_exemptions(fs, [], session_id="s1", subject=SUBJ) == fs


def test_session_allow_drops_finding():
    ex = [{"ruleId": "curl-pipe-sh", "scope": "session", "scopeId": "s1", "action": "allow"}]
    out = _apply_rule_exemptions([_finding("curl-pipe-sh")], ex, session_id="s1", subject=SUBJ)
    assert out == []  # allowed → dropped


def test_session_scope_miss_keeps_finding():
    ex = [{"ruleId": "curl-pipe-sh", "scope": "session", "scopeId": "OTHER", "action": "allow"}]
    out = _apply_rule_exemptions([_finding("curl-pipe-sh")], ex, session_id="s1", subject=SUBJ)
    assert len(out) == 1


def test_user_allow():
    ex = [{"ruleId": "r", "scope": "user", "scopeId": "alice", "action": "allow"}]
    assert _apply_rule_exemptions([_finding("r")], ex, session_id="s", subject=SUBJ) == []
    ex_miss = [{"ruleId": "r", "scope": "user", "scopeId": "bob", "action": "allow"}]
    assert len(_apply_rule_exemptions([_finding("r")], ex_miss, session_id="s", subject=SUBJ)) == 1


def test_device_allow(monkeypatch):
    # device_id comes from the enrolled identity, not the Subject.
    monkeypatch.setattr("prismor.runtime.enterprise.identity.load_identity", lambda: {"device_id": "dev_1"})
    ex = [{"ruleId": "r", "scope": "device", "scopeId": "dev_1", "action": "allow"}]
    assert _apply_rule_exemptions([_finding("r")], ex, session_id="s", subject=SUBJ) == []
    ex_miss = [{"ruleId": "r", "scope": "device", "scopeId": "dev_2", "action": "allow"}]
    assert len(_apply_rule_exemptions([_finding("r")], ex_miss, session_id="s", subject=SUBJ)) == 1


def test_flag_downgrades_but_keeps():
    ex = [{"ruleId": "r", "scope": "session", "scopeId": "s1", "action": "flag"}]
    out = _apply_rule_exemptions([_finding("r", mode="enforce")], ex, session_id="s1", subject=SUBJ)
    assert len(out) == 1
    assert out[0]["mode"] == "observe"      # no longer blocks
    assert out[0]["exempted"] == "flag"     # marked for the dashboard


def test_expired_exemption_ignored():
    ex = [{"ruleId": "r", "scope": "session", "scopeId": "s1", "action": "allow",
           "expires": "2000-01-01T00:00:00Z"}]  # long past
    out = _apply_rule_exemptions([_finding("r")], ex, session_id="s1", subject=SUBJ)
    assert len(out) == 1  # expired → not applied


def test_floor_rule_never_exemptable():
    # A core rule id and a core category both stay, even with a matching exemption.
    ex = [
        {"ruleId": "destructive-command", "scope": "session", "scopeId": "s1", "action": "allow"},
        {"ruleId": "secret-leak", "scope": "session", "scopeId": "s1", "action": "allow"},
    ]
    fs = [_finding("destructive-command", category="destructive_command"),
          _finding("secret-leak", category="secret_exfiltration")]
    out = _apply_rule_exemptions(fs, ex, session_id="s1", subject=SUBJ)
    assert len(out) == 2  # both floor findings survive


def test_kill_switch_never_exemptable():
    ex = [{"ruleId": "agent-disabled", "scope": "session", "scopeId": "s1", "action": "allow"}]
    fs = [_finding("agent-disabled", category="agent-control")]
    assert len(_apply_rule_exemptions(fs, ex, session_id="s1", subject=SUBJ)) == 1


def test_scoped_agent_finding_is_exemptable():
    # The whole point: a scoped-agent denial (not a policy rule) can be relaxed.
    ex = [{"ruleId": "scoped-agent", "scope": "session", "scopeId": "s1", "action": "allow"}]
    fs = [_finding("scoped-agent", category="scoped_agent")]
    assert _apply_rule_exemptions(fs, ex, session_id="s1", subject=SUBJ) == []


def test_sig_round_trips(tmp_path, monkeypatch):
    """_current_rule_exemptions_sig reproduces the server's format so a change
    triggers a re-pull; empty when there are none."""
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / ".prismor"))
    from prismor.runtime.enterprise import remote_policy
    import hashlib

    exemptions = [
        {"id": "re_1", "ruleId": "curl-pipe-sh", "scope": "session", "scopeId": "s1", "action": "allow", "expires": "2099-01-01T00:00:00Z"},
        {"id": "re_2", "ruleId": "scoped-agent", "scope": "user", "scopeId": "alice", "action": "flag"},
    ]
    monkeypatch.setattr(remote_policy, "verify_and_load", lambda: {"settings": {"rule_exemptions": exemptions}})
    sig = remote_policy._current_rule_exemptions_sig()
    lines = sorted([
        "re_1:curl-pipe-sh:session:s1:allow:2099-01-01T00:00:00Z",
        "re_2:scoped-agent:user:alice:flag:",
    ])
    assert sig == hashlib.sha256("\n".join(lines).encode()).hexdigest()[:16]

    monkeypatch.setattr(remote_policy, "verify_and_load", lambda: {"settings": {}})
    assert remote_policy._current_rule_exemptions_sig() == ""


# ── exact-call decisions, ask / deny, agent and org scope ─────────────────────

def test_floor_rule_allowed_for_one_exact_call_only():
    ev = {"type": "shell", "command": "node -e 'let m; while((m=re.exec(c))){}'"}
    ex = [{"ruleId": "rce-canary", "scope": "session", "scopeId": "s1", "action": "allow",
           "pattern": "node -e 'let m; while((m=re.exec(c))){}'"}]
    f = _finding("rce-canary", category="rce_canary")
    assert _apply_rule_exemptions([f], ex, session_id="s1", subject=SUBJ, event=ev) == []
    other = {"type": "shell", "command": "node -e 'require(\"child_process\").execSync(x)'"}
    assert len(_apply_rule_exemptions([f], ex, session_id="s1", subject=SUBJ, event=other)) == 1


def test_self_protection_rule_never_relaxed_even_for_exact_call():
    ev = {"type": "shell", "command": "prismor allow x"}
    ex = [{"ruleId": "prismor-self-edit", "scope": "org", "scopeId": "org", "action": "allow",
           "pattern": "prismor allow x"}]
    f = _finding("prismor-self-edit", category="security_bypass")
    assert len(_apply_rule_exemptions([f], ex, session_id="s1", subject=SUBJ, event=ev)) == 1


def test_ask_turns_finding_into_step_up():
    ex = [{"ruleId": "r", "scope": "session", "scopeId": "s1", "action": "ask"}]
    out = _apply_rule_exemptions([_finding("r", mode="observe")], ex, session_id="s1", subject=SUBJ)
    assert out[0]["action"] == "step_up" and out[0]["mode"] == "enforce"


def test_deny_makes_observe_finding_block():
    ex = [{"ruleId": "r", "scope": "agent", "scopeId": "claude", "action": "deny"}]
    out = _apply_rule_exemptions([_finding("r", mode="observe")], ex, session_id="s1",
                                 subject=SUBJ, agent_names=("claude",))
    assert out[0]["action"] == "block" and out[0]["authoritative"]
    miss = _apply_rule_exemptions([_finding("r", mode="observe")], ex, session_id="s1",
                                  subject=SUBJ, agent_names=("codex",))
    assert miss[0]["mode"] == "observe"


def test_org_scope_applies_everywhere():
    ex = [{"ruleId": "r", "scope": "org", "scopeId": "org", "action": "allow"}]
    assert _apply_rule_exemptions([_finding("r")], ex, session_id="s9", subject=None) == []
