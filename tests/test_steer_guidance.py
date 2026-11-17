"""Rule `guidance:` and the `instruct` action: steer the agent, never weaken a block.

guidance on a block rule is appended to the reason the agent sees. An
instruct rule allows the call and sends its guidance as PreToolUse context
where the agent's protocol takes it (hook_caps), else logs it.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_hook_caps import _dispatch  # noqa: E402

_POLICY = """
rules:
  - id: steer-block
    severity: HIGH
    category: test_steer
    title: Block the block marker
    event_types: [shell]
    fields: [command]
    mode: enforce
    action: block
    guidance: "use STEER_SAFE_ALTERNATIVE"
    patterns: ["STEER_BLOCK_MARKER"]
  - id: steer-instruct
    severity: LOW
    category: test_steer
    title: Instruct on the instruct marker
    event_types: [shell]
    fields: [command]
    mode: enforce
    action: instruct
    guidance: "prefer STEER_HINT_TEXT next time"
    patterns: ["STEER_INSTRUCT_MARKER"]
"""

_PAYLOAD = {
    "claude": {"hook_event_name": "PreToolUse", "tool_name": "Bash"},
    "codex": {"hook_event_name": "PreToolUse", "tool_name": "Bash"},
    "copilot": {"hookEventName": "PreToolUse", "tool_name": "Bash"},
}


def _run(agent, tmp_path, command):
    ws = tmp_path / "ws"
    (ws / ".prismor").mkdir(parents=True, exist_ok=True)
    (ws / ".prismor" / "policy.yaml").write_text(_POLICY, encoding="utf-8")
    payload = {"session_id": f"steer-{agent}", **_PAYLOAD[agent], "tool_input": {"command": command}}
    return _dispatch(agent, ws, tmp_path / "home", payload)


@pytest.mark.parametrize("agent", sorted(_PAYLOAD))
def test_block_reason_carries_guidance(agent, tmp_path):
    proc, out = _run(agent, tmp_path, "echo STEER_BLOCK_MARKER")
    shown = proc.stderr + (str(out) if out else "")
    assert "Instead: use STEER_SAFE_ALTERNATIVE" in shown
    if agent == "copilot":
        assert out["permissionDecision"] == "deny"
    else:
        assert proc.returncode == 2


@pytest.mark.parametrize("agent", sorted(_PAYLOAD))
def test_instruct_allows_and_steers_where_supported(agent, tmp_path):
    proc, out = _run(agent, tmp_path, "echo STEER_INSTRUCT_MARKER")
    assert proc.returncode == 0, proc.stderr
    if agent == "claude":
        hso = out["hookSpecificOutput"]
        assert hso["hookEventName"] == "PreToolUse"
        assert "STEER_HINT_TEXT" in hso["additionalContext"] and "steer-instruct" in hso["additionalContext"]
        assert "permissionDecision" not in hso  # allowed, not auto-approved
    else:
        # No verified PreToolUse context on this protocol: plain allow + a log line.
        assert out is None
        assert "guidance not delivered" in proc.stderr and "STEER_HINT_TEXT" in proc.stderr


@pytest.mark.parametrize("agent", sorted(_PAYLOAD))
def test_instruct_never_weakens_a_block(agent, tmp_path):
    proc, out = _run(agent, tmp_path, "echo STEER_INSTRUCT_MARKER STEER_BLOCK_MARKER")
    if agent == "copilot":
        assert out["permissionDecision"] == "deny"
    else:
        assert proc.returncode == 2
        assert out is None or "additionalContext" not in out.get("hookSpecificOutput", {})


def test_instruct_resolves_to_observe_even_under_device_enforce(tmp_path):
    from prismor.runtime.hooks import should_block
    from prismor.runtime.policy_engine import PolicyEngine

    ws = tmp_path / "ws"
    (ws / ".prismor").mkdir(parents=True)
    (ws / ".prismor" / "policy.yaml").write_text(_POLICY, encoding="utf-8")
    engine = PolicyEngine(workspace=ws)
    engine.device_mode = "enforce"
    rule = next(r for r in engine.rules if r.id == "steer-instruct")
    assert engine.explain_mode(rule)[0] == "observe"
    event = {"type": "shell", "command": "echo STEER_INSTRUCT_MARKER", "agent_event": "PreToolUse"}
    findings = [f for f in engine.evaluate(event, 0, session_id="s") if f["ruleId"] == "steer-instruct"]
    assert findings and findings[0]["guidance"] == "prefer STEER_HINT_TEXT next time"
    assert should_block(findings, event) is None


def _validate(tmp_path, rule):
    import yaml
    from prismor.runtime.policy_engine import validate_policy
    path = tmp_path / "p.yaml"
    path.write_text(yaml.safe_dump({"version": "1.0", "rules": [rule]}), encoding="utf-8")
    return validate_policy(path)


def test_validation_and_telemetry(tmp_path):
    from prismor.runtime.enterprise.telemetry import build_record

    base = {"id": "x", "severity": "LOW", "category": "c", "title": "t", "event_types": ["shell"], "patterns": ["a"]}
    assert any("needs a guidance" in e for e in _validate(tmp_path, {**base, "action": "instruct"}))
    assert any("guidance" in e for e in _validate(tmp_path, {**base, "action": "block", "guidance": ""}))
    assert not _validate(tmp_path, {**base, "action": "instruct", "guidance": "do y"})

    rec = build_record({"ruleId": "x", "severity": "LOW", "category": "c", "title": "t", "mode": "observe",
                        "action": "instruct", "guidance": "do y"},
                       {"type": "shell", "command": "a"}, extra={}, full_capture=False)
    assert rec["guidance"] == "do y" and rec["verdict"] == "observed"
