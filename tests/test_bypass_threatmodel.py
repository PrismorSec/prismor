"""Regression tests for the 2026-11-05 agent-bypass threat model fixes."""
import base64
import io
import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prismor.runtime.policy_engine import PolicyEngine


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("HOME", str(tmp_path))


def _rules(command=None, path=None, etype="shell"):
    event = {"type": etype}
    if command is not None:
        event["command"] = command
    if path is not None:
        event["path"] = path
    return {f["ruleId"] for f in PolicyEngine().evaluate(event, index=0)}


# ── §2: a crashing hook denies on enforce ────────────────────────────────────

def _run_shim(monkeypatch, capsys, payload, agent="claude", mode="enforce"):
    from prismor.runtime import immunity_cli
    import prismor.runtime.cli as cli

    def boom(argv):
        raise RuntimeError("boom")

    monkeypatch.setattr(cli, "main", boom)
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(payload)))
    with pytest.raises(SystemExit) as exc:
        immunity_cli._hook_dispatch_fail_closed(["--agent", agent, "--mode", mode])
    return exc.value.code, capsys.readouterr()


def test_crash_on_enforce_blocks(monkeypatch, capsys):
    code, _ = _run_shim(monkeypatch, capsys, {"hook_event_name": "PreToolUse", "tool_name": "Bash"})
    assert code == 2


def test_crash_on_copilot_prints_json_deny(monkeypatch, capsys):
    code, out = _run_shim(monkeypatch, capsys, {"toolName": "bash"}, agent="copilot")
    assert code == 0 and json.loads(out.out)["permissionDecision"] == "deny"


@pytest.mark.parametrize("payload,mode", [
    ({"hook_event_name": "PreToolUse", "tool_name": "Bash"}, "observe"),
    ({"hook_event_name": "Stop"}, "enforce"),            # exit 2 would loop "keep going"
    ({"hook_event_name": "UserPromptSubmit"}, "enforce"),
    ({"hook_event_name": "PreToolUse", "tool_name": "Read"}, "enforce"),
])
def test_crash_does_not_deny_where_it_must_not(monkeypatch, capsys, payload, mode):
    code, _ = _run_shim(monkeypatch, capsys, payload, mode=mode)
    assert code == 1


# ── §5: decode-at-runtime and variable indirection ───────────────────────────

@pytest.mark.parametrize("command", [
    f"echo {base64.b64encode(b'rm -rf /').decode()} | base64 -d | sh",
    f"echo {b'rm -rf /'.hex()} | xxd -r -p | sh",
    "CMD=rm; DIR=/; $CMD -rf $DIR",
    "X='rm -rf'; ${X} /",
])
def test_destructive_payload_is_seen_through_indirection(command):
    assert "destructive-command" in _rules(command)


def test_benign_decode_is_quiet():
    assert "destructive-command" not in _rules("echo aGVsbG8gd29ybGQ= | base64 -d")


# ── §6: self-tampering without a shell verb, and other hosts' hooks ─────────

@pytest.mark.parametrize("command", [
    "python3 -c \"open('/u/.prismor/pause.json','w').write('{}')\"",
    "python3 -I -c \"import os; os.remove('.cursor/hooks.json')\"",
    "perl -pi -e 's/hooks = true/hooks = false/' ~/.codex/config.toml",
    "rm ~/.cursor/hooks.json",
    "echo '{}' > .codex/hooks.json",
])
def test_tampering_is_blocked(command):
    assert "agent-config-tampering" in _rules(command)


@pytest.mark.parametrize("command", [
    "cat ~/.codex/config.toml",
    "python3 -c 'print(open(\".prismor/policy.yaml\").read())'",
    "ls ~/.prismor | grep -i pause",
])
def test_reads_are_not_tampering(command):
    assert "agent-config-tampering" not in _rules(command)


@pytest.mark.parametrize("path", ["/u/.cursor/hooks.json", "/u/.gemini/settings.json",
                                  "/u/.codex/config.toml", "/u/.prismor/hook-dispatch.py"])
def test_host_hook_config_writes_are_blocked(path):
    assert "agent-config-tampering-path" in _rules(path=path, etype="file_write")


def test_pause_key_read_and_eval_url_are_self_edit():
    assert "prismor-self-edit" in _rules("cat ~/.prismor/pause.key")
    assert "prismor-self-edit" in _rules("PRISMOR_EVAL_URL=http://x codex exec hi")


# ── §5: a floor finding inside a script blocks by default ────────────────────

def test_floor_finding_in_script_enforces(tmp_path):
    (tmp_path / "go.sh").write_text("rm -rf /\n")
    findings = PolicyEngine(workspace=tmp_path).evaluate(
        {"type": "shell", "command": "bash go.sh"}, index=0)
    target = [f for f in findings if f.get("execTarget") and f["ruleId"] == "destructive-command"]
    assert target and target[0]["mode"] == "enforce"


# ── §4: a pause never silences the floor ─────────────────────────────────────

def _dispatch(tmp_path, command):
    import subprocess
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = {k: v for k, v in os.environ.items() if not k.startswith("PRISMOR_")}
    env.update(HOME=str(tmp_path), PRISMOR_HOME=str(tmp_path / "home"))
    boot = f"import sys; sys.path.insert(0, {root!r}); from prismor.runtime.immunity_cli import main; main(sys.argv[1:])"
    payload = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "session_id": "s1",
               "cwd": str(tmp_path), "tool_input": {"command": command}}
    return subprocess.run(
        [sys.executable, "-c", boot, "hook-dispatch", "--agent", "claude",
         "--workspace", str(tmp_path), "--mode", "enforce"],
        input=json.dumps(payload), capture_output=True, text=True, env=env, timeout=60)


def test_pause_keeps_floor_blocking(tmp_path, monkeypatch):
    from prismor.runtime import pause
    pause.set_paused(600, reason="test")
    assert pause.active_state() is not None
    assert _dispatch(tmp_path, "rm -rf /").returncode == 2
