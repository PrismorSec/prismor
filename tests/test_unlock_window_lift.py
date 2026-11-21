"""GHSA-v6vw-pfgj-4mg8: what an open unlock window lifts, and that the lift is
in the signed trail. Drives the real hook-dispatch in a subprocess."""
import json
import os
import subprocess
import sys

root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, root)


def _dispatch(tmp_path, command):
    env = {k: v for k, v in os.environ.items() if not k.startswith("PRISMOR_")}
    env.update(HOME=str(tmp_path), PRISMOR_HOME=str(tmp_path / "home"))
    boot = f"import sys; sys.path.insert(0, {root!r}); from prismor.runtime.immunity_cli import main; main(sys.argv[1:])"
    payload = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "session_id": "s1",
               "cwd": str(tmp_path), "tool_input": {"command": command}}
    return subprocess.run(
        [sys.executable, "-c", boot, "hook-dispatch", "--agent", "claude",
         "--workspace", str(tmp_path), "--mode", "enforce"],
        input=json.dumps(payload), capture_output=True, text=True, env=env, timeout=60)


def _open_window(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / "home"))
    from prismor.runtime import unlock
    unlock.set_password("correct horse battery")
    unlock.open_window(workspace=tmp_path)
    assert unlock.is_open(tmp_path)


def _trail(tmp_path):
    p = tmp_path / "home" / "audit" / "trail.jsonl"
    return [json.loads(l) for l in p.read_text().splitlines()] if p.exists() else []


def test_window_lifts_policy_edit_and_signs_the_lift(tmp_path, monkeypatch):
    _open_window(tmp_path, monkeypatch)
    r = _dispatch(tmp_path, "prismor allow risky-write --off --yes")
    assert r.returncode == 0, r.stderr
    lifts = [x for x in _trail(tmp_path)
             if x.get("record_type") == "approval" and x.get("status") == "unlock_window"]
    assert lifts and lifts[0]["rules"] == ["prismor-self-edit"]


def test_window_never_lifts_credential_or_trail(tmp_path, monkeypatch):
    _open_window(tmp_path, monkeypatch)
    for command in ("cat ~/.prismor/unlock.json",
                    "echo '{}' > ~/.prismor/unlock-grant.json",
                    "cat ~/.prismor/receipt_signing_key.pem",
                    "rm ~/.prismor/audit/trail.jsonl",
                    "cat ~/.prismor/pause.key"):
        assert _dispatch(tmp_path, command).returncode == 2, command


def test_closed_window_still_blocks(tmp_path):
    assert _dispatch(tmp_path, "prismor allow risky-write --off --yes").returncode == 2
