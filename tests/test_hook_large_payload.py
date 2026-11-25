"""A padded payload must not make the hook slow enough to be killed (agents then
run the tool). Every oversize case answers fast and enforce stays fail-closed.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from prismor.runtime import payload_bounds  # noqa: E402
from prismor.runtime.policy_engine import _expand_braces  # noqa: E402

MB5 = 5_000_000
BOUND_S = 20
RM = "rm -" + "rf /"  # kept apart so this file itself is not read as the command


@pytest.fixture()
def ws(tmp_path):
    w = tmp_path / "ws"
    w.mkdir()
    subprocess.run(["git", "init", "-q", str(w)], check=True)
    return w


def _run(ws, payload, mode="enforce", env_extra=None, raw=None):
    home = ws.parent / "home"
    home.mkdir(exist_ok=True)
    env = dict(os.environ, PRISMOR_HOME=str(home), HOME=str(home), USERPROFILE=str(home),
               PYTHONPATH=str(ROOT))
    env.update(env_extra or {})
    code = "from prismor.runtime.immunity_cli import main; main()"
    t0 = time.time()
    p = subprocess.run(
        [sys.executable, "-c", code, "hook-dispatch", "--agent", "claude",
         "--workspace", str(ws), "--mode", mode],
        input=json.dumps(payload) if raw is None else raw, capture_output=True, text=True,
        cwd=str(ws), env=env, timeout=120)
    return p, time.time() - t0


def _pre(ws, command=None, tool="Bash", **tool_input):
    ti = {"command": command} if command is not None else tool_input
    return {"session_id": "s1", "cwd": str(ws), "hook_event_name": "PreToolUse",
            "tool_name": tool, "tool_input": ti}


def _post_read(ws, text):
    return {"session_id": "s1", "cwd": str(ws), "hook_event_name": "PostToolUse", "tool_name": "Read",
            "tool_input": {"file_path": str(ws / "f.txt")}, "tool_response": {"file": {"content": text}}}


def test_payload_5mb_every_event_kind_answers_fast(ws):
    pad = "a" * MB5
    cases = {
        "bash": _pre(ws, "echo " + pad),
        "write": _pre(ws, tool="Write", file_path=str(ws / "f.txt"), content=pad),
        "read": _post_read(ws, pad),
        "prompt": {"session_id": "s1", "cwd": str(ws), "hook_event_name": "UserPromptSubmit",
                   "prompt": pad},
    }
    for name, payload in cases.items():
        p, secs = _run(ws, payload)
        assert secs < BOUND_S, f"{name}: {secs:.1f}s"
        # Only the oversize shell command is refused; the others are screened by window.
        assert (p.returncode == 2) == (name == "bash"), f"{name}: rc={p.returncode} {p.stderr[-300:]}"


@pytest.mark.parametrize("pad", ["a" * MB5, " " * MB5, ";" * 200_000, "$(" * 100_000],
                         ids=["a-5mb", "spaces-5mb", "semicolons", "dollar-paren"])
def test_dangerous_command_padded_is_still_blocked(ws, pad):
    for cmd in (f"git push --force origin main # {pad}", f"{RM}{pad}; echo hi", f"echo {pad}; {RM}"):
        p, secs = _run(ws, _pre(ws, cmd))
        assert secs < BOUND_S
        assert p.returncode == 2, p.stderr[-300:]


def test_observe_mode_does_not_block_a_large_command(ws):
    p, secs = _run(ws, _pre(ws, "echo " + "a" * MB5), mode="observe")
    assert secs < BOUND_S and p.returncode == 0


def test_ordinary_200kb_file_write_and_read_are_allowed(ws):
    text = "".join(f"def f{i}(x):\n    return x + {i}\n\n" for i in range(8000))[:200_000]
    p, _ = _run(ws, _pre(ws, tool="Write", file_path=str(ws / "mod.py"), content=text))
    assert p.returncode == 0, p.stderr[-300:]
    p, _ = _run(ws, _post_read(ws, text))
    assert p.returncode == 0, p.stderr[-300:]


def test_ordinary_heredoc_command_is_allowed(ws):
    body = "".join(f"line {i} of the file\n" for i in range(3000))
    p, secs = _run(ws, _pre(ws, f"cat > notes.txt <<'EOF'\n{body}EOF"))
    assert p.returncode == 0, p.stderr[-300:]
    assert secs < BOUND_S


def test_time_budget_fails_closed_in_enforce_and_open_in_observe(ws):
    env = {"PRISMOR_HOOK_BUDGET_MS": "1"}
    p, _ = _run(ws, _pre(ws, "echo hi"), env_extra=env)
    assert p.returncode == 2 and "time budget" in p.stderr
    p, _ = _run(ws, _pre(ws, "echo hi"), mode="observe", env_extra=env)
    assert p.returncode == 1 and "not screened" in p.stderr


def test_empty_stdin_is_fail_closed_in_enforce_only(ws):
    p, _ = _run(ws, None, raw="")
    assert p.returncode == 2 and "empty hook payload" in p.stderr
    p, _ = _run(ws, None, mode="observe", raw="")
    assert p.returncode == 0


def test_expand_braces_is_linear_and_unchanged():
    assert _expand_braces("rm -rf /{bin,etc}") == "rm -rf /bin /etc"
    assert _expand_braces("echo x{a,b}y z{c,d}") == "echo xay xby zc zd"
    t0 = time.time()
    _expand_braces("echo " + "a" * MB5)
    assert time.time() - t0 < 5


def test_bound_event_windows_and_flags_a_command():
    big = "x " * 200_000
    ev = {"type": "shell", "command": big, "metadata": {"raw": {"tool_input": {"command": big}}}}
    cuts = payload_bounds.bound_event(ev)
    assert {c["path"] for c in cuts} == {"command", "metadata.raw.tool_input.command"}
    assert len(ev["command"]) < 10_000
    f = payload_bounds.findings_for(cuts, "s", 0)
    assert f[0]["ruleId"] == "payload-too-large" and f[0]["action"] == "block"
