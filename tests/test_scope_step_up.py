"""A synthesised scope asks; it does not block (#257).

The session scope is synthesised from the user's prompt. When it leaves out a
tool that prompt plainly needs ("Research how other projects do retry backoff
and write me a summary" -> WebFetch denied), every later use of that tool was
hard-denied, the user's own request along with any injected one: the rule sees
the capability, never the call. It was the only measured cause of blocking a
legitimate action, and it took the no-injection utility control from 100% to
33% in enforce mode.

A miss in a synthesised scope is now a ``step_up``: Claude asks the person
inline, surfaces that cannot ask still fail closed, and attack policy still
blocks outright (block outranks step_up). A scope a human wrote keeps
blocking. Scope findings carry their origin so telemetry can report them apart
from attack policy.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import types
from pathlib import Path

import pytest

from prismor.runtime import scoped_agent as sa
from prismor.runtime.enterprise import telemetry
from prismor.runtime.hooks import should_block

_REPO_ROOT = Path(sa.__file__).parents[2]
GOAL = "Research how other projects do retry backoff and write me a summary."
# What the synthesiser returned for GOAL in the issue: WebFetch, the one tool
# the request cannot be done without, left out and denied.
LLM_SCOPE = {
    "allowed_tools": ["Read", "Write", "Glob", "Grep"],
    "allowed_paths": ["**"],
    "deny_tools": ["Bash", "Edit", "MultiEdit", "WebFetch", "WebSearch"],
    "deny_network": True,
}
WEBFETCH = {"type": "network", "url": "https://example.com/retry-backoff",
            "metadata": {"tool_name": "WebFetch"}}


@pytest.fixture
def home(tmp_path, monkeypatch):
    ph = tmp_path / "prismor-home"
    ph.mkdir()
    (tmp_path / "home").mkdir()
    monkeypatch.setenv("PRISMOR_HOME", str(ph))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    return ph


@pytest.fixture
def llm_scope(monkeypatch):
    """Run the real LLM synthesis path against a stubbed SDK."""
    reply = types.SimpleNamespace(content=[types.SimpleNamespace(text=json.dumps(LLM_SCOPE))])
    client = types.SimpleNamespace(messages=types.SimpleNamespace(create=lambda **kw: reply))
    monkeypatch.setitem(sys.modules, "anthropic", types.SimpleNamespace(Anthropic=lambda **kw: client))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-not-real")
    rules = sa.synthesize_scoped_rules(GOAL, list(sa.BUILTIN_SCOPE_TOOLS), Path("."))
    monkeypatch.delenv("ANTHROPIC_API_KEY")
    assert "WebFetch" in rules["deny_tools"] and rules["origin"] == "llm"
    return rules


def _dispatch(ws: Path, agent: str, payload: dict) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env.pop("PRISMOR_WORKSPACE", None)
    env["PYTHONPATH"] = str(_REPO_ROOT) + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    payload = {"session_id": "s257", "cwd": str(ws), "hook_event_name": "PreToolUse", **payload}
    return subprocess.run(
        [sys.executable, "-m", "prismor.runtime.immunity_cli", "hook-dispatch",
         "--agent", agent, "--workspace", str(ws), "--mode", "enforce"],
        cwd=str(ws), env=env, input=json.dumps(payload), capture_output=True, text=True, timeout=120, check=False,
    )


def _decision(r: subprocess.CompletedProcess) -> str:
    if r.returncode == 2:
        return "deny"
    for line in r.stdout.splitlines():
        try:
            out = json.loads(line)
        except ValueError:
            continue
        hso = out.get("hookSpecificOutput") or {}
        if hso.get("permissionDecision"):
            return hso["permissionDecision"]
    return "allow"


@pytest.fixture
def ws(tmp_path):
    w = tmp_path / "ws"
    (w / ".git").mkdir(parents=True)
    return w


# ── the finding ────────────────────────────────────────────────────────────

def test_synthesised_scope_miss_is_step_up(llm_scope):
    f = sa.check_scoped_rules(llm_scope, WEBFETCH, session_id="s257")
    assert f["ruleId"] == "scoped-agent" and f["action"] == "step_up"
    assert f["mode"] == "enforce" and f["scopeOrigin"] == "llm"
    # Every way a synthesised scope says no is the same kind of guess.
    not_listed = dict(llm_scope, allowed_tools=["Read"], deny_tools=[])
    assert sa.check_scoped_rules(not_listed, WEBFETCH)["action"] == "step_up"
    net = dict(llm_scope, allowed_tools=["Bash"], deny_tools=[])
    shell = {"type": "shell", "command": "curl https://example.com", "metadata": {"tool_name": "Bash"}}
    assert sa.check_scoped_rules(net, shell)["action"] == "step_up"
    static = dict(llm_scope, origin="static")
    assert sa.check_scoped_rules(static, WEBFETCH)["scopeOrigin"] == "static"


def test_human_written_scope_still_blocks(llm_scope):
    edited = dict(llm_scope, operator_edited=True)  # dashboard / `prismor scope edit`
    f = sa.check_scoped_rules(edited, WEBFETCH)
    assert f["action"] == "block" and f["scopeOrigin"] == "operator"
    # An IAM profile (or any hand-written allowlist) has no inventory.
    iam_like = {"allowed_tools": ["Read"], "deny_tools": ["WebFetch"]}
    f = sa.check_scoped_rules(iam_like, WEBFETCH)
    assert f["action"] == "block" and "scopeOrigin" not in f


def test_attack_policy_outranks_the_scope_ask(llm_scope):
    ask = sa.check_scoped_rules(llm_scope, WEBFETCH)
    attack = {"ruleId": "remote-exec", "action": "block", "mode": "enforce", "category": "remote_execution"}
    assert should_block([ask, attack], {"agent_event": "PreToolUse", "type": "network"}) is attack


def test_telemetry_reports_scope_findings_apart(llm_scope):
    f = sa.check_scoped_rules(llm_scope, WEBFETCH, session_id="s257")
    rec = telemetry.build_record(f, WEBFETCH, {})
    assert rec["rule_id"] == "scoped-agent" and rec["scope_origin"] == "llm"
    attack = {"ruleId": "remote-exec", "action": "block", "mode": "enforce", "title": "x"}
    assert "scope_origin" not in telemetry.build_record(attack, WEBFETCH, {})


# ── end to end through the hook (the utility control) ──────────────────────

def test_utility_control_asks_instead_of_denying(home, ws, llm_scope):
    """The openly requested WebFetch reaches the person instead of being
    refused. Before #257 this was exit 2: '... explicitly denied for this
    session'."""
    sa.save_scoped_rules(ws, "s257", llm_scope)
    r = _dispatch(ws, "claude", {"tool_name": "WebFetch",
                                 "tool_input": {"url": WEBFETCH["url"], "prompt": "summarise"}})
    assert _decision(r) == "ask", (r.returncode, r.stdout, r.stderr)
    assert "scoped agent" in r.stdout


def test_surface_that_cannot_ask_fails_closed(home, ws, llm_scope):
    sa.save_scoped_rules(ws, "s257", llm_scope)
    r = _dispatch(ws, "claude", {"tool_name": "WebFetch", "agent_id": "sub-1",
                                 "tool_input": {"url": WEBFETCH["url"], "prompt": "summarise"}})
    assert _decision(r) == "deny", (r.returncode, r.stdout, r.stderr)  # subagent: no ask
    # Codex has no inline ask (Bash is denied in this scope).
    r = _dispatch(ws, "codex", {"tool_name": "Bash", "tool_input": {"command": "ls"}})
    assert r.returncode == 2 and "scoped agent" in r.stderr, (r.stdout, r.stderr)


def test_operator_edited_scope_still_denies(home, ws, llm_scope):
    sa.save_scoped_rules(ws, "s257", dict(llm_scope, operator_edited=True))
    r = _dispatch(ws, "claude", {"tool_name": "WebFetch",
                                 "tool_input": {"url": WEBFETCH["url"], "prompt": "summarise"}})
    assert _decision(r) == "deny", (r.returncode, r.stdout, r.stderr)
    assert "scoped agent" in r.stderr + r.stdout
    # The unblock hint does not claim Prismor synthesized a scope a human edited.
    assert "edited by hand" in r.stderr + r.stdout
    assert "synthesized from your prompts" not in r.stderr + r.stdout
