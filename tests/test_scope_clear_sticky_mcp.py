"""Session scope: `prismor scope clear` must stick, and MCP tools must be
scope-able.

Regression for the transcript where every prompt re-blocked the PostHog MCP
tool and the user was told to run `prismor scope clear` four times:

- ``scope clear`` deleted the sidecar; the next UserPromptSubmit saw "no scope"
  and synthesised a fresh one — clear meant "reset and guess again", not
  "stop scoping". Now clear leaves an allow-all, operator_edited marker.
- The synthesiser was handed a hardcoded 7-tool list and clamped its output to
  it, so ``mcp__<server>__<tool>`` could *never* be in allowed_tools; every
  MCP call was denied by omission on every prompt regardless of what the
  prompt asked for. Now the reachable MCP servers are passed as
  ``mcp__<server>__*`` families, allow/deny entries may be globs, and MCP
  tools the scope has no opinion on fall through to the base policy.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from prismor.runtime import scoped_agent as sa

POSTHOG_TOOL = "mcp__plugin_posthog_posthog__exec"
POSTHOG_FAMILY = "mcp__plugin_posthog_posthog__*"


@pytest.fixture
def home(tmp_path, monkeypatch):
    ph = tmp_path / "prismor-home"
    ph.mkdir()
    monkeypatch.setenv("PRISMOR_HOME", str(ph))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()
    # Force the static synthesiser: the test must not depend on an API key.
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    return ph


_REPO_ROOT = Path(sa.__file__).parents[2]


def _env(extra=None):
    env = dict(os.environ)
    env.pop("PRISMOR_WORKSPACE", None)
    env.pop("ANTHROPIC_API_KEY", None)
    env["PYTHONPATH"] = str(_REPO_ROOT) + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    env.update(extra or {})
    return env


def _cli(*argv: str, cwd: Path, stdin: str = "") -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "prismor.runtime.immunity_cli", *argv],
        cwd=str(cwd), env=_env(), input=stdin, capture_output=True, text=True, timeout=120,
    )


def _ws(tmp_path: Path) -> Path:
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / ".git").mkdir()
    return ws


def _prompt(ws: Path, text: str, sid: str):
    payload = {"session_id": sid, "cwd": str(ws), "hook_event_name": "UserPromptSubmit", "prompt": text}
    r = _cli("hook-dispatch", "--agent", "claude", "--workspace", str(ws), "--mode", "enforce",
             cwd=ws, stdin=json.dumps(payload))
    assert r.returncode == 0, r.stderr
    return r


def _mcp_call(ws: Path, sid: str, tool: str = POSTHOG_TOOL):
    payload = {"session_id": sid, "cwd": str(ws), "hook_event_name": "PreToolUse",
               "tool_name": tool, "tool_input": {"command": "query trends"}}
    return _cli("hook-dispatch", "--agent", "claude", "--workspace", str(ws), "--mode", "enforce",
                cwd=ws, stdin=json.dumps(payload))


def _blocked_by_scope(r: subprocess.CompletedProcess) -> bool:
    return r.returncode == 2 and "scoped agent" in (r.stderr + r.stdout)


# ── 1. `scope clear` sticks ───────────────────────────────────────────────

def test_scope_clear_survives_the_next_prompt(home, tmp_path):
    ws = _ws(tmp_path)
    sid = "sess-clear"
    _prompt(ws, "What does this repo do?", sid)
    rules = sa.load_scoped_rules(ws, sid)
    assert rules and "*" not in rules["allowed_tools"]

    r = _cli("scope", "clear", sid, cwd=ws)
    assert r.returncode == 0, r.stderr
    assert "Cleared" in r.stdout and "auto-scoping is off" in r.stdout
    assert sa.is_cleared(sa.load_scoped_rules(ws, sid))

    # The bug: this prompt used to re-synthesise a fresh restrictive scope.
    _prompt(ws, "Tell me data for signed-up users, what are they doing in the platform", sid)
    rules = sa.load_scoped_rules(ws, sid)
    assert sa.is_cleared(rules), rules
    assert rules["allowed_tools"] == ["*"]
    assert "prompts_seen" not in rules  # nothing was merged in

    r = _cli("scope", "list", cwd=ws)
    assert "cleared" in r.stdout and "hand-edited" not in r.stdout


def test_scope_clear_on_unknown_session_still_prevents_later_scoping(home, tmp_path):
    ws = _ws(tmp_path)
    sid = "sess-preclear"
    r = _cli("scope", "clear", sid, cwd=ws)
    assert r.returncode == 0
    assert "recorded it as cleared" in r.stdout
    _prompt(ws, "fix the failing tests", sid)
    assert sa.is_cleared(sa.load_scoped_rules(ws, sid))


# ── 2. The transcript, end to end ─────────────────────────────────────────

def _install_posthog_plugin(tmp_path: Path):
    """Mimic Claude Code's installed_plugins.json for the posthog plugin."""
    home = Path(os.environ["HOME"])
    install = tmp_path / "plugin-cache" / "posthog"
    install.mkdir(parents=True)
    (install / ".mcp.json").write_text(json.dumps({"mcpServers": {"posthog": {"type": "http", "url": "https://x"}}}))
    plugins_dir = home / ".claude" / "plugins"
    plugins_dir.mkdir(parents=True)
    (plugins_dir / "installed_plugins.json").write_text(json.dumps({
        "version": 2,
        "plugins": {"posthog@claude-plugins-official": [{"scope": "user", "installPath": str(install)}]},
    }))


def test_transcript_replay_posthog_after_web_preview_prompt(home, tmp_path):
    """First prompt is about the web codebase, second asks for PostHog data.
    Before: PostHog blocked on prompt 2 (and every later prompt, even after
    `scope clear`). After: prompt 2 widens the scope to the posthog family."""
    _install_posthog_plugin(tmp_path)
    ws = _ws(tmp_path)
    sid = "ae2da67a"

    _prompt(ws, "look at the web preview code and summarize the layout", sid)
    rules = sa.load_scoped_rules(ws, sid)
    # Static mode has no opinion on a family the prompt did not name: not
    # denied, not in the inventory. A keyword miss is not a decision, so the
    # call falls through to the base policy instead of being blocked.
    assert POSTHOG_FAMILY not in rules["deny_tools"] and POSTHOG_FAMILY not in rules["inventory"], rules
    assert not _blocked_by_scope(_mcp_call(ws, sid))

    _prompt(ws, "can you tell me from mcp posthog on our product usage and give me a summary", sid)
    rules = sa.load_scoped_rules(ws, sid)
    assert POSTHOG_FAMILY in rules["allowed_tools"] and POSTHOG_FAMILY not in rules["deny_tools"], rules
    r = _mcp_call(ws, sid)
    assert not _blocked_by_scope(r), r.stderr

    # A different MCP server the scope has seen but not been asked for stays denied…
    # (nothing else installed here, so simulate the dashboard adding a deny)
    rules["deny_tools"].append("mcp__node_repl__*")
    sa.save_scoped_rules(ws, sid, rules)
    assert _blocked_by_scope(_mcp_call(ws, sid, "mcp__node_repl__js"))
    # …while posthog remains allowed.
    assert not _blocked_by_scope(_mcp_call(ws, sid))


def test_undiscovered_mcp_server_is_not_denied_by_omission(home, tmp_path):
    """No MCP inventory at all (no plugins, no .mcp.json): a scope synthesised
    from the 7 built-ins has no opinion on MCP, so an MCP call falls through to
    the base policy instead of being blocked forever."""
    ws = _ws(tmp_path)
    sid = "sess-nomcp"
    _prompt(ws, "What does this repo do?", sid)
    rules = sa.load_scoped_rules(ws, sid)
    assert not any(t.startswith("mcp__") for t in rules["allowed_tools"] + rules["deny_tools"])
    r = _mcp_call(ws, sid)
    assert not _blocked_by_scope(r), r.stderr
    # …but the built-in scope is still enforced for built-in tools.
    payload = {"session_id": sid, "cwd": str(ws), "hook_event_name": "PreToolUse",
               "tool_name": "Write", "tool_input": {"file_path": str(ws / "a.txt"), "content": "x"}}
    r = _cli("hook-dispatch", "--agent", "claude", "--workspace", str(ws), "--mode", "enforce",
             cwd=ws, stdin=json.dumps(payload))
    assert _blocked_by_scope(r), r.stderr


# ── 3. check_scoped_rules: globs + MCP semantics ──────────────────────────

def _ev(tool: str, typ: str = "mcp"):
    return {"type": typ, "metadata": {"tool_name": tool}}


def test_family_glob_allows_and_denies():
    allow = {"allowed_tools": ["Read", POSTHOG_FAMILY], "deny_tools": ["mcp__github__*"]}
    assert sa.check_scoped_rules(allow, _ev(POSTHOG_TOOL)) is None
    assert sa.check_scoped_rules(allow, _ev("mcp__github__create_issue")) is not None
    # explicit tool deny still beats a family allow
    both = {"allowed_tools": [POSTHOG_FAMILY], "deny_tools": [POSTHOG_TOOL]}
    assert sa.check_scoped_rules(both, _ev(POSTHOG_TOOL)) is not None


def test_mcp_fallthrough_only_when_scope_is_silent_on_mcp():
    silent = {"allowed_tools": ["Read", "Bash"], "deny_tools": ["Write"]}
    assert sa.check_scoped_rules(silent, _ev(POSTHOG_TOOL)) is None
    opinionated = {"allowed_tools": ["Read", "mcp__github__*"], "deny_tools": []}
    assert sa.check_scoped_rules(opinionated, _ev(POSTHOG_TOOL)) is not None
    # built-ins are unaffected by the fallthrough
    assert sa.check_scoped_rules(silent, _ev("Write", "file_write")) is not None
    assert sa.check_scoped_rules(silent, _ev("Bash", "shell")) is None


def test_hand_edited_scope_does_not_fall_through_for_mcp():
    """Operator narrowed the scope to Read+Bash without mentioning MCP: that
    allowlist is authoritative — MCP tools stay blocked (found by the
    multi-prompt scenario run; auto-synthesised scopes still fall through)."""
    edited = {"allowed_tools": ["Read", "Bash"], "deny_tools": ["Edit", "Write"], "operator_edited": True}
    assert sa.check_scoped_rules(edited, _ev(POSTHOG_TOOL)) is not None
    auto = {"allowed_tools": ["Read", "Bash"], "deny_tools": ["Edit", "Write"]}
    assert sa.check_scoped_rules(auto, _ev(POSTHOG_TOOL)) is None


def test_cleared_scope_allows_everything():
    assert sa.check_scoped_rules(dict(sa.CLEARED_SCOPE), _ev(POSTHOG_TOOL)) is None
    assert sa.check_scoped_rules(dict(sa.CLEARED_SCOPE), _ev("Write", "file_write")) is None


# ── 4. discovery + static fallback ────────────────────────────────────────

def test_discover_mcp_families_reads_claude_configs(home, tmp_path, monkeypatch):
    ws = _ws(tmp_path)
    hp = Path(os.environ["HOME"])
    (hp / ".claude.json").write_text(json.dumps({
        "mcpServers": {"get-an-expert": {}},
        "projects": {str(ws): {"mcpServers": {"notion": {}}},
                     str(tmp_path / "other"): {"mcpServers": {"elsewhere": {}}}},
    }))
    (ws / ".mcp.json").write_text(json.dumps({"mcpServers": {"repo-local": {}}}))
    _install_posthog_plugin(tmp_path)
    fams = sa.discover_mcp_families(ws, "claude")
    assert set(fams) == {"mcp__repo-local__*", "mcp__get-an-expert__*", "mcp__notion__*", POSTHOG_FAMILY}
    tools = sa.available_tools_for_scope(ws, "claude")
    n = len(sa.BUILTIN_SCOPE_TOOLS)
    assert tools[:n] == sa.BUILTIN_SCOPE_TOOLS and POSTHOG_FAMILY in tools


def test_static_fallback_allows_family_named_in_prompt():
    tools = sa.BUILTIN_SCOPE_TOOLS + [POSTHOG_FAMILY, "mcp__plugin_cloudflare_cloudflare-api__*"]
    r = sa._static_fallback_rules("give me a posthog usage summary", tools)
    assert POSTHOG_FAMILY in r["allowed_tools"]
    # Unnamed family: no opinion (not denied, not in the inventory) — it falls
    # through to the base policy rather than being denied on a keyword miss.
    assert "mcp__plugin_cloudflare_cloudflare-api__*" not in r["deny_tools"]
    assert "mcp__plugin_cloudflare_cloudflare-api__*" not in r["inventory"]
    assert r["deny_network"] is False
    r = sa._static_fallback_rules("what does this repo do", tools)
    assert POSTHOG_FAMILY not in r["allowed_tools"] and POSTHOG_FAMILY not in r["deny_tools"]


def test_merge_widens_families_and_drops_them_from_deny():
    old = {"allowed_tools": ["Read"], "deny_tools": ["Bash", POSTHOG_FAMILY], "allowed_paths": ["**"], "deny_network": True}
    new = {"allowed_tools": ["Read", POSTHOG_FAMILY], "deny_tools": ["Bash"], "allowed_paths": ["**"], "deny_network": False}
    m = sa.merge_scoped_rules(old, new)
    assert POSTHOG_FAMILY in m["allowed_tools"] and POSTHOG_FAMILY not in m["deny_tools"]
    assert m["deny_network"] is False


def test_family_helpers():
    assert sa.mcp_family_for_server("plugin:posthog:posthog") == POSTHOG_FAMILY
    assert sa._mcp_family_tokens("mcp__plugin_cloudflare_cloudflare-api__*") == ["cloudflare"]
    assert sa.is_mcp_family(POSTHOG_FAMILY) and not sa.is_mcp_family(POSTHOG_TOOL)
