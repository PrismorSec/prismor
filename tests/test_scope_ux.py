"""Scope UX regressions found by live-testing 1.42.0 on a fresh machine.

- ``prismor scope edit`` crashed (UnboundLocalError: subprocess shadowed).
- ``prismor scope show <id>`` rejected the positional id every message told
  users to type.
- Session scope was synthesised from the first prompt only, so a session that
  opened with "what does this repo do?" was Read-only forever; Codex (no Read
  tool) could not even ``cat`` a file.
- Runtime findings (scoped-agent/IAM/kill-switch) were wiped by the next
  event's session snapshot, so an enforce block vanished from ``prismor status``.
- ``status --all`` never listed a workspace under the single-DB layout.
- Global (~/.claude) hooks pinned the directory setup ran from as the
  workspace for every repo on the machine.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from prismor.runtime import scoped_agent as sa
from prismor.runtime import store


@pytest.fixture
def home(tmp_path, monkeypatch):
    ph = tmp_path / "prismor-home"
    ph.mkdir()
    monkeypatch.setenv("PRISMOR_HOME", str(ph))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()
    return ph


_REPO_ROOT = Path(sa.__file__).parents[2]


def _env(extra=None):
    env = dict(os.environ)
    env.pop("PRISMOR_WORKSPACE", None)  # the test host may itself be hooked
    env["PYTHONPATH"] = str(_REPO_ROOT) + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    env.update(extra or {})
    return env


def _cli(*argv: str, cwd: Path, env_extra=None, stdin: str = "") -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "prismor.runtime.immunity_cli", *argv],
        cwd=str(cwd), env=_env(env_extra), input=stdin, capture_output=True, text=True, timeout=120,
    )


# ── prismor scope edit / show ─────────────────────────────────────────────

def test_scope_edit_does_not_crash_and_marks_operator_edit(home, tmp_path):
    ws = tmp_path / "ws"; ws.mkdir()
    sa.save_scoped_rules(ws, "sess-1", {"allowed_tools": ["Read"], "deny_tools": ["Bash"],
                                        "allowed_paths": ["**"], "deny_network": True})
    # EDITOR that appends nothing but touches the file → unchanged → no flag
    r = _cli("scope", "edit", "sess-1", cwd=ws, env_extra={"EDITOR": "true"})
    assert r.returncode == 0, r.stderr
    assert not sa.load_scoped_rules(ws, "sess-1").get("operator_edited")
    # EDITOR that rewrites the file → flagged as operator-edited
    editor = tmp_path / "ed.sh"
    editor.write_text('#!/bin/sh\nprintf \'{"allowed_tools": ["Read","Bash"], "deny_tools": []}\' > "$1"\n')
    editor.chmod(0o755)
    r = _cli("scope", "edit", "sess-1", cwd=ws, env_extra={"EDITOR": str(editor)})
    assert r.returncode == 0, r.stderr
    rules = sa.load_scoped_rules(ws, "sess-1")
    assert rules["operator_edited"] is True and "Bash" in rules["allowed_tools"]


def test_scope_edit_restores_on_invalid_json(home, tmp_path):
    ws = tmp_path / "ws"; ws.mkdir()
    sa.save_scoped_rules(ws, "sess-2", {"allowed_tools": ["Read"], "deny_tools": []})
    editor = tmp_path / "bad.sh"
    editor.write_text('#!/bin/sh\nprintf "{not json" > "$1"\n'); editor.chmod(0o755)
    r = _cli("scope", "edit", "sess-2", cwd=ws, env_extra={"EDITOR": str(editor)})
    assert r.returncode == 1 and "not valid JSON" in r.stderr
    assert sa.load_scoped_rules(ws, "sess-2")["allowed_tools"] == ["Read"]


def test_scope_show_accepts_positional_id_latest_and_prefix(home, tmp_path):
    ws = tmp_path / "ws"; ws.mkdir()
    sa.save_scoped_rules(ws, "aaaa-1111", {"allowed_tools": ["Read"], "deny_tools": []})
    for ref in ("aaaa-1111", "aaaa", "latest"):
        r = _cli("scope", "show", ref, cwd=ws)
        assert r.returncode == 0 and "allowed_tools:  [Read]" in r.stdout, (ref, r.stdout, r.stderr)
    r = _cli("scope", "show", "--session-id", "aaaa-1111", cwd=ws)   # old spelling still works
    assert r.returncode == 0 and "allowed_tools:  [Read]" in r.stdout


def test_workspace_hint_names_the_real_command():
    src = (Path(sa.__file__).parent / "cli.py").read_text()
    assert "prismor scope personal" not in src and "prismor scope managed" not in src


# ── scope widening across prompts ─────────────────────────────────────────

def test_static_rules_keep_bash_and_merge_widens():
    first = sa._static_fallback_rules("What does this repo do? Summarize README.md",
                                      ["Bash", "Read", "Edit", "Write", "WebFetch"])
    assert "Bash" in first["allowed_tools"] and "Read" in first["allowed_tools"]
    assert "Edit" in first["deny_tools"] and first["deny_network"] is False  # static never guesses network
    second = sa._static_fallback_rules("Now fix the typo in README.md and fetch the changelog from the url",
                                       ["Bash", "Read", "Edit", "Write", "WebFetch"])
    merged = sa.merge_scoped_rules(first, second)
    assert {"Read", "Bash", "Edit", "Write", "WebFetch"} <= set(merged["allowed_tools"])
    assert merged["deny_tools"] == [] and merged["deny_network"] is False
    assert merged["prompts_seen"] == 2


def test_shell_only_agents_always_keep_bash():
    rules = {"allowed_tools": ["Read"], "deny_tools": ["Bash", "Edit"], "allowed_paths": ["**"], "deny_network": True}
    out = sa.apply_agent_invariants(dict(rules), "codex")
    assert "Bash" in out["allowed_tools"] and "Bash" not in out["deny_tools"]
    assert sa.apply_agent_invariants(dict(rules), "claude")["deny_tools"] == ["Bash", "Edit"]


def test_hook_dispatch_widens_scope_on_second_prompt(home, tmp_path):
    ws = tmp_path / "ws"; ws.mkdir()
    (ws / ".git").mkdir()
    def prompt(text, sid="sess-w"):
        payload = {"session_id": sid, "cwd": str(ws), "hook_event_name": "UserPromptSubmit", "prompt": text}
        return _cli("hook-dispatch", "--agent", "claude", "--workspace", str(ws), "--mode", "enforce",
                    cwd=ws, stdin=json.dumps(payload))
    r = prompt("What does this repo do?")
    assert r.returncode == 0, r.stderr
    rules = sa.load_scoped_rules(ws, "sess-w")
    assert "Edit" in rules["deny_tools"]
    r = prompt("Now edit README.md and add a line")
    assert r.returncode == 0, r.stderr
    rules = sa.load_scoped_rules(ws, "sess-w")
    assert "Edit" in rules["allowed_tools"] and "Edit" not in rules["deny_tools"]
    assert rules["prompts_seen"] == 2
    # operator edit freezes it
    rules["operator_edited"] = True; rules["allowed_tools"] = ["Read"]; rules["deny_tools"] = ["Bash"]
    sa.save_scoped_rules(ws, "sess-w", rules)
    prompt("run the tests")
    assert sa.load_scoped_rules(ws, "sess-w")["deny_tools"] == ["Bash"]


# ── runtime findings survive the next snapshot ────────────────────────────

def test_runtime_findings_survive_next_snapshot(home, tmp_path):
    ws = tmp_path / "ws"; ws.mkdir()
    sid = "sess-f"
    from prismor.runtime.cli import analyze_events
    ev = {"ts": "2026-08-15T00:00:00+00:00", "type": "shell", "command": "ls", "agent": "claude",
          "agent_event": "PreToolUse", "metadata": {"tool_name": "Bash"}}
    store.append_session_event(ws, sid, ev)
    events = store.read_session_events(ws, sid)
    store.save_session_snapshot(workspace=ws, session_id=sid, agent="claude", source="hook", repo_url=None,
                                events=events, analysis=analyze_events(events, repo_root=ws, workspace=ws, session_id=sid))
    store.persist_runtime_findings(ws, sid, [{"id": f"{sid}:scoped-agent", "severity": "HIGH", "category": "scoped_agent",
                                              "title": "[scoped agent] Tool 'Edit' is explicitly denied", "evidence": "x",
                                              "ruleId": "scoped-agent", "action": "block", "mode": "enforce"}], 1)
    assert store.get_session(ws, sid)["findingsCount"] == 1
    # next benign event → snapshot again
    store.append_session_event(ws, sid, dict(ev, ts="2026-08-15T00:00:01+00:00", command="echo hi"))
    events = store.read_session_events(ws, sid)
    store.save_session_snapshot(workspace=ws, session_id=sid, agent="claude", source="hook", repo_url=None,
                                events=events, analysis=analyze_events(events, repo_root=ws, workspace=ws, session_id=sid))
    s = store.get_session(ws, sid)
    assert s["findingsCount"] == 1 and s["riskScore"] >= 70


def test_registered_workspaces_listed_with_shared_db(home, tmp_path):
    ws = tmp_path / "ws"; ws.mkdir()
    store.register_workspace(ws)
    store.initialize_database(ws)
    assert ws.resolve() in [p.resolve() for p in store.list_registered_workspaces()]


# ── global hooks: no pinned workspace ─────────────────────────────────────

def test_global_hook_command_has_no_pinned_workspace(home, tmp_path):
    from prismor.runtime import hooks
    ws = tmp_path / "ws"; ws.mkdir()
    repo_root = Path(sa.__file__).parents[2]
    hooks.install_hooks(repo_root=repo_root, workspace=ws, agent="claude", scope="global", mode="observe")
    cfg = json.loads((Path(os.environ["HOME"]) / ".claude" / "settings.json").read_text())
    cmd = cfg["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
    assert "--workspace" not in cmd and "PRISMOR_WORKSPACE" not in json.dumps(cfg.get("env", {}))
    hooks.install_hooks(repo_root=repo_root, workspace=ws, agent="claude", scope="project", mode="observe")
    cfg = json.loads((ws / ".claude" / "settings.json").read_text())
    assert f'--workspace "{ws}"' in cfg["hooks"]["PreToolUse"][0]["hooks"][0]["command"]


def test_hook_dispatch_resolves_workspace_from_payload_cwd(home, tmp_path):
    repo = tmp_path / "repo"; (repo / "sub").mkdir(parents=True); (repo / ".git").mkdir()
    payload = {"session_id": "sess-cwd", "cwd": str(repo / "sub"), "hook_event_name": "PreToolUse",
               "tool_name": "Bash", "tool_input": {"command": "ls"}}
    r = _cli("hook-dispatch", "--agent", "claude", "--mode", "observe", cwd=tmp_path, stdin=json.dumps(payload))
    assert r.returncode == 0, r.stderr
    assert store.get_session(repo, "sess-cwd")["workspacePath"] == str(repo.resolve())


def test_scope_flag_accepts_both_spellings(home, tmp_path):
    ws = tmp_path / "ws"; ws.mkdir()
    assert _cli("install-hooks", "--agent", "claude", "--scope", "global", cwd=ws).returncode == 0
    assert _cli("uninstall-hooks", "--agent", "claude", "--scope", "global", cwd=ws).returncode == 0
    assert _cli("cloak", "status", "--scope", "global", cwd=ws).returncode == 0
