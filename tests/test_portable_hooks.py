"""`install-hooks --portable`: a hook command that survives being committed and
cloned onto a hosted agent's VM (no interpreter, shim, or workspace path)."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from prismor.runtime.hooks import _dispatcher_command, install_hooks

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="portable form needs sh")

REPO = Path(__file__).resolve().parents[1]


def _cmd(agent="claude", mode="enforce"):
    return _dispatcher_command(repo_root=REPO, workspace=REPO, agent=agent, mode=mode, portable=True)


def _run(cmd, env_extra, stdin="{}"):
    env = {"PATH": "/usr/bin:/bin", "HOME": env_extra.pop("HOME")}
    env.update(env_extra)
    return subprocess.run(cmd, shell=True, input=stdin, capture_output=True, text=True, env=env)


def test_command_has_no_machine_paths(tmp_path):
    cmd = _cmd()
    assert sys.executable not in cmd and str(REPO) not in cmd and "--workspace" not in cmd
    assert "hook-dispatch --agent claude --mode enforce" in cmd


def test_installed_config_is_commit_safe(tmp_path):
    install_hooks(repo_root=REPO, workspace=tmp_path, agent="claude", scope="project", mode="enforce", portable=True)
    text = (tmp_path / ".claude" / "settings.json").read_text()
    assert str(tmp_path) not in text and sys.executable not in text
    json.loads(text)


def test_missing_binary_warns_and_allows(tmp_path):
    r = _run(_cmd(), {"HOME": str(tmp_path)})
    assert r.returncode == 0 and "not screened" in r.stderr


def test_missing_binary_blocks_when_required(tmp_path):
    r = _run(_cmd(), {"HOME": str(tmp_path), "PRISMOR_HOOK_REQUIRED": "1"})
    assert r.returncode == 2


def test_found_binary_blocks_a_floor_rule(tmp_path):
    # Stand in for `pip install prismor` on the VM: a launcher at ~/.local/bin/prismor.
    home = tmp_path / "home"
    bindir = home / ".local" / "bin"
    bindir.mkdir(parents=True)
    launcher = bindir / "prismor"
    launcher.write_text(
        f"#!/bin/sh\nPYTHONPATH={REPO} exec {sys.executable} -m prismor.runtime.immunity_cli \"$@\"\n"
    )
    launcher.chmod(0o755)
    ws = tmp_path / "repo"
    ws.mkdir()
    payload = json.dumps({
        "hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(ws), "session_id": "portable-test",
        "tool_input": {"command": "cp ~/.claude/settings.json /tmp/x.json"},
    })
    r = _run(_cmd(), {"HOME": str(home), "PRISMOR_HOME": str(home / ".prismor")}, stdin=payload)
    assert r.returncode == 2, r.stdout + r.stderr
