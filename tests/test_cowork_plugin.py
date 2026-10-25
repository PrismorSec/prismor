"""Cowork plugin: the wrapper Cowork runs in its sandbox, driven against the working tree."""
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
COWORK = ROOT / "packaging" / "cowork"


def _build_module():
    spec = importlib.util.spec_from_file_location("cowork_build", COWORK / "build_plugin.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _plugin(tmp_path):
    """The template plus a policy and a vendor/ that is just this checkout -
    the same layout build_plugin.py zips, minus the pip download."""
    root = tmp_path / "plugin"
    shutil.copytree(COWORK / "template", root)
    (root / "policy.yaml").write_text(_build_module().cowork_policy())
    (root / "vendor").mkdir()
    (root / "vendor" / "prismor").symlink_to(ROOT / "prismor")
    bindir = tmp_path / "bin"
    bindir.mkdir()
    (bindir / "python3").symlink_to(sys.executable)
    # The wrapper only runs on Linux (the sandbox); pretend, so this runs anywhere.
    (bindir / "uname").write_text('#!/bin/sh\necho "${FAKE_UNAME:-Linux}"\n')
    (bindir / "uname").chmod(0o755)
    return root, bindir


def _hook(root, bindir, tmp_path, event, **extra_env):
    work = tmp_path / "work"
    work.mkdir(exist_ok=True)
    env = {k: v for k, v in os.environ.items() if not k.startswith("PRISMOR_")}
    env.update(PATH=f"{bindir}{os.pathsep}{env.get('PATH', '')}", CLAUDE_PLUGIN_ROOT=str(root),
               CLAUDE_PLUGIN_DATA=str(tmp_path / "data"), HOME=str(tmp_path), **extra_env)
    payload = {"session_id": "cowork-t", "cwd": str(work), **event}
    return subprocess.run(["sh", str(root / "hooks" / "prismor-hook.sh")], input=json.dumps(payload),
                          capture_output=True, text=True, env=env, cwd=work, timeout=120)


def test_hooks_cover_prompt_tools_and_session_end():
    hooks = json.loads((COWORK / "template" / "hooks" / "hooks.json").read_text())["hooks"]
    assert set(hooks) == {"UserPromptSubmit", "PreToolUse", "PostToolUse", "SessionEnd"}
    assert os.access(COWORK / "template" / "hooks" / "prismor-hook.sh", os.X_OK)


def test_secret_read_blocks_with_cowork_message(tmp_path):
    root, bindir = _plugin(tmp_path)
    r = _hook(root, bindir, tmp_path, {"hook_event_name": "PreToolUse", "tool_name": "Bash",
                                       "tool_input": {"command": "cat .env"}})
    assert r.returncode == 2, r.stderr
    assert "secret-file-shell-read" in r.stderr
    # The laptop unblock steps are useless in a sandbox and must not reach the agent.
    assert "Cowork sandbox" in r.stderr and "prismor allow" not in r.stderr


def test_web_fetch_is_reported_not_blocked(tmp_path):
    root, bindir = _plugin(tmp_path)
    r = _hook(root, bindir, tmp_path, {"hook_event_name": "PreToolUse", "tool_name": "WebFetch",
                                       "tool_input": {"url": "https://example.com"}})
    assert r.returncode == 0, r.stderr


def test_steps_aside_outside_the_linux_sandbox(tmp_path):
    # The desktop app runs synced plugins in local sessions too; the laptop's own
    # install governs those, so the plugin must not screen or report there.
    root, bindir = _plugin(tmp_path)
    r = _hook(root, bindir, tmp_path, {"hook_event_name": "PreToolUse", "tool_name": "Bash",
                                       "tool_input": {"command": "cat .env"}}, FAKE_UNAME="Darwin")
    assert r.returncode == 0 and not r.stderr
    assert not (tmp_path / "data").exists()
