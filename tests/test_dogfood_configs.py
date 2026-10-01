"""Tripwire for the committed dogfood hook configs (#495).

This repo's own agent sessions run hook-dispatch from the working tree via
scripts/dev-hook.py. The configs are committed, so nothing regenerates them:
these tests fail when they drift from what `install-hooks` would register, or
lose the details that are easy to get wrong (cwd anchoring, exit codes, the
Windows forms).

Regenerate after changing an installer's events/matchers:
    python tests/test_dogfood_configs.py --write
"""
import json
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from prismor.runtime import hooks

ROOT = Path(__file__).resolve().parents[1]
WINDOWS = sys.platform == "win32"
posix_only = pytest.mark.skipif(WINDOWS, reason="POSIX sh guard")
windows_only = pytest.mark.skipif(not WINDOWS, reason="Windows forms")

CONFIGS = {
    "claude": ".claude/settings.json",
    "codex": ".codex/hooks.json",
    "cursor": ".cursor/hooks.json",
    "copilot": ".github/hooks/prismor.json",
}


def _is_stop_class(event):
    return "stop" in event.lower()


def dogfood_command(agent, event=""):
    """The POSIX form: sh on macOS/Linux, Git Bash for Claude Code on Windows."""
    # Claude spawns hooks in the session's *current* cwd, which drifts when the
    # agent cd's, so anchor on $CLAUDE_PROJECT_DIR. The others run hooks from
    # the project root.
    root = "$CLAUDE_PROJECT_DIR" if agent == "claude" else "$(git rev-parse --show-toplevel)"
    # Exit 2 on a Stop-class event means "keep going", and a shell guard can't
    # read stop_hook_active, so it would loop forever.
    code = 1 if _is_stop_class(event) else 2
    # Probe for yaml so a bare system python3 is skipped, not exec'd into an
    # import error. </dev/null: the probe must not eat the hook payload.
    return (
        "sh -c '[ \"$PRISMOR_DOGFOOD\" = 0 ] && exit 0; "
        'for py in "$PRISMOR_DEV_PYTHON" python3 python; do '
        '[ -n "$py" ] && "$py" -c "import yaml" </dev/null 2>/dev/null && '
        f'exec "$py" "{root}/scripts/dev-hook.py" hook-dispatch --agent {agent} --mode observe; done; '
        'echo "prismor dogfood: no python with pyyaml found (pip install pyyaml, or set PRISMOR_DEV_PYTHON)" >&2; '
        f"exit {code}'"
    )


def windows_command(agent):
    """The Windows form, run by PowerShell (Codex's hook shell on Windows, and
    Copilot's `powershell` field) from the project root. `-Command` reports
    only 0/1 for a native command unless told otherwise, and Codex blocks on
    exit 2 alone, so the launcher's exit code is passed through explicitly."""
    return f"& .\\scripts\\dev-hook.cmd hook-dispatch --agent {agent} --mode observe; exit $LASTEXITCODE"


def expected_config(agent):
    cmd = dogfood_command(agent)
    if agent == "claude":
        return hooks._merge_claude({}, cmd, ROOT, pin_workspace=False)
    config = getattr(hooks, f"_merge_{agent}")({}, cmd)
    for entries in config["hooks"].values():
        for entry in entries:
            if agent == "codex":  # Codex: `commandWindows` overrides `command` on Windows
                for h in entry["hooks"]:
                    h["commandWindows"] = windows_command(agent)
            elif agent == "copilot":  # Copilot: `bash` on Unix, `powershell` on Windows
                entry["bash"] = entry.pop("command")
                entry["powershell"] = windows_command(agent)
    return config


_COMMAND_KEYS = ("command", "bash", "powershell", "commandWindows")


def _commands(node, event=""):
    """Yield (event, key, command) for every hook command in a config."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key in _COMMAND_KEYS and isinstance(value, str):
                yield event, key, value
            else:
                yield from _commands(value, key if isinstance(value, list) and key != "hooks" else event)
    elif isinstance(node, list):
        for item in node:
            yield from _commands(item, event)


def _committed(agent):
    return json.loads((ROOT / CONFIGS[agent]).read_text(encoding="utf-8"))


@pytest.mark.parametrize("agent", sorted(CONFIGS))
def test_config_matches_installer_events_and_matchers(agent):
    assert _committed(agent) == expected_config(agent), (
        f"{CONFIGS[agent]} drifted from install-hooks; run: python tests/test_dogfood_configs.py --write"
    )


@pytest.mark.parametrize("agent", sorted(CONFIGS))
def test_commands_use_launcher_anchor_and_exit_split(agent):
    found = list(_commands(_committed(agent)))
    assert found
    for event, key, cmd in found:
        assert "--workspace" not in cmd and str(ROOT) not in cmd
        assert f"hook-dispatch --agent {agent} --mode observe" in cmd
        if key in ("powershell", "commandWindows"):
            assert cmd == windows_command(agent)
            continue
        assert '/scripts/dev-hook.py" hook-dispatch' in cmd
        assert ("$CLAUDE_PROJECT_DIR/" in cmd) == (agent == "claude")
        assert cmd.endswith(f"exit {1 if _is_stop_class(event) else 2}'"), (event, cmd)


def test_windows_launcher_is_crlf():
    raw = (ROOT / "scripts" / "dev-hook.cmd").read_bytes()
    assert raw.count(b"\r\n") == raw.count(b"\n")


def _env(tmp_path, **extra):
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    env = {k: v for k, v in os.environ.items() if not k.startswith("PRISMOR_")}
    env.update(HOME=str(home), USERPROFILE=str(home), PRISMOR_HOME=str(home / ".prismor"),
               PRISMOR_NO_UPDATE_CHECK="1")
    env.update(extra)
    return env


def _rm_rf(cwd):
    return json.dumps({
        "hook_event_name": "PreToolUse", "session_id": "dogfood-test", "cwd": str(cwd),
        "tool_name": "Bash", "tool_input": {"command": "rm -rf /"},
    })


def _screened(proc):
    # Observe mode lets the call through but reports the floor rule it hit,
    # which proves the payload reached the working tree's engine intact.
    return proc.returncode == 0 and "Blocks rm -rf /" in proc.stderr


@posix_only
def test_claude_command_screens_from_a_drifted_cwd(tmp_path):
    drifted = ROOT / "prismor" / "runtime"
    proc = subprocess.run(
        dogfood_command("claude"), shell=True, cwd=drifted, input=_rm_rf(drifted), capture_output=True,
        encoding="utf-8", errors="replace", env=_env(tmp_path, CLAUDE_PROJECT_DIR=str(ROOT), PRISMOR_DEV_PYTHON=sys.executable),
        timeout=120,
    )
    assert _screened(proc), proc.stderr


@posix_only
@pytest.mark.parametrize("agent", ["codex", "cursor", "copilot"])
def test_git_rooted_commands_screen(agent, tmp_path):
    proc = subprocess.run(
        dogfood_command(agent), shell=True, cwd=ROOT, input=_rm_rf(ROOT), capture_output=True, encoding="utf-8", errors="replace",
        env=_env(tmp_path, PRISMOR_DEV_PYTHON=sys.executable), timeout=120,
    )
    assert proc.returncode == 0, proc.stderr


@posix_only
def test_no_usable_interpreter_fails_loud(tmp_path):
    # PATH with sh but no python: the guard must say so and block, not no-op.
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "sh").symlink_to(shutil.which("sh"))
    proc = subprocess.run(
        dogfood_command("claude"), shell=True, cwd=tmp_path, input=_rm_rf(tmp_path), capture_output=True,
        encoding="utf-8", errors="replace", env=_env(tmp_path, CLAUDE_PROJECT_DIR=str(ROOT), PATH=str(bin_dir),
                            PRISMOR_DEV_PYTHON="/nonexistent/python"),
    )
    assert proc.returncode == 2 and "no python with pyyaml" in proc.stderr


@posix_only
def test_dogfood_off_switch(tmp_path):
    proc = subprocess.run(
        dogfood_command("claude"), shell=True, cwd=tmp_path, input=_rm_rf(tmp_path), capture_output=True,
        encoding="utf-8", errors="replace", env=_env(tmp_path, CLAUDE_PROJECT_DIR=str(tmp_path), PRISMOR_DOGFOOD="0"),
    )
    assert proc.returncode == 0 and not proc.stderr


def _run_broken_tree(tmp_path, payload, agent="claude"):
    # A tree whose prismor package won't import: the launcher alone, no package.
    (tmp_path / "scripts").mkdir(exist_ok=True)
    shutil.copy(ROOT / "scripts" / "dev-hook.py", tmp_path / "scripts")
    return subprocess.run(
        # -S -E: don't let an installed prismor in site-packages mask the break.
        [sys.executable, "-S", "-E", str(tmp_path / "scripts" / "dev-hook.py"), "hook-dispatch", "--agent", agent],
        input=json.dumps(payload), capture_output=True, encoding="utf-8", errors="replace", cwd=tmp_path,
    )


@pytest.mark.parametrize("payload,code", [
    ({"hook_event_name": "PreToolUse", "tool_name": "Bash"}, 2),       # loud
    ({"hook_event_name": "PreToolUse", "tool_name": "WebFetch"}, 2),
    ({"hook_event_name": "PreToolUse", "tool_name": "Read"}, 0),       # the agent can still see and fix it
    ({"hook_event_name": "PreToolUse", "tool_name": "Edit"}, 0),
    ({"hook_event_name": "PreToolUse", "tool_name": "apply_patch"}, 0),
    ({"hook_event_name": "UserPromptSubmit"}, 0),                      # never eat the prompt
    ({"hook_event_name": "SessionStart"}, 0),
    ({"hook_event_name": "Stop"}, 1),                                  # 2 would loop forever
    ({"hook_event_name": "SubagentStop"}, 1),
    ({"hook_event_name": "PostToolUse", "stop_hook_active": True}, 1),
])
def test_broken_working_tree_policy(tmp_path, payload, code):
    proc = _run_broken_tree(tmp_path, payload)
    assert proc.returncode == code, proc.stderr
    assert "working tree" in proc.stderr and "is broken" in proc.stderr


def test_broken_tree_tells_claude_on_prompt(tmp_path):
    proc = _run_broken_tree(tmp_path, {"hook_event_name": "UserPromptSubmit"})
    assert "is broken" in proc.stdout  # stdout on UserPromptSubmit reaches the model


def test_cursor_payload_on_claude_hook_is_skipped(tmp_path):
    # Cursor runs .claude/settings.json hooks with camelCase payloads; the
    # launcher must exit before even importing (a broken tree still exits 0).
    proc = _run_broken_tree(tmp_path, {"hook_event_name": "preToolUse", "tool_name": "Shell"})
    assert proc.returncode == 0 and not proc.stderr


# --- Windows: the forms Codex and Copilot run, under each shell they might use --

def _windows_shells():
    shells = [["powershell", "-NoProfile", "-Command"]]
    if shutil.which("pwsh"):
        shells.append(["pwsh", "-NoProfile", "-Command"])
    return shells


@windows_only
@pytest.mark.parametrize("agent", ["codex", "copilot"])
@pytest.mark.parametrize("shell", _windows_shells(), ids=lambda s: s[0])
def test_windows_form_screens_under_shell(agent, shell, tmp_path):
    [cmd] = {c for _, key, c in _commands(_committed(agent)) if key in ("powershell", "commandWindows")}
    proc = subprocess.run(
        shell + [cmd], cwd=ROOT, input=_rm_rf(ROOT), capture_output=True, encoding="utf-8", errors="replace",
        env=_env(tmp_path, PRISMOR_DEV_PYTHON=sys.executable), timeout=180,
    )
    assert _screened(proc), (proc.returncode, proc.stdout, proc.stderr)


@windows_only
@pytest.mark.parametrize("shell", _windows_shells(), ids=lambda s: s[0])
def test_windows_form_fails_loud_without_python(shell, tmp_path):
    system32 = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")
    env = _env(tmp_path, PATH=";".join([system32, os.path.join(system32, "WindowsPowerShell", "v1.0")]))
    env.pop("PRISMOR_DEV_PYTHON", None)
    exe = shutil.which(shell[0])  # resolve before PATH is narrowed
    proc = subprocess.run(
        [exe] + shell[1:] + [windows_command("codex")], cwd=ROOT, input=_rm_rf(ROOT),
        capture_output=True, encoding="utf-8", errors="replace", env=env, timeout=120,
    )
    assert proc.returncode == 2 and "no python with pyyaml" in proc.stderr, (proc.returncode, proc.stderr)


@windows_only
def test_cmd_launcher_itself_under_cmd_exe(tmp_path):
    # Some Codex builds reportedly spawn hooks through cmd.exe; the launcher
    # must keep its exit codes there too.
    system32 = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")
    launcher = [".\\scripts\\dev-hook.cmd", "hook-dispatch", "--agent", "codex", "--mode", "observe"]
    ok = subprocess.run(["cmd", "/d", "/c"] + launcher, cwd=ROOT, input=_rm_rf(ROOT), capture_output=True,
                        encoding="utf-8", errors="replace", env=_env(tmp_path, PRISMOR_DEV_PYTHON=sys.executable),
                        timeout=180)
    assert _screened(ok), (ok.returncode, ok.stderr)
    env = _env(tmp_path, PATH=system32)
    env.pop("PRISMOR_DEV_PYTHON", None)
    loud = subprocess.run([shutil.which("cmd"), "/d", "/c"] + launcher, cwd=ROOT, input=_rm_rf(ROOT),
                          capture_output=True, encoding="utf-8", errors="replace", env=env, timeout=120)
    assert loud.returncode == 2 and "no python with pyyaml" in loud.stderr, (loud.returncode, loud.stderr)


@windows_only
def test_claude_form_screens_under_git_bash(tmp_path):
    # Claude Code on Windows runs hook strings in Git Bash. Not System32's bash.exe, which is WSL.
    bash = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Git" / "bin" / "bash.exe"
    if not bash.exists():
        pytest.skip("Git Bash not installed")
    drifted = ROOT / "prismor" / "runtime"
    [cmd] = {c for _, _, c in _commands(_committed("claude"))}
    proc = subprocess.run(
        [str(bash), "-c", cmd], cwd=drifted, input=_rm_rf(drifted), capture_output=True, encoding="utf-8", errors="replace",
        env=_env(tmp_path, CLAUDE_PROJECT_DIR=str(ROOT), PRISMOR_DEV_PYTHON=Path(sys.executable).as_posix()),
        timeout=180,
    )
    assert _screened(proc), (proc.returncode, proc.stdout, proc.stderr)


# --- the commands install-hooks generates for users --------------------------

@pytest.fixture
def fake_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", staticmethod(lambda: home))
    for var in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(var, str(home))
    monkeypatch.setenv("PRISMOR_HOME", str(home / ".prismor"))
    monkeypatch.setenv("CODEX_HOME", str(home / ".codex"))
    return home


_INLINE_AGENTS = [a for a in hooks._SUPPORTED_AGENTS if a not in hooks._PLUGIN_REGISTERED_AGENTS]


@pytest.mark.parametrize("agent", _INLINE_AGENTS)
def test_installed_command_is_executable_as_written(agent, tmp_path, fake_home):
    ws = tmp_path / "ws"
    ws.mkdir()
    for scope in ("project", "global"):
        [result] = hooks.install_hooks(repo_root=ROOT, workspace=ws, agent=agent, scope=scope, mode="observe")
        config = json.loads(Path(result["configPath"]).read_text(encoding="utf-8"))
        cmds = [c for _, _, c in _commands(config) if "hook-dispatch" in c]
        assert cmds, f"{agent}/{scope}: no hook-dispatch command in {result['configPath']}"
        for cmd in cmds:
            argv = shlex.split(cmd, posix=not WINDOWS)
            argv = [a.strip('"') for a in argv]
            assert os.access(argv[0], os.X_OK), f"{agent}/{scope}: interpreter missing: {argv[0]}"
            assert Path(argv[1]).is_file(), f"{agent}/{scope}: shim missing: {argv[1]}"
            assert argv[2:5] == ["hook-dispatch", "--agent", agent]


@pytest.mark.parametrize("agent", hooks._SUPPORTED_AGENTS)
def test_installed_command_runs_under_the_platform_shell(agent, tmp_path, fake_home):
    # Existing and well-formed is not enough: gemini and opencode commands once
    # pointed at an --agent value hook-dispatch's argparse rejected, which exits
    # 2 -- a block on every tool call for those agents.
    cmd = hooks._dispatcher_command(repo_root=ROOT, workspace=tmp_path, agent=agent, mode="observe")
    proc = subprocess.run(cmd, shell=True, input="{}", capture_output=True, encoding="utf-8", errors="replace",
                          env=dict(os.environ, PRISMOR_NO_UPDATE_CHECK="1"), timeout=120)
    assert proc.returncode == 0, proc.stderr[-2000:]


if __name__ == "__main__" and "--write" in sys.argv:
    for agent, rel in CONFIGS.items():
        path = ROOT / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(expected_config(agent), indent=2) + "\n", encoding="utf-8")
        print(f"wrote {rel}")
