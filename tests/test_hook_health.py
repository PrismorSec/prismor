"""Hook configuration is evidence of wiring, not proof of enforcement (#489)."""
import json
import os
import sys
import subprocess
import venv
from datetime import datetime, timezone
from pathlib import Path

import pytest

from prismor.runtime import cli, hooks


@pytest.fixture(autouse=True)
def isolated_client_home(tmp_path, monkeypatch):
    # Path.home() uses USERPROFILE, not HOME, on Windows. Keep global
    # client configs out of the real profile and out of subsequent tests.
    home = tmp_path / "client-home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setattr(hooks.Path, "home", lambda: home)


def configure(workspace, agent, command, scope="project"):
    command = command.replace("--agent claude", "--agent " + agent)
    path = hooks._config_path(agent, scope, workspace)
    path.parent.mkdir(parents=True, exist_ok=True)
    from prismor.runtime.integrations.registry import get
    event = next(e for e in get(agent).events if hooks._is_pre_action(e) and "prompt" not in e.lower())
    config = {"hooks": {event: [
        {"hooks": [{"type": "command", "command": command}]}]}}
    if agent == "antigravity":
        config = hooks._merge_antigravity({}, command)
    path.write_text(json.dumps(config))
    return path


def launcher(tmp_path, executable=None):
    shim = tmp_path / "directory with spaces" / "hook-dispatch.py"
    shim.parent.mkdir()
    # Must never be executed by a passive health check.
    shim.write_text("raise RuntimeError('health check executed the hook')\n")
    return f'"{executable or sys.executable}" "{shim}" hook-dispatch --agent claude --workspace "{tmp_path}" --mode enforce'


@pytest.mark.parametrize("agent", ["claude", "crush", "openhands", "qwen", "continue", "goose", "gemini", "antigravity"])
def test_registry_agents_and_quoted_paths(tmp_path, agent):
    configure(tmp_path, agent, launcher(tmp_path))
    checks = hooks.hook_health(tmp_path)
    assert len(checks) == 1
    assert checks[0]["state"] == "ok"
    assert checks[0]["agent"] == agent
    assert checks[0]["mode"] == "enforce"
    assert "invocation not verified" in checks[0]["detail"]
    assert cli._hooks_by_scope(tmp_path)["project"] == {agent: "enforce"}


def test_missing_interpreter(tmp_path):
    configure(tmp_path, "claude", launcher(tmp_path, str(tmp_path / "missing-python")))
    check = hooks.hook_health(tmp_path)[0]
    assert check["configured"] and check["state"] == "fail"
    assert "interpreter" in check["detail"]


@pytest.mark.parametrize("scope", ["project", "global"])
def test_opencode_plugin_is_configured_but_not_runtime_verified(tmp_path, scope):
    path = hooks._config_path("opencode", scope, tmp_path)
    hooks._write_opencode_plugin(path, launcher(tmp_path))
    checks = hooks.hook_health(tmp_path, self_test=True)
    assert len(checks) == 1
    assert checks[0]["agent"] == "opencode"
    assert checks[0]["scope"] == scope
    assert checks[0]["configured"] is True
    assert checks[0]["state"] == "warn"
    assert "invocation not verified" in checks[0]["detail"]
    assert cli._hooks_by_scope(tmp_path)[scope] == {"opencode": "enforce"}


def test_missing_dispatcher(tmp_path):
    command = f'"{sys.executable}" "{tmp_path}/hook-dispatch.py" hook-dispatch --agent claude --workspace "{tmp_path}" --mode enforce'
    configure(tmp_path, "claude", command)
    check = hooks.hook_health(tmp_path)[0]
    assert check["state"] == "fail"
    assert "script is missing" in check["detail"]


def test_relative_interpreter_is_resolved_from_workspace(tmp_path, monkeypatch):
    environment = tmp_path / "environment with spaces"
    venv.EnvBuilder(with_pip=False).create(environment)
    executable = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    relative = executable.relative_to(tmp_path).as_posix()
    configure(tmp_path, "claude", launcher(tmp_path, relative))
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    assert hooks.hook_health(tmp_path)[0]["state"] == "ok"


@pytest.mark.skipif(os.name == "nt", reason="Windows does not use POSIX execute permission bits")
def test_nonexecutable_interpreter_fails(tmp_path):
    executable = tmp_path / "python"
    executable.write_text("must not run")
    executable.chmod(0o600)
    configure(tmp_path, "claude", launcher(tmp_path, str(executable)))
    assert hooks.hook_health(tmp_path)[0]["state"] == "fail"


def test_invalid_config_is_visible(tmp_path):
    path = configure(tmp_path, "claude", "unused")
    path.write_text("{broken")
    check = hooks.hook_health(tmp_path)[0]
    assert check["state"] == "fail" and not check["configured"]


@pytest.mark.parametrize("command", ["sh -c 'prismor hook-dispatch --mode enforce'", "custom hook-dispatch", '"bad hook-dispatch'])
def test_unrecognized_launchers_are_not_verified(tmp_path, command):
    configure(tmp_path, "claude", command)
    assert hooks.hook_health(tmp_path)[0]["state"] in ("warn", "fail")


def test_marker_in_unrelated_metadata_is_not_a_hook(tmp_path):
    path = configure(tmp_path, "claude", "echo hello")
    path.write_text(json.dumps({"description": "hook-dispatch --mode enforce", "hooks": {}}))
    assert hooks.hook_health(tmp_path) == []


def test_registered_plugin_is_unverified(tmp_path):
    path = hooks._config_path("openclaw", "project", tmp_path)
    path.parent.mkdir()
    path.write_text(json.dumps({"plugins": ["/missing/prismor/plugin.js"]}))
    check = hooks.hook_health(tmp_path)[0]
    assert check["agent"] == "openclaw" and check["state"] == "warn"
    assert check["configured"] and check["mode"] is None


def test_both_scopes_and_mode_resolution(tmp_path):
    command = launcher(tmp_path)
    configure(tmp_path, "qwen", command.replace("enforce", "observe"))
    configure(tmp_path, "qwen", command, "global")
    assert cli._hooks_by_scope(tmp_path) == {"project": {"qwen": "observe"}, "global": {"qwen": "enforce"}}


def test_status_surfaces_broken_hook(tmp_path, capsys):
    configure(tmp_path, "claude", launcher(tmp_path, str(tmp_path / "missing-python")))
    cli._print_status_overview(tmp_path)
    out = capsys.readouterr().out
    assert "interpreter is missing" in out
    assert "agent invocation not verified" in out


def test_doctor_json_fails_for_broken_hook(tmp_path, capsys):
    configure(tmp_path, "claude", launcher(tmp_path, str(tmp_path / "missing-python")))
    with pytest.raises(SystemExit) as exc:
        cli._run_doctor(tmp_path, as_json=True)
    assert exc.value.code != 0
    payload = json.loads(capsys.readouterr().out)
    assert any(c["name"] == "hook claude (project)" and c["state"] == "fail" for c in payload["checks"])


def generated_launcher(tmp_path, root=None):
    root = root or Path(__file__).resolve().parents[1]
    shim = tmp_path / "hook-dispatch.py"
    shim.write_text(hooks._SHIM_TEMPLATE.format(repo_root=str(root)))
    return f'"{sys.executable}" "{shim}" hook-dispatch --agent claude --workspace "{tmp_path}" --mode enforce'


def test_live_dispatcher_self_test_uses_disposable_state(tmp_path):
    configure(tmp_path, "claude", generated_launcher(tmp_path))
    state = hooks.prismor_home()
    before = sorted(str(p.relative_to(state)) for p in state.rglob("*"))
    check = hooks.hook_health(tmp_path, self_test=True)[0]
    assert check["state"] == "ok", check
    assert "allow/block verified" in check["detail"]
    assert "client invocation and active policy not verified" in check["detail"]
    assert not (tmp_path / ".prismor").exists()
    assert sorted(str(p.relative_to(state)) for p in state.rglob("*")) == before


def test_self_test_does_not_execute_custom_shim(tmp_path):
    configure(tmp_path, "claude", launcher(tmp_path))
    check = hooks.hook_health(tmp_path, self_test=True)[0]
    assert check["state"] == "warn" and "self-test skipped" in check["detail"]


def test_self_test_reports_import_failure(tmp_path, monkeypatch):
    configure(tmp_path, "claude", generated_launcher(tmp_path))
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a[0], 1, "", "private error"))
    check = hooks.hook_health(tmp_path, self_test=True)[0]
    assert check["state"] == "fail" and "cannot import" in check["detail"]
    assert "private error" not in json.dumps(check)


def test_self_test_reports_timeout(tmp_path, monkeypatch):
    configure(tmp_path, "claude", generated_launcher(tmp_path))
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], kwargs["timeout"])
    monkeypatch.setattr(subprocess, "run", timeout)
    assert "timed out" in hooks.hook_health(tmp_path, self_test=True)[0]["detail"]


def test_self_test_rejects_python_exit_two_without_denial(tmp_path, monkeypatch):
    configure(tmp_path, "claude", generated_launcher(tmp_path))
    replies = iter([0, 0, 2])
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a[0], next(replies), "", "cannot open script"))
    check = hooks.hook_health(tmp_path, self_test=True)[0]
    assert check["state"] == "fail" and "expected allow/block" in check["detail"]


def test_doctor_self_test_flag():
    assert cli.build_parser().parse_args(["doctor", "--self-test", "--json"]).self_test


@pytest.mark.parametrize("agent", hooks._SUPPORTED_AGENTS)
def test_health_recognizes_installer_output(tmp_path, agent):
    hooks.install_hooks(repo_root=Path(__file__).resolve().parents[1], workspace=tmp_path,
                        agent=agent, scope="project", mode="enforce")
    checks = [c for c in hooks.hook_health(tmp_path) if c["scope"] == "project" and c["agent"] == agent]
    assert len(checks) == 1 and checks[0]["configured"], checks
    assert checks[0]["state"] == ("warn" if agent in (*hooks._PLUGIN_REGISTERED_AGENTS, "opencode") else "ok")


def test_invalid_agent_argument_is_reported(tmp_path):
    configure(tmp_path, "claude", generated_launcher(tmp_path).replace("--agent claude", "--agent qwen"))
    check = hooks.hook_health(tmp_path, self_test=True)[0]
    assert check["state"] == "fail" and "arguments" in check["detail"]


def test_shell_suffix_is_not_self_tested(tmp_path):
    configure(tmp_path, "claude", generated_launcher(tmp_path) + "; exit 1")
    check = hooks.hook_health(tmp_path, self_test=True)[0]
    assert check["state"] == "warn" and "custom dispatcher arguments" in check["detail"]


def test_all_workspaces_reports_broken_hook(tmp_path, monkeypatch, capsys):
    configure(tmp_path, "claude", launcher(tmp_path, str(tmp_path / "missing-python")))
    monkeypatch.setattr(cli, "list_registered_workspaces", lambda: [tmp_path])
    cli._print_dashboard()
    out = capsys.readouterr().out
    assert "enforce (configured)" in out
    assert "interpreter is missing" in out


def test_dashboard_dates_cross_month_without_padding(monkeypatch, capsys):
    class FixedDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            return cls(2026, 10, 2, tzinfo=timezone.utc)

    monkeypatch.setattr(cli, "datetime", FixedDatetime)
    monkeypatch.setattr(cli, "list_registered_workspaces", lambda: [])
    cli._print_dashboard(days=3)
    assert "Wed 30  Thu 1  Fri 2" in capsys.readouterr().out


def test_probe_cache_and_environment_exclude_credentials(tmp_path, monkeypatch):
    command = generated_launcher(tmp_path)
    configure(tmp_path, "claude", command)
    configure(tmp_path, "qwen", command, "global")
    monkeypatch.setenv("OPENAI_API_KEY", "test-placeholder")
    monkeypatch.setenv("PRISMOR_SECRETS_DIR", str(tmp_path / "untouched-vault"))
    calls = []
    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        denied = kwargs.get("input") and json.loads(kwargs["input"])["tool_input"]["command"] == "rm -rf /"
        return subprocess.CompletedProcess(argv, 2 if denied else 0, "",
            "Prismor blocked this action: (rule: destructive-command)" if denied else "")
    monkeypatch.setattr(subprocess, "run", run)
    checks = hooks.hook_health(tmp_path, self_test=True)
    assert len(checks) == 2 and all(c["state"] == "ok" for c in checks)
    assert len(calls) == 3  # import, allow, deny once for the shared launcher
    for argv, kwargs in calls:
        assert "-I" in argv
        assert "OPENAI_API_KEY" not in kwargs["env"]
        assert "PRISMOR_SECRETS_DIR" not in kwargs["env"]
        assert kwargs["cwd"] != str(tmp_path)
        assert kwargs["env"]["HOME"] == kwargs["cwd"]


@pytest.mark.parametrize("agent", ["claude", "cursor", "gemini", "antigravity"])
@pytest.mark.parametrize("broken", ["missing", "misspelled"])
def test_pre_action_wiring_gaps_fail_without_running_probes(tmp_path, monkeypatch, agent, broken):
    hooks.install_hooks(repo_root=Path(__file__).resolve().parents[1], workspace=tmp_path,
                        agent=agent, scope="project", mode="enforce")
    path = hooks._config_path(agent, "project", tmp_path)
    config = json.loads(path.read_text())
    group = config["prismor"] if agent == "antigravity" else config["hooks"]
    pre = [name for name in group if hooks._is_pre_action(name)
           and "prompt" not in name.lower() and name != "PermissionRequest"]
    removed = group.pop(pre[0])
    for name in pre[1:]:
        group.pop(name)
    if broken == "misspelled":
        group["TypoPreToolUse"] = removed
    elif not group:
        # Keep the dispatcher discoverable on an audit-only event.
        group["PostToolUse"] = removed
    path.write_text(json.dumps(config))
    monkeypatch.setattr(hooks, "_dispatcher_self_test", lambda *a: pytest.fail("broken wiring was probed"))
    check = hooks.hook_health(tmp_path, self_test=True)[0]
    assert check["configured"] and check["state"] == "fail"
    assert "hook" in check["detail"]


def test_missing_pretool_fails_doctor_and_is_visible_in_status(tmp_path, capsys):
    path = configure(tmp_path, "claude", generated_launcher(tmp_path))
    config = json.loads(path.read_text())
    config["hooks"]["PostToolUse"] = config["hooks"].pop("PreToolUse")
    path.write_text(json.dumps(config))
    with pytest.raises(SystemExit) as exc:
        cli._run_doctor(tmp_path, as_json=True, self_test=True)
    assert exc.value.code == 1
    assert json.loads(capsys.readouterr().out)["ok"] is False
    cli._print_status_overview(tmp_path)
    assert "no pre-action tool hook" in capsys.readouterr().out


@pytest.mark.parametrize("target", [None, "different workspace"])
def test_project_workspace_missing_or_mismatched_fails(tmp_path, monkeypatch, target):
    command = generated_launcher(tmp_path)
    expected = f'--workspace "{tmp_path}" '
    replacement = "" if target is None else f'--workspace "{tmp_path / target}" '
    configure(tmp_path, "claude", command.replace(expected, replacement))
    monkeypatch.setattr(hooks, "_dispatcher_self_test", lambda *a: pytest.fail("wrong workspace was probed"))
    check = hooks.hook_health(tmp_path, self_test=True)[0]
    assert check["state"] == "fail" and "workspace" in check["detail"]


def test_relative_project_workspace_is_resolved_from_inspected_workspace(tmp_path, monkeypatch):
    command = generated_launcher(tmp_path).replace(f'--workspace "{tmp_path}"', '--workspace "."')
    configure(tmp_path, "claude", command)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    assert hooks.hook_health(tmp_path)[0]["state"] == "ok"


def test_symlink_equivalent_project_workspace_is_accepted(tmp_path):
    alias = tmp_path / "workspace alias"
    try:
        alias.symlink_to(tmp_path, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation is unavailable")
    configure(tmp_path, "claude", generated_launcher(tmp_path).replace(
        f'--workspace "{tmp_path}"', f'--workspace "{alias}"'))
    assert hooks.hook_health(tmp_path)[0]["state"] == "ok"


@pytest.mark.parametrize("pinned", [False, True])
def test_global_launcher_does_not_require_current_workspace_match(tmp_path, pinned):
    command = generated_launcher(tmp_path)
    command = command.replace(f'--workspace "{tmp_path}" ',
                              f'--workspace "{tmp_path / "elsewhere"}" ' if pinned else "")
    configure(tmp_path, "claude", command, scope="global")
    assert hooks.hook_health(tmp_path)[0]["state"] == "ok"


def test_portable_launcher_is_not_required_to_pin_project_workspace(tmp_path):
    configure(tmp_path, "claude", hooks._PORTABLE_TEMPLATE.format(agent="claude", mode="enforce"))
    check = hooks.hook_health(tmp_path, self_test=True)[0]
    assert check["state"] == "warn" and "portable" in check["detail"]
