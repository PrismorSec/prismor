"""An enforcing hook must not let a call through because Prismor itself failed to load.

Exit-code hosts read every nonzero exit except 2 as "hook errored" and run the
tool, so an ImportError in the launcher (a broken or half-upgraded install)
used to open every call. These tests run the real generated launcher in a
subprocess against deliberately broken installs.
"""
import ast
import io
import json
import os
import shutil
import subprocess
import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prismor.runtime import hook_failclosed as hfc
from prismor.runtime import hooks, immunity_cli

REPO = Path(__file__).resolve().parent.parent
PRE = {"hook_event_name": "PreToolUse", "tool_name": "Bash"}


# ── the shared handler: exit code and stdout, per host ───────────────────────

def _crash(monkeypatch, capsys, payload, agent="claude", mode="enforce", raw=None):
    monkeypatch.setattr(sys, "stdin", io.StringIO(raw if raw is not None else json.dumps(payload)))
    with pytest.raises(SystemExit) as exc:
        hfc.handle_crash(["--agent", agent, "--mode", mode], RuntimeError("boom"))
    out = capsys.readouterr()
    return exc.value.code, out.out, out.err


@pytest.mark.parametrize("agent,code", [
    ("claude", 2), ("codex", 2), ("cursor", 2), ("gemini", 2), ("windsurf", 2), ("grok", 2),
    ("copilot", 0), ("qwen", 0), ("antigravity", 0),
])
def test_enforce_pretool_denies_with_each_hosts_protocol(monkeypatch, capsys, agent, code):
    got, out, err = _crash(monkeypatch, capsys, PRE, agent=agent)
    assert got == code
    assert "blocked because this hook enforces" in err
    if agent in ("copilot", "qwen", "antigravity", "grok"):
        assert json.loads(out)  # a JSON deny the host can read
    if agent == "cursor":
        assert "Prismor hook failed" in out


def test_codex_on_windows_uses_the_json_deny(monkeypatch, capsys):
    monkeypatch.setattr(hfc, "os", types.SimpleNamespace(name="nt"))
    code, out, _ = _crash(monkeypatch, capsys, PRE, agent="codex")
    assert code == 0
    assert json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny"


@pytest.mark.parametrize("payload,mode", [
    (PRE, "observe"),
    ({"hook_event_name": "Stop"}, "enforce"),             # exit 2 would loop "keep going"
    ({"hook_event_name": "UserPromptSubmit"}, "enforce"),
    ({"hook_event_name": "SessionStart"}, "enforce"),
    ({"hook_event_name": "PostToolUse", "tool_name": "Bash"}, "enforce"),
    ({"hook_event_name": "PreToolUse", "tool_name": "Read"}, "enforce"),
    ({"hook_event_name": "PreToolUse", "tool_name": "Grep"}, "enforce"),
])
def test_where_a_deny_would_do_harm_the_call_goes_through(monkeypatch, capsys, payload, mode):
    code, _, err = _crash(monkeypatch, capsys, payload, mode=mode)
    assert code == 1 and "not screened" in err


@pytest.mark.parametrize("raw", ["", "not json", "[1, 2]", "null"])
def test_unreadable_payload_on_enforce_denies(monkeypatch, capsys, raw):
    code, _, _ = _crash(monkeypatch, capsys, None, raw=raw)
    assert code == 2


def test_stdin_that_cannot_be_read_on_enforce_denies(monkeypatch, capsys):
    class Broken:
        def read(self):
            raise OSError("closed")

    monkeypatch.setattr(sys, "stdin", Broken())
    with pytest.raises(SystemExit) as exc:
        hfc.handle_crash(["--agent", "claude", "--mode", "enforce"], RuntimeError("boom"))
    assert exc.value.code == 2


def test_missing_mode_means_observe(monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(PRE)))
    with pytest.raises(SystemExit) as exc:
        hfc.handle_crash(["--agent", "claude"], RuntimeError("boom"))
    assert exc.value.code == 1


# ── crash points inside immunity_cli that used to sit outside the guard ──────

def _dispatch(monkeypatch, argv, payload=PRE):
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(payload)))
    with pytest.raises(SystemExit) as exc:
        immunity_cli.main(argv)
    return exc.value.code


HOOK = ["hook-dispatch", "--agent", "claude", "--mode", "enforce"]


def test_cli_module_that_cannot_import_denies_on_enforce(monkeypatch):
    monkeypatch.setitem(sys.modules, "prismor.runtime.cli", None)  # makes the import raise
    assert _dispatch(monkeypatch, HOOK) == 2


def test_cli_module_that_cannot_import_passes_on_observe(monkeypatch):
    monkeypatch.setitem(sys.modules, "prismor.runtime.cli", None)
    assert _dispatch(monkeypatch, ["hook-dispatch", "--agent", "claude", "--mode", "observe"]) == 1


def test_stdin_failure_inside_the_dispatcher_denies(monkeypatch):
    class Broken:
        def read(self):
            raise OSError("closed")

    monkeypatch.setattr(sys, "stdin", Broken())
    with pytest.raises(SystemExit) as exc:
        immunity_cli._hook_dispatch_fail_closed(["--agent", "claude", "--mode", "enforce"])
    assert exc.value.code == 2


def test_startup_work_that_fails_denies_on_enforce(monkeypatch):
    import prismor.runtime.happy_eyeballs as he

    def boom():
        raise RuntimeError("startup")

    monkeypatch.setattr(he, "install", boom)
    assert _dispatch(monkeypatch, HOOK) == 2


def test_startup_failure_is_not_swallowed_for_other_commands(monkeypatch):
    import prismor.runtime.happy_eyeballs as he

    def boom():
        raise RuntimeError("startup")

    monkeypatch.setattr(he, "install", boom)
    with pytest.raises(RuntimeError):
        immunity_cli.main(["--version"])


def test_a_real_block_still_wins_over_the_crash_path(monkeypatch):
    import prismor.runtime.cli as cli

    def block(argv):
        raise SystemExit(2)

    monkeypatch.setattr(cli, "main", block)
    assert _dispatch(monkeypatch, HOOK) == 2


# ── the generated launcher, run for real against broken installs ─────────────

def _install(tmp_path, runtime_init="", immunity_cli_src='raise ImportError("boom")', failclosed=True):
    root = tmp_path / "root"
    rt = root / "prismor" / "runtime"
    rt.mkdir(parents=True)
    (root / "prismor" / "__init__.py").write_text("")
    (rt / "__init__.py").write_text(runtime_init)
    (rt / "immunity_cli.py").write_text(immunity_cli_src)
    if failclosed:
        shutil.copy(REPO / "prismor" / "runtime" / "hook_failclosed.py", rt / "hook_failclosed.py")
    shim = tmp_path / "hook-dispatch.py"
    shim.write_text(hooks._SHIM_TEMPLATE.format(repo_root=str(root)), encoding="utf-8")
    return shim


def _run(shim, agent="claude", mode="enforce", payload=PRE, env_extra=None):
    env = {k: os.environ[k] for k in ("PATH", "SYSTEMROOT", "TEMP", "TMP") if k in os.environ}
    env.update(env_extra or {})
    # -S: no site-packages, so the real prismor cannot stand in for the fake one.
    return subprocess.run([sys.executable, "-S", str(shim), "hook-dispatch", "--agent", agent, "--mode", mode],
                          input=json.dumps(payload), capture_output=True, text=True, env=env, timeout=30)


def test_broken_import_denies_on_enforce(tmp_path):
    r = _run(_install(tmp_path))
    assert r.returncode == 2
    assert "ImportError: boom" in r.stderr and "blocked" in r.stderr


def test_broken_import_denies_even_when_the_runtime_package_will_not_import(tmp_path):
    # The handler is loaded by file path, so a corrupt prismor/runtime/__init__.py cannot hide it.
    r = _run(_install(tmp_path, runtime_init="def (:\n"))
    assert r.returncode == 2 and "blocked" in r.stderr


def test_syntax_error_in_the_cli_denies(tmp_path):
    assert _run(_install(tmp_path, immunity_cli_src="def (:\n")).returncode == 2


def test_broken_import_uses_the_hosts_own_protocol(tmp_path):
    r = _run(_install(tmp_path), agent="copilot")
    assert r.returncode == 0 and json.loads(r.stdout)["permissionDecision"] == "deny"


@pytest.mark.parametrize("payload,mode", [
    (PRE, "observe"),
    ({"hook_event_name": "Stop"}, "enforce"),
    ({"hook_event_name": "PreToolUse", "tool_name": "Read"}, "enforce"),
])
def test_broken_import_does_not_deny_where_it_must_not(tmp_path, payload, mode):
    r = _run(_install(tmp_path), payload=payload, mode=mode)
    assert r.returncode == 1 and "not screened" in r.stderr


def test_broken_hookd_denies_too(tmp_path):
    # Opt-in warm server: a failure there must not open the call either.
    shim = _install(tmp_path, immunity_cli_src="def main():\n    return 0\n")
    r = _run(shim, env_extra={"PRISMOR_HOOKD": "1"})  # prismor.runtime.hookd does not exist here
    assert r.returncode == 2


def test_healthy_install_is_untouched(tmp_path):
    shim = _install(tmp_path, immunity_cli_src="def main():\n    import sys\n    sys.stdout.write('ran')\n    return 7\n")
    r = _run(shim)
    assert r.returncode == 7 and r.stdout == "ran" and r.stderr == ""


def test_prismor_not_installed_lets_the_call_through_loudly(tmp_path):
    shim = tmp_path / "hook-dispatch.py"
    shim.write_text(hooks._SHIM_TEMPLATE.format(repo_root=str(tmp_path / "gone")), encoding="utf-8")
    r = _run(shim)
    assert r.returncode == 1 and "could not be loaded" in r.stderr and "not screened" in r.stderr


def test_prismor_not_installed_blocks_when_required(tmp_path):
    shim = tmp_path / "hook-dispatch.py"
    shim.write_text(hooks._SHIM_TEMPLATE.format(repo_root=str(tmp_path / "gone")), encoding="utf-8")
    assert _run(shim, env_extra={"PRISMOR_HOOK_REQUIRED": "1"}).returncode == 2


def test_handler_file_missing_falls_back_to_the_loud_pass_through(tmp_path):
    r = _run(_install(tmp_path, failclosed=False))
    assert r.returncode == 1 and "could not be loaded" in r.stderr


# ── the launcher template must stay readable by the doctor's self-test ───────

@pytest.mark.parametrize("root", ["/home/u/prismor", "C:\\Users\\a b\\prismor", "/tmp/it's"])
def test_template_keeps_one_constant_path_insert(root):
    source = hooks._SHIM_TEMPLATE.format(repo_root=root)
    inserts = [n for n in ast.walk(ast.parse(source))
               if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
               and ast.dump(n.func) == ast.dump(ast.parse("sys.path.insert", mode="eval").body)]
    assert len(inserts) == 1 and inserts[0].args[1].value == root


def test_template_imports_prismor_only_inside_the_guard():
    # A prismor import outside the try block is exactly the old fail-open hole,
    # and the crash path's own imports stay inside the handler so a healthy
    # call pays nothing for them.
    top = [n for n in ast.parse(hooks._SHIM_TEMPLATE.format(repo_root="/x")).body
           if isinstance(n, (ast.Import, ast.ImportFrom))]
    assert [a.name for n in top for a in n.names] == ["os", "sys", "time"]


def test_handler_is_found_when_prismor_spans_several_locations(tmp_path):
    # Namespace package: the launcher's own root has no runtime/ (an adapter
    # dist, say), the real one is further down sys.path.
    root = tmp_path / "root"
    (root / "prismor").mkdir(parents=True)
    other = tmp_path / "other"
    rt = other / "prismor" / "runtime"
    rt.mkdir(parents=True)
    (rt / "__init__.py").write_text("")
    (rt / "immunity_cli.py").write_text('raise ImportError("boom")')
    shutil.copy(REPO / "prismor" / "runtime" / "hook_failclosed.py", rt / "hook_failclosed.py")
    shim = tmp_path / "hook-dispatch.py"
    shim.write_text(hooks._SHIM_TEMPLATE.format(repo_root=str(root)), encoding="utf-8")
    r = _run(shim, env_extra={"PYTHONPATH": str(other)})
    assert r.returncode == 2 and "blocked" in r.stderr


# ── an upgrade replaces the old fail-open launcher on the next healthy call ──

# The launcher every machine has before this change (generated by 1.80.1).
OLD_LAUNCHER = (
    "# Generated by `prismor setup` -- do not edit. Rewritten on every install.\n"
    "import os, sys, time\n"
    "\n"
    "os.environ['PRISMOR_HOOK_T0'] = str(time.time())\n"
    "sys.path.insert(0, {root!r})\n"
    "\n"
    "if os.environ.get('PRISMOR_HOOKD') == '1':  # opt-in warm server, see prismor/runtime/hookd.py\n"
    "    from prismor.runtime.hookd import run_client\n"
    "    _code = run_client()\n"
    "    if _code is not None:\n"
    "        sys.exit(_code)\n"
    "\n"
    "from prismor.runtime.immunity_cli import main\n"
    "\n"
    "sys.exit(main())\n"
)


def _old_launcher(tmp_path, root="/opt/prismor's root"):
    shim = tmp_path / "hook-dispatch.py"
    shim.write_text(OLD_LAUNCHER.format(root=root), encoding="utf-8")
    shim.chmod(0o640)
    return shim


def test_old_launcher_is_rewritten_with_the_same_root_and_mode(tmp_path):
    shim = _old_launcher(tmp_path)
    hooks.refresh_dispatch_shim(str(shim))
    assert shim.read_text(encoding="utf-8") == hooks._SHIM_TEMPLATE.format(repo_root="/opt/prismor's root")
    assert (shim.stat().st_mode & 0o777) == 0o640
    assert [p.name for p in tmp_path.iterdir()] == ["hook-dispatch.py"]  # no temp file left


def test_current_launcher_is_not_touched(tmp_path):
    shim = tmp_path / "hook-dispatch.py"
    shim.write_text(hooks._SHIM_TEMPLATE.format(repo_root="/x"), encoding="utf-8")
    before = shim.stat().st_mtime_ns
    os.utime(shim, ns=(before - 10**9, before - 10**9))
    hooks.refresh_dispatch_shim(str(shim))
    assert shim.stat().st_mtime_ns == before - 10**9


@pytest.mark.parametrize("name,text", [
    ("hook-dispatch.py", "# my own launcher\nimport sys\nsys.path.insert(0, '/x')\n"),
    ("hook-dispatch.py", "# Generated by `prismor setup` -- do not edit. Rewritten on every install.\nsys.path.insert(0, __file__)\n"),
    ("dev-hook.py", OLD_LAUNCHER.format(root="/x")),
])
def test_launchers_that_are_not_ours_are_left_alone(tmp_path, name, text):
    shim = tmp_path / name
    shim.write_text(text, encoding="utf-8")
    hooks.refresh_dispatch_shim(str(shim))
    assert shim.read_text(encoding="utf-8") == text


@pytest.mark.skipif(os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0),
                    reason="needs POSIX permissions and a non-root user")
def test_launcher_this_user_cannot_write_is_left_alone(tmp_path):
    shim = _old_launcher(tmp_path)
    tmp_path.chmod(0o500)  # like a system install's directory
    try:
        hooks.refresh_dispatch_shim(str(shim))  # must not raise
        assert shim.read_text(encoding="utf-8") == OLD_LAUNCHER.format(root="/opt/prismor's root")
    finally:
        tmp_path.chmod(0o700)


def test_missing_launcher_path_does_not_raise(tmp_path):
    hooks.refresh_dispatch_shim(str(tmp_path / "hook-dispatch.py"))


def test_a_healthy_hook_call_refreshes_the_launcher_it_ran_from(tmp_path, monkeypatch):
    import prismor.runtime.cli as cli
    shim = _old_launcher(tmp_path, root=str(REPO))
    monkeypatch.setattr(sys, "argv", [str(shim), "hook-dispatch", "--agent", "claude", "--mode", "enforce"])
    monkeypatch.setattr(cli, "main", lambda argv: None)
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(PRE)))
    immunity_cli._hook_dispatch_fail_closed(["--agent", "claude", "--mode", "enforce"])
    assert shim.read_text(encoding="utf-8") == hooks._SHIM_TEMPLATE.format(repo_root=str(REPO))


def test_refreshed_launcher_then_fails_closed(tmp_path):
    # End to end: old launcher on disk -> refreshed -> a later broken install denies.
    root = _install(tmp_path).parent / "root"
    shim = tmp_path / "hook-dispatch.py"
    shim.write_text(OLD_LAUNCHER.format(root=str(root)), encoding="utf-8")
    assert _run(shim).returncode == 1          # the old launcher: fails open
    hooks.refresh_dispatch_shim(str(shim))
    assert _run(shim).returncode == 2          # the new one: denies
