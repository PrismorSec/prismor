"""#930: a bare origin registered with cloak is never substring-masked.
#931: attack strings in a Python harness that only runs argv lists are data."""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from prismor.runtime.cloaking.runtime import is_scrubbable_secret
from prismor.runtime.policy_engine import PolicyEngine

ROOT = Path(__file__).resolve().parents[1] / "prismor" / "runtime" / "cloaking"


def _hermes(path):
    spec = importlib.util.spec_from_file_location(f"h{abs(hash(path))}", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod._is_scrubbable_secret


CHECKS = [is_scrubbable_secret, _hermes(ROOT / "hermes_plugin_entry.py"),
          _hermes(ROOT / "hermes-plugin" / "__init__.py")]


@pytest.mark.parametrize("check", CHECKS)
@pytest.mark.parametrize("value", [
    "http://localhost:3000", "https://app.example.com/", "http://127.0.0.1:7391",
])
def test_bare_origin_not_masked(check, value):
    assert not check(value)


@pytest.mark.parametrize("check", CHECKS)
@pytest.mark.parametrize("value", [
    "https://hooks.slack.com/services/T000/B000/XXXXXXXXXXXX",  # token in path
    "https://user:pw0rd@db.example.com",                        # userinfo
    "https://api.example.com/?key=abcd1234efgh",                # query
    "sk-abcdefghijklmnop1234",
])
def test_credentials_still_masked(check, value):
    assert check(value)


ENGINE = PolicyEngine()
RM = "rm -rf"


def _live(cmd, rule):
    return [f for f in ENGINE.evaluate({"type": "shell", "command": cmd}, 0)
            if f["ruleId"] == rule and not f.get("contextInert")]


def _harness(call):
    return (
        "cat > /tmp/h/x.py <<'EOF'\n"
        "import json, subprocess\n"
        f'cmds = ["ls -la", "{RM} ~/"]\n'
        "for c in cmds:\n"
        f"    {call}\n"
        "EOF\npython3 /tmp/h/x.py"
    )


ARGV_DATA = 'r = subprocess.run(["prismor", "check", c], input=json.dumps({"c": c}), capture_output=True, text=True, stdout=subprocess.PIPE)'


def test_argv_list_harness_is_data():
    assert not _live(_harness(ARGV_DATA), "destructive-command")


def test_sys_executable_prismor_hook_is_data():
    call = ('subprocess.run([sys.executable, "-m", "prismor.runtime.cli", "hook-dispatch", '
            '"--agent", "claude"], input=json.dumps({"command": c}), capture_output=True)')
    cmd = _harness(call).replace("import json, subprocess", "import json, subprocess, sys")
    assert not _live(cmd, "destructive-command")


@pytest.mark.parametrize("argv", [
    '[sys.executable, "-m", "prismor.runtime.cli", "sandbox", c]',
    '[sys.executable, "-m", "other.mod", "check", c]',
    '[sys.executable, "run.py", c]',
    '[sys.executable, "-c", c]',
])
def test_sys_executable_other_stays_live(argv):
    cmd = _harness(f"subprocess.run({argv})").replace("import json, subprocess", "import json, subprocess, sys")
    assert _live(cmd, "destructive-command")


@pytest.mark.parametrize("call", [
    "subprocess.run(c, shell=True)",
    'subprocess.run(["bash", "-c", c])',
    'subprocess.run(["/bin/sh", "-c", c])',
    'subprocess.run(["ssh", "host", c])',
    'subprocess.run(["python3", "-c", c])',
    'subprocess.run(["env", "sh", "-c", c])',
    'subprocess.run(["git", "-c", "core.pager=" + c, "log"])',
    'subprocess.run(["rsync", "-e", c, "a", "b"])',
    'subprocess.run([c])',
    "subprocess.run(argv)",
    'subprocess.run(["prismor", c], executable="/bin/sh")',
    'subprocess.run(["prismor", c], **kw)',
    "f = subprocess.run; f(c, shell=True)",
    "import os; os.system(c)",
    'subprocess.run(["prismor", c]); eval(c)',
])
def test_runner_harness_stays_live(call):
    assert _live(_harness(call), "destructive-command")


def test_aliased_or_from_import_stays_live():
    for head in ("import subprocess as sp\n", "from subprocess import run\n"):
        cmd = _harness(ARGV_DATA).replace("import json, subprocess\n", "import json, subprocess\n" + head)
        assert _live(cmd, "destructive-command")
