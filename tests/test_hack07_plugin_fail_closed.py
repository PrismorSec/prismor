"""Plugin pre-hooks deny unless the hook exits 0."""

import json
from unittest import mock

from prismor.runtime import hooks


def test_templates_deny_unless_exit_zero():
    assert "r.status !== 0" in hooks._OPENCODE_PLUGIN_JS
    assert "r.status !== 0" in hooks._OPENCLAW_PLUGIN_JS
    assert "returncode != 0" in hooks._HERMES_PLUGIN_PY
    assert "call allowed" not in hooks._OPENCODE_PLUGIN_JS
    assert "call allowed" not in hooks._OPENCLAW_PLUGIN_JS
    assert "call allowed" not in hooks._HERMES_PLUGIN_PY


def test_hermes_pre_hook_blocks_on_crash_and_nonzero():
    src = hooks._HERMES_PLUGIN_PY.replace("__PRISMOR_COMMAND_JSON__", json.dumps("prismor"))
    ns = {}
    exec(src, ns)
    with mock.patch.object(ns["subprocess"], "run", side_effect=OSError("missing")):
        blocked = ns["_pre_tool_call"](tool_name="Bash", args={"command": "rm -rf /"})
    assert blocked["action"] == "block"
    proc = mock.Mock(returncode=1, stderr="no")
    with mock.patch.object(ns["subprocess"], "run", return_value=proc):
        blocked = ns["_pre_tool_call"](tool_name="Bash", args={})
    assert blocked["action"] == "block"
    proc.returncode = 0
    with mock.patch.object(ns["subprocess"], "run", return_value=proc):
        assert ns["_pre_tool_call"](tool_name="Bash", args={}) is None
