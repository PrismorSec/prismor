"""The OpenClaw / Hermes / OpenCode shims run under Node against stub commands (#488).

Each check must be async (the gateway's event loop keeps ticking while the hook
runs) and must separate "blocked" from "could not evaluate": a timeout or a
missing binary is logged and then resolved by failure_mode, never silently
allowed.
"""
import json
import shutil
import subprocess
import sys

import pytest

from prismor.runtime import hooks

NODE = shutil.which("node")
pytestmark = pytest.mark.skipif(NODE is None, reason="node not installed")

# (template, handler call) per shim.
SHIMS = {
    "openclaw-plugin": (hooks._OPENCLAW_PLUGIN_JS, 'm.before_tool_call({toolName: "Bash", toolInput: {command: "ls"}})'),
    "hermes-plugin": (hooks._HERMES_PLUGIN_JS, 'm.before_tool_call({toolName: "Bash", toolInput: {command: "ls"}})'),
    "opencode-plugin": (hooks._OPENCODE_PLUGIN_JS, 'm({})["tool.execute.before"]({tool: "bash", args: {command: "ls"}})'),
    "openclaw-hook": (hooks._OPENCLAW_HOOK_JS, 'm({context: {content: "hi"}})'),
    "hermes-hook": (hooks._HERMES_HOOK_JS, 'm({context: {content: "hi"}})'),
}
PRE_TOOL = {"openclaw-plugin", "hermes-plugin", "opencode-plugin"}

STUBS = {
    "allow": f'"{sys.executable}" -c "import sys; sys.stdin.read()"',
    "block": f'"{sys.executable}" -c "import sys; sys.stdin.read(); sys.stderr.write(\'Prismor blocked this action: nope\'); sys.exit(2)"',
    "slow": f'"{sys.executable}" -c "import time; time.sleep(5)"',
    "missing": "/nonexistent/prismor-hook hook-dispatch",
    # Python's own exit 2 (dispatch script gone) is not a verdict.
    "no-script": f'"{sys.executable}" /nonexistent/hook-dispatch.py',
}

RUNNER = """
const m = require(process.argv[1]);
let ticks = 0;
const t = setInterval(() => ticks++, 10);
Promise.resolve().then(() => %s).then(
  (r) => { clearInterval(t); console.log(JSON.stringify({ r: r === undefined ? null : r, ticks })); },
  (e) => { clearInterval(t); console.log(JSON.stringify({ r: { block: true, reason: e.message }, ticks })); }
);
"""


def _run(tmp_path, shim, stub, mode):
    template, call = SHIMS[shim]
    js = tmp_path / f"{shim}.js"
    js.write_text(hooks._render_gateway_js(template, STUBS[stub], mode), encoding="utf-8")
    proc = subprocess.run(
        [NODE, "-e", RUNNER % call, str(js)],
        capture_output=True, text=True, timeout=30,
        env={"PATH": "/usr/bin:/bin", "PRISMOR_GATEWAY_TIMEOUT_MS": "500"},
    )
    assert proc.returncode == 0, proc.stderr
    out = json.loads(proc.stdout.strip().splitlines()[-1])
    return out["r"] or {}, out["ticks"], proc.stderr


@pytest.mark.parametrize("shim", sorted(SHIMS))
def test_allow_exits_zero_quietly(tmp_path, shim):
    r, _, err = _run(tmp_path, shim, "allow", "enforce")
    assert not r.get("block")
    assert "could not evaluate" not in err


@pytest.mark.parametrize("shim", sorted(PRE_TOOL))
def test_exit_two_blocks_with_reason(tmp_path, shim):
    r, _, _ = _run(tmp_path, shim, "block", "observe")
    assert r["block"] and r["reason"] == "Prismor blocked this action: nope"


@pytest.mark.parametrize("stub", ["slow", "missing", "no-script"])
@pytest.mark.parametrize("shim", sorted(SHIMS))
def test_could_not_evaluate_is_logged_and_follows_failure_mode(tmp_path, shim, stub):
    r, ticks, err = _run(tmp_path, shim, stub, "enforce")
    assert "[prismor] could not evaluate" in err
    assert {"slow": "timed out", "missing": "exit 127", "no-script": "exit 2"}[stub] in err
    # Only a pre-tool event can be denied; message hooks cannot block.
    assert bool(r.get("block")) == (shim in PRE_TOOL)
    if stub == "slow":
        assert ticks >= 20, "event loop was blocked during the check"

    r, _, err = _run(tmp_path, shim, stub, "observe")
    assert not r.get("block")
    assert "failure_mode=allow, allowing" in err


def test_command_with_quotes_is_valid_js(tmp_path):
    # The dispatcher command quotes its own paths; pasting it raw into a "..."
    # literal made every generated plugin a SyntaxError.
    js = tmp_path / "p.js"
    js.write_text(hooks._render_gateway_js(hooks._OPENCLAW_PLUGIN_JS, '"/a b/py" "/s.py" hook-dispatch', "observe"))
    subprocess.run([NODE, "--check", str(js)], check=True)


def test_opencode_before_is_a_pre_action():
    # Without this, should_block() ignored every OpenCode call: nothing blocked.
    assert hooks._is_pre_action("tool.execute.before")
    assert not hooks._is_pre_action("tool.execute.after")


@pytest.mark.parametrize("agent", ["openclaw", "hermes", "opencode"])
def test_epoch_ms_timestamp_becomes_iso(tmp_path, agent):
    payload = {"hookEvent": "before_tool_call", "toolName": "Bash", "toolInput": {"command": "ls"},
               "sessionId": "s", "timestamp": 1790575660000}
    ts = hooks.normalize_payload(agent=agent, payload=payload, workspace=tmp_path)["event"]["ts"]
    assert ts.startswith("2026-09-")
