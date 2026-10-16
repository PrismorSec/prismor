"""Tests for the OpenCode hooks adapter (_strip_opencode, _merge_opencode, _normalize_opencode).

OpenCode auto-loads JS/TS plugin modules from .opencode/plugins/ (project) and
~/.config/opencode/plugins/ (global) -- https://opencode.ai/docs/plugins/ -- and
blocks a tool call when "tool.execute.before" throws. These tests verify:
  - "opencode" is in _SUPPORTED_AGENTS.
  - install writes a single ESM plugin module into the plugins directory.
  - _strip_opencode / install / uninstall clean up the legacy plugins.json
    registration (a file OpenCode never read).
  - _normalize_opencode maps tool calls (bash, read, write, fetch) correctly.
  - install/uninstall roundtrip lifecycle works as expected.
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prismor.runtime.hooks import (
    _SUPPORTED_AGENTS,
    _config_path,
    _strip_opencode,
    _normalize_opencode,
    _write_opencode_plugin,
    hook_installed,
    install_hooks,
    normalize_payload,
    uninstall_hooks,
)

_MARKER = "hook-dispatch"
_COMMAND = (
    'PYTHONPATH="/repo" python3 -m prismor.runtime.immunity_cli '
    f'{_MARKER} --agent opencode --workspace "/proj" --mode observe'
)


class TestSupportedAgentsOpenCode(unittest.TestCase):
    """OpenCode must appear in the _SUPPORTED_AGENTS registry."""

    def test_opencode_in_supported_agents(self):
        self.assertIn("opencode", _SUPPORTED_AGENTS)


# --- _strip_opencode ---------------------------------------------------------

class TestStripOpenCode(unittest.TestCase):
    """_strip_opencode removes Prismor plugin entries while keeping others."""

    def test_removes_prismor_plugin(self):
        config = {
            "plugins": [
                "/repo/prismor/runtime/opencode-plugin",
                "/other/plugin",
            ]
        }
        result, removed = _strip_opencode(config, _MARKER)
        self.assertTrue(removed)
        self.assertEqual(result["plugins"], ["/other/plugin"])

    def test_no_change_when_absent(self):
        config = {"plugins": ["/other/plugin"]}
        result, removed = _strip_opencode(config, _MARKER)
        self.assertFalse(removed)
        self.assertEqual(result["plugins"], ["/other/plugin"])


# --- plugin module -----------------------------------------------------------

class TestOpenCodePluginModule(unittest.TestCase):
    """The generated file must be something OpenCode actually loads."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.path = Path(self.tmpdir) / "plugins" / "prismor.js"

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_config_paths_are_the_auto_loaded_plugin_dirs(self):
        ws = Path("/proj")
        self.assertEqual(_config_path("opencode", "project", ws), ws / ".opencode" / "plugins" / "prismor.js")
        self.assertEqual(
            _config_path("opencode", "global", ws),
            Path.home() / ".config" / "opencode" / "plugins" / "prismor.js",
        )

    def test_writes_esm_module_with_one_named_plugin_export(self):
        _write_opencode_plugin(self.path, _COMMAND)
        js = self.path.read_text()
        # OpenCode calls every exported function as a plugin: exactly one, named.
        self.assertEqual(js.count("export const "), 1)
        self.assertIn("export const PrismorPlugin = async", js)
        self.assertNotIn("module.exports", js)
        self.assertIn('"tool.execute.before"', js)
        self.assertIn('"tool.execute.after"', js)
        # Tool arguments live on output.args, not input.
        self.assertIn("output.args", js)
        self.assertIn("throw new Error", js)

    def test_command_is_embedded_as_a_json_string_literal(self):
        _write_opencode_plugin(self.path, _COMMAND)
        js = self.path.read_text()
        self.assertIn(f"const PRISMOR_COMMAND = {json.dumps(_COMMAND)};", js)

    @unittest.skipUnless(__import__("shutil").which("node"), "node not installed")
    def test_module_is_valid_javascript(self):
        import subprocess
        _write_opencode_plugin(self.path, _COMMAND)
        mjs = self.path.with_suffix(".mjs")
        mjs.write_text(self.path.read_text())
        proc = subprocess.run(["node", "--check", str(mjs)], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)


# --- _normalize_opencode -----------------------------------------------------

class TestNormalizeOpenCode(unittest.TestCase):
    """_normalize_opencode maps OpenCode hook payloads to Prismor canonical events."""

    _SID = "opencode-testsession123"

    def _n(self, payload):
        return _normalize_opencode(payload, self._SID)

    def test_bash_tool_maps_to_shell(self):
        event = self._n({
            "hookEvent": "tool.execute.before",
            "toolName": "bash",
            "toolInput": {"command": "echo hello"},
        })
        self.assertEqual(event["type"], "shell")
        self.assertEqual(event["command"], "echo hello")
        self.assertEqual(event["agent"], "opencode")

    def test_read_tool_maps_to_file_read(self):
        event = self._n({
            "hookEvent": "tool.execute.before",
            "toolName": "read",
            "toolInput": {"path": "src/index.ts"},
        })
        self.assertEqual(event["type"], "file_read")
        self.assertEqual(event["path"], "src/index.ts")

    def test_write_tool_maps_to_file_write(self):
        event = self._n({
            "hookEvent": "tool.execute.before",
            "toolName": "write",
            "toolInput": {"path": "dist/out.js", "content": "console.log('hi')"},
        })
        self.assertEqual(event["type"], "file_write")
        self.assertEqual(event["path"], "dist/out.js")
        self.assertEqual(event["content"], "console.log('hi')")

    def test_fetch_tool_maps_to_network(self):
        # OpenCode's fetch tool id is "webfetch" (packages/opencode/src/tool/webfetch.ts).
        event = self._n({
            "hookEvent": "tool.execute.before",
            "toolName": "webfetch",
            "toolInput": {"url": "https://api.github.com"},
        })
        self.assertEqual(event["type"], "network")
        self.assertEqual(event["url"], "https://api.github.com")

    def test_opencode_native_camelcase_args(self):
        """OpenCode's built-in read/edit tools pass filePath / newString."""
        read = self._n({"toolName": "read", "toolInput": {"filePath": "/w/.env"}})
        self.assertEqual((read["type"], read["path"]), ("file_read", "/w/.env"))
        edit = self._n({"toolName": "edit", "toolInput": {"filePath": "a.py", "oldString": "x", "newString": "y"}})
        self.assertEqual((edit["type"], edit["path"], edit["content"]), ("file_write", "a.py", "y"))
        fetch = self._n({"toolName": "webfetch", "toolInput": {"url": "https://example.com"}})
        self.assertEqual((fetch["type"], fetch["url"]), ("network", "https://example.com"))

    def test_unknown_tool_maps_to_tool_result(self):
        event = self._n({
            "hookEvent": "tool.execute.before",
            "toolName": "custom_tool",
            "toolInput": {},
        })
        self.assertEqual(event["type"], "tool_result")

    def test_normalize_payload_routes_to_opencode(self):
        result = normalize_payload(
            agent="opencode",
            payload={
                "hookEvent": "tool.execute.before",
                "toolName": "bash",
                "toolInput": {"command": "ls -la"},
                "sessionId": "opencode-xyz",
            },
            workspace=Path("/fake/ws"),
        )
        self.assertEqual(result["event"]["agent"], "opencode")
        self.assertEqual(result["event"]["type"], "shell")


# --- install / uninstall roundtrip -------------------------------------------

class TestOpenCodeInstallUninstallRoundtrip(unittest.TestCase):
    """install_hooks + uninstall_hooks write and cleanly remove the OpenCode plugin."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.workspace = Path(self.tmpdir) / "project"
        self.workspace.mkdir()
        self.repo_root = Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        self.plugin = self.workspace / ".opencode" / "plugins" / "prismor.js"
        self.legacy = self.workspace / ".opencode" / "plugins.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _install(self):
        return install_hooks(
            repo_root=self.repo_root, workspace=self.workspace,
            agent="opencode", scope="project", mode="observe",
        )

    def _uninstall(self):
        return uninstall_hooks(
            repo_root=self.repo_root, workspace=self.workspace,
            agent="opencode", scope="project",
        )

    def test_install_and_uninstall_roundtrip(self):
        results = self._install()
        self.assertEqual(results[0]["configPath"], str(self.plugin))
        self.assertTrue(self.plugin.exists())
        self.assertIn("hook-dispatch --agent opencode", self.plugin.read_text())
        self.assertTrue(hook_installed("opencode", "project", self.workspace))

        results = self._uninstall()
        self.assertTrue(results[0]["removed"])
        self.assertFalse(self.plugin.exists())
        self.assertFalse(hook_installed("opencode", "project", self.workspace))

    def test_install_is_idempotent(self):
        self._install()
        first = self.plugin.read_text()
        self._install()
        self.assertEqual(self.plugin.read_text(), first)
        self.assertEqual(list(self.plugin.parent.iterdir()), [self.plugin])

    def test_install_migrates_legacy_plugins_json(self):
        self.legacy.parent.mkdir(parents=True)
        self.legacy.write_text(json.dumps({"plugins": ["/repo/prismor/runtime/opencode-plugin"]}))
        self._install()
        self.assertFalse(self.legacy.exists(), "a plugins.json holding only Prismor's entry is deleted")
        self.assertTrue(self.plugin.exists())

    def test_legacy_cleanup_keeps_foreign_entries(self):
        self.legacy.parent.mkdir(parents=True)
        self.legacy.write_text(json.dumps({"plugins": ["/repo/prismor/runtime/opencode-plugin", "/other/plugin"]}))
        results = self._uninstall()
        self.assertTrue(results[0]["removed"])
        self.assertEqual(json.loads(self.legacy.read_text()), {"plugins": ["/other/plugin"]})

    def test_uninstall_leaves_a_foreign_prismor_js_alone(self):
        self.plugin.parent.mkdir(parents=True)
        self.plugin.write_text("export const Mine = async () => ({})\n")
        results = self._uninstall()
        self.assertFalse(results[0]["removed"])
        self.assertTrue(self.plugin.exists())

    def test_global_scope_writes_under_config_opencode_plugins(self):
        results = install_hooks(
            repo_root=self.repo_root, workspace=self.workspace,
            agent="opencode", scope="global", mode="observe",
        )
        path = Path(results[0]["configPath"])
        self.assertEqual(path, Path.home() / ".config" / "opencode" / "plugins" / "prismor.js")
        self.assertTrue(path.exists())
        uninstall_hooks(repo_root=self.repo_root, workspace=self.workspace, agent="opencode", scope="global")
        self.assertFalse(path.exists())


if __name__ == "__main__":
    unittest.main()


# --- blocking: the plugin's `tool.execute.before` must be a pre-action event --

class TestOpenCodeBeforeEventBlocks(unittest.TestCase):
    """Live OpenCode 1.19 run: the plugin loaded but nothing was blocked, because
    `tool.execute.before` didn't count as pre-action and every call was treated
    as already executed (logged, never denied)."""

    def test_before_and_after_classification(self):
        from prismor.runtime.hooks import _is_pre_action
        from prismor.runtime.policy_engine import _is_pre_action_event
        self.assertTrue(_is_pre_action("tool.execute.before"))
        self.assertFalse(_is_pre_action("tool.execute.after"))
        self.assertTrue(_is_pre_action_event({"agent_event": "tool.execute.before"}))
        self.assertFalse(_is_pre_action_event({"agent_event": "tool.execute.after"}))

    def _dispatch(self, payload):
        import subprocess
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            ws.mkdir()
            env = {k: v for k, v in os.environ.items() if not k.startswith("PRISMOR_")}
            env.update(HOME=tmp, PRISMOR_HOME=str(Path(tmp) / ".prismor"),
                       PYTHONPATH=str(Path(__file__).resolve().parents[1]))
            return subprocess.run(
                [sys.executable, "-m", "prismor.runtime.cli", "hook-dispatch",
                 "--agent", "opencode", "--workspace", str(ws), "--mode", "enforce"],
                input=json.dumps(payload), capture_output=True, text=True, env=env, timeout=120,
            )

    def test_lockfile_deletion_is_blocked(self):
        proc = self._dispatch({"hookEvent": "tool.execute.before", "toolName": "bash",
                               "toolInput": {"command": "rm package-lock.json"}, "sessionId": "oc-1"})
        self.assertEqual(proc.returncode, 2, proc.stderr)

    def test_secret_read_is_blocked(self):
        proc = self._dispatch({"hookEvent": "tool.execute.before", "toolName": "read",
                               "toolInput": {"filePath": "/home/u/.ssh/id_rsa"}, "sessionId": "oc-2"})
        self.assertEqual(proc.returncode, 2, proc.stderr)

    def test_ls_is_allowed(self):
        proc = self._dispatch({"hookEvent": "tool.execute.before", "toolName": "bash",
                               "toolInput": {"command": "ls"}, "sessionId": "oc-3"})
        self.assertEqual(proc.returncode, 0, proc.stderr)
