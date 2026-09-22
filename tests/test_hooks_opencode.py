"""Tests for the OpenCode hooks adapter (strip, _merge_opencode, _normalize_opencode).

OpenCode uses JS plugins registered under opencode.json ("plugins": [...]) and
throws an Error on deny inside tool.execute.before.
These tests verify:
  - "opencode" is in _SUPPORTED_AGENTS.
  - stripping      removes Prismor plugin entries.
  - _merge_opencode scaffolds the plugin package and registers it.
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
    _strip_for_agent,
    _merge_opencode,
    _normalize_opencode,
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


# --- stripping ---------------------------------------------------------

class TestStripOpenCode(unittest.TestCase):
    """Stripping removes Prismor plugin entries while keeping others."""

    def test_removes_prismor_plugin(self):
        config = {
            "plugins": [
                "/repo/prismor/runtime/opencode-plugin",
                "/other/plugin",
            ]
        }
        result, removed = _strip_for_agent("opencode", config, _MARKER)
        self.assertTrue(removed)
        self.assertEqual(result["plugins"], ["/other/plugin"])

    def test_no_change_when_absent(self):
        config = {"plugins": ["/other/plugin"]}
        result, removed = _strip_for_agent("opencode", config, _MARKER)
        self.assertFalse(removed)
        self.assertEqual(result["plugins"], ["/other/plugin"])


# --- _merge_opencode & scaffolding -------------------------------------------

class TestMergeOpenCode(unittest.TestCase):
    """_merge_opencode scaffolds plugin and adds entry to plugins.json."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.repo_root = Path(self.tmpdir)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_scaffolds_plugin_file_and_package_json(self):
        config = _merge_opencode({}, _COMMAND, self.repo_root)
        plugin_dir = self.repo_root / "prismor" / "runtime" / "opencode-plugin"
        self.assertTrue((plugin_dir / "package.json").exists())
        self.assertTrue((plugin_dir / "index.js").exists())

        index_js = (plugin_dir / "index.js").read_text()
        self.assertIn(_COMMAND, index_js)
        self.assertIn("tool.execute.before", index_js)
        self.assertIn("tool.execute.after", index_js)

        # Check plugin path registered
        self.assertIn(str(plugin_dir), config["plugins"])

    def test_idempotent_merge(self):
        config1 = _merge_opencode({}, _COMMAND, self.repo_root)
        config2 = _merge_opencode(config1, _COMMAND, self.repo_root)
        plugin_dir = str(self.repo_root / "prismor" / "runtime" / "opencode-plugin")
        self.assertEqual(config2["plugins"].count(plugin_dir), 1)


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
        event = self._n({
            "hookEvent": "tool.execute.before",
            "toolName": "fetch",
            "toolInput": {"url": "https://api.github.com"},
        })
        self.assertEqual(event["type"], "network")
        self.assertEqual(event["url"], "https://api.github.com")

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
    """install_hooks + uninstall_hooks write and cleanly remove OpenCode config."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.workspace = Path(self.tmpdir) / "project"
        self.workspace.mkdir()
        self.repo_root = Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_install_and_uninstall_roundtrip(self):
        install_hooks(
            repo_root=self.repo_root,
            workspace=self.workspace,
            agent="opencode",
            scope="project",
            mode="observe",
        )
        config_path = self.workspace / ".opencode" / "plugins.json"
        self.assertTrue(config_path.exists())
        config = json.loads(config_path.read_text())
        self.assertGreater(len(config.get("plugins", [])), 0)

        # Uninstall
        results = uninstall_hooks(
            repo_root=self.repo_root,
            workspace=self.workspace,
            agent="opencode",
            scope="project",
        )
        self.assertTrue(results[0]["removed"])
        config_after = json.loads(config_path.read_text())
        self.assertEqual(config_after.get("plugins", []), [])


if __name__ == "__main__":
    unittest.main()
