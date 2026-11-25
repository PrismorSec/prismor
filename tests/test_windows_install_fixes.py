"""Windows VM findings: hook-config parsing and mode switching."""

import tempfile
import unittest
from pathlib import Path

from prismor.runtime.hooks import HookConfigError, _read_json


class TestReadJson(unittest.TestCase):
    def _read(self, data: bytes):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "settings.json"
            p.write_bytes(data)
            return _read_json(p)

    def test_bom_is_accepted(self):
        self.assertEqual(self._read(b'\xef\xbb\xbf{"a": 1}'), {"a": 1})

    def test_empty_and_blank_files_are_empty_configs(self):
        self.assertEqual(self._read(b""), {})
        self.assertEqual(self._read(b" \r\n"), {})

    def test_null_root_and_null_hooks(self):
        self.assertEqual(self._read(b"null"), {})
        self.assertEqual(self._read(b'{"a": 1, "hooks": null}'), {"a": 1})

    def test_non_object_root_is_a_config_error(self):
        with self.assertRaises(HookConfigError):
            self._read(b"[1, 2]")

    def test_invalid_json_is_a_config_error(self):
        with self.assertRaises(HookConfigError):
            self._read(b"{nope")


class TestModeSwitchLiftsToolRules(unittest.TestCase):
    def test_previous_mode_tool_denies_are_lifted(self):
        from prismor.runtime.modes import apply_mode, load_modes
        MODES = load_modes()
        import yaml
        denying = [m for m, v in MODES.items() if (v.get("tools") or {}).get("deny")]
        if not denying:
            self.skipTest("no mode denies tools")
        first = denying[0]
        second = next((m for m, v in MODES.items() if not (v.get("tools") or {}).get("deny")), None)
        if second is None:
            self.skipTest("every mode denies tools")
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            apply_mode(ws, first)
            apply_mode(ws, second)
            f = ws / ".prismor" / "agents.yaml"
            cfg = yaml.safe_load(f.read_text()) if f.exists() else {}
            denied = (cfg or {}).get("global_deny_tools") or []
            for tool in (MODES[first].get("tools") or {}).get("deny") or []:
                self.assertNotIn(tool, denied)


if __name__ == "__main__":
    unittest.main()
