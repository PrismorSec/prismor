"""The `prismor enroll` summary box keeps its right border aligned, however long the values."""
import contextlib
import io
import unittest
from pathlib import Path

from prismor.runtime.tui_format import fit_list, print_enroll_summary, visible_len

AGENTS = ["claude", "cursor", "windsurf", "openclaw", "codex", "grok", "kiro", "openhands",
          "qwen", "continue", "goose", "antigravity", "copilot", "opencode"]


class EnrollBoxTest(unittest.TestCase):
    def test_every_row_is_the_same_width(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            print_enroll_summary(
                workspace=Path("/srv/a/very/long/workspace/path/that/keeps/going/on"),
                org="An Organisation Name That Is Far Too Long To Fit",
                device_label="a-rather-long-device-label-for-a-laptop",
                device_id="cmvhli4c800d1234567890",
                mode="observe", agents=AGENTS, rules_active=91,
                cloak_installed=False, cloak_secret_count=0, full_capture=False,
            )
        rows = [l for l in out.getvalue().splitlines() if "│" in l]
        self.assertTrue(rows)
        self.assertEqual({visible_len(r) for r in rows}, {visible_len(rows[0])})
        self.assertIn("more", "".join(rows))

    def test_fit_list_keeps_whole_names(self):
        s = fit_list(AGENTS, 32)
        self.assertLessEqual(len(s), 32)
        self.assertTrue(s.startswith("claude, cursor"))
        self.assertTrue(s.endswith("more"))
        self.assertEqual(fit_list(["claude"], 32), "claude")


if __name__ == "__main__":
    unittest.main()
