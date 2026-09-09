"""The setup wizard's confirm box has to hold what it prints.

The box was a fixed 48 columns and its row padding floors at zero, so a value
wider than the box -- ten enrolled agents, comfortably -- printed straight
through the right border.
"""

import os
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prismor.runtime import setup_wizard as wizard  # noqa: E402

AGENTS = ["claude", "cursor", "windsurf", "openclaw", "codex", "grok", "kiro",
          "openhands", "qwen", "goose"]


def _plain(line: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*m", "", line)


def _confirm_lines(width: int):
    captured = []
    original = (wizard._render, wizard._read_key, wizard._term_width)
    wizard._render = lambda lines: captured.append(list(lines))
    wizard._read_key = lambda: "q"
    wizard._term_width = lambda: width
    try:
        wizard._step_confirm(Path.home() / "workspace", "observe",
                             [{"on": True, "recommended": True}], AGENTS,
                             cloak=True, scope="project")
    except SystemExit:
        pass
    finally:
        wizard._render, wizard._read_key, wizard._term_width = original
    return [_plain(l) for l in captured[0]]


class TestConfirmBox(unittest.TestCase):
    def test_every_box_line_is_the_same_width(self):
        for width in (64, 80, 100, 140):
            lines = [l for l in _confirm_lines(width)
                     if l.lstrip().startswith(("│", "╭", "╰"))]
            widths = {len(l) for l in lines}
            self.assertEqual(len(widths), 1,
                             f"ragged box at term width {width}: {sorted(widths)}")

    def test_the_box_fits_the_terminal(self):
        for width in (64, 80, 100):
            for line in _confirm_lines(width):
                self.assertLessEqual(len(line), width, f"line wider than {width}: {line!r}")

    def test_a_long_agent_list_wraps_rather_than_truncates(self):
        body = " ".join(_confirm_lines(64))
        for agent in AGENTS:
            self.assertIn(agent, body, f"{agent} vanished from the summary")


class TestWrapValue(unittest.TestCase):
    def test_breaks_on_commas_first(self):
        self.assertEqual(wizard._wrap_value("alpha, beta, gamma", 12), ["alpha, beta,", "gamma"])

    def test_short_value_is_left_alone(self):
        self.assertEqual(wizard._wrap_value("observe", 20), ["observe"])

    def test_an_unbreakable_value_is_still_cut_to_width(self):
        out = wizard._wrap_value("x" * 30, 10)
        self.assertTrue(all(len(chunk) <= 10 for chunk in out), out)


if __name__ == "__main__":
    unittest.main()
