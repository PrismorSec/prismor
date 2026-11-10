"""`prismor setup` must leave the alternate screen exactly once.

`ESC[?1049l` switches back to the main screen *and* restores the cursor saved
by `ESC[?1049h`. _do_install leaves the alt screen to print its summary on the
main screen; the atexit cleanup used to write `ESC[?1049l` again, which jumped
the cursor back to the row the wizard started on, so the shell prompt landed on
top of the install summary (`EXIT=1alling Prismor...`).
"""
import io
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prismor.runtime import setup_wizard as wizard  # noqa: E402

_ON = "\033[?1049h"
_OFF = "\033[?1049l"


class TestAltScreenLeftOnce(unittest.TestCase):
    def setUp(self):
        self.out = io.StringIO()
        self.home = tempfile.mkdtemp(prefix="prismor-alt-home-")
        self.target = Path(tempfile.mkdtemp(prefix="prismor-alt-ws-"))
        patches = [
            mock.patch.object(wizard, "ALT_ON", _ON),
            mock.patch.object(wizard, "ALT_OFF", _OFF),
            mock.patch.object(wizard, "_PLAIN", False),
            mock.patch.object(wizard, "_alt_active", False),
            mock.patch.object(wizard, "_raw_off", lambda: None),
            mock.patch.object(wizard.sys, "stdout", self.out),
            mock.patch.dict(os.environ, {"HOME": self.home}),
            mock.patch("prismor.runtime.setup_wizard._REPO_ROOT", Path("/nonexistent")),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def test_install_then_atexit_cleanup_writes_alt_off_once(self):
        wizard._enter_alt()
        wizard._do_install(self.target, "observe", rules=[], agents=[],
                           cloak=False, scope="project")
        wizard._cleanup()  # what atexit runs after the summary is printed
        text = self.out.getvalue()
        self.assertEqual(text.count(_ON), 1)
        self.assertEqual(text.count(_OFF), 1)
        # The summary is printed after leaving the alt screen, not before.
        self.assertLess(text.index(_OFF), text.index("Installing Prismor"))

    def test_quit_from_a_step_still_leaves_the_alt_screen(self):
        wizard._enter_alt()
        wizard._cleanup()  # `q` on any step
        wizard._cleanup()  # ...then atexit
        self.assertEqual(self.out.getvalue().count(_OFF), 1)

    def test_noninteractive_install_never_writes_alt_off(self):
        # The scripted path never entered the alt screen, so leaving it would
        # only restore a cursor position nobody saved.
        wizard._do_install(self.target, "observe", rules=[], agents=[],
                           cloak=False, scope="project")
        wizard._cleanup()
        self.assertNotIn(_OFF, self.out.getvalue())


if __name__ == "__main__":
    unittest.main()
