"""Tests for the Prismor IAM enforcement layer.

Regression guard for the PR #41 review finding: ``check_iam()`` produced a
finding with ``category="iam"``, but ``should_block()`` silently dropped it
because ``iam`` was missing from the policy ``block_categories`` — making
enforce-mode IAM a no-op. The ``iam check`` CLI masked this by exiting 2
directly, so the manual test plan passed while live enforcement did nothing.

These tests exercise the real blocking path (``should_block`` + a full
``hook-dispatch`` subprocess), not ``iam check``.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prismor.runtime import iam as iam_mod
from prismor.runtime.hooks import should_block
from prismor.runtime.policy_engine import PolicyEngine

REPO_ROOT = Path(__file__).resolve().parent.parent

_PROFILES = """\
agents:
  readonly-bot:
    allowed_tools: [Read]
    deny_tools: []
    deny_network: true
    allowed_paths: ["**"]
  researcher:
    allowed_tools: [Read, WebFetch, WebSearch]
    deny_tools: [Bash, Write, Edit]
    deny_network: false
    allowed_paths: ["**"]
  scoped-reader:
    allowed_tools: [Read]
    deny_tools: []
    deny_network: true
    allowed_paths: ["docs/**"]
  edit-only:
    allowed_tools: [Read, Edit]
    deny_tools: [Write]
    deny_network: true
    allowed_paths: ["**"]
"""


class _IamTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        # Hermetic: drop the path+mtime config memo and the warn-once state so
        # test order can't leak a cached config or a suppressed warning.
        iam_mod._CONFIG_CACHE.clear()
        iam_mod._WARNED_UNKNOWN_IDS.clear()
        # Isolate from any real ~/.prismor/iam.yaml on the test machine.
        self._orig_global = iam_mod._global_iam_path
        iam_mod._global_iam_path = lambda: self.tmp / "no-such-global-iam.yaml"
        proj = self.tmp / ".prismor"
        proj.mkdir(parents=True, exist_ok=True)
        (proj / "iam.yaml").write_text(_PROFILES, encoding="utf-8")
        self._orig_env = os.environ.get("PRISMOR_AGENT_ID")

    def tearDown(self):
        iam_mod._global_iam_path = self._orig_global
        if self._orig_env is None:
            os.environ.pop("PRISMOR_AGENT_ID", None)
        else:
            os.environ["PRISMOR_AGENT_ID"] = self._orig_env

    def _block_categories(self):
        # Mirror cli.py: block decision uses the policy's block_categories.
        return set(PolicyEngine(workspace=self.tmp).block_categories)


class TestSubjectLabel(_IamTestBase):
    def test_org_deny_names_console_label_not_raw_id(self):
        from prismor.runtime.principal import Subject
        os.environ.pop("PRISMOR_AGENT_ID", None)
        ev = {"type": "shell", "command": "ls", "metadata": {"tool_name": "Bash"}}
        ctl = {"user:XFz991": {"deny_tools": ["Bash"], "label": "Dana Reyes"}}
        f = iam_mod.check_iam(workspace=self.tmp, event=ev, session_id="s",
                              subject=Subject(user_id="XFz991"), remote_controls=ctl)
        self.assertIsNotNone(f)
        self.assertIn("user 'Dana Reyes'", f["title"])


class TestCheckIamFinding(_IamTestBase):
    def test_denied_write_produces_iam_finding(self):
        os.environ["PRISMOR_AGENT_ID"] = "readonly-bot"
        ev = {"type": "file_write", "path": "main.py", "agent_event": "PreToolUse"}
        f = iam_mod.check_iam(workspace=self.tmp, event=ev, session_id="s")
        self.assertIsNotNone(f)
        self.assertEqual(f["category"], "iam")

    def test_allowed_read_passes(self):
        os.environ["PRISMOR_AGENT_ID"] = "readonly-bot"
        ev = {"type": "file_read", "path": "main.py", "agent_event": "PreToolUse"}
        self.assertIsNone(iam_mod.check_iam(workspace=self.tmp, event=ev, session_id="s"))

    def test_no_agent_id_means_no_restriction(self):
        os.environ.pop("PRISMOR_AGENT_ID", None)
        ev = {"type": "file_write", "path": "main.py", "agent_event": "PreToolUse"}
        self.assertIsNone(iam_mod.check_iam(workspace=self.tmp, event=ev, session_id="s"))

    def test_unknown_agent_falls_back_to_deny(self):
        os.environ["PRISMOR_AGENT_ID"] = "ghost"
        ev = {"type": "shell", "command": "ls", "agent_event": "PreToolUse"}
        f = iam_mod.check_iam(workspace=self.tmp, event=ev, session_id="s")
        self.assertIsNotNone(f)
        self.assertEqual(f["category"], "iam")

    def test_project_config_overrides_global(self):
        # Global defines readonly-bot as allowing writes; project locks it down.
        global_path = self.tmp / "global.yaml"
        iam_mod._global_iam_path = lambda: global_path
        global_path.write_text(
            "agents:\n  readonly-bot:\n    allowed_tools: [Read, Write]\n"
            "    deny_tools: []\n    deny_network: true\n    allowed_paths: ['**']\n",
            encoding="utf-8",
        )
        os.environ["PRISMOR_AGENT_ID"] = "readonly-bot"
        ev = {"type": "file_write", "path": "main.py", "agent_event": "PreToolUse"}
        # Project profile (Read only) must win → write is denied.
        self.assertIsNotNone(iam_mod.check_iam(workspace=self.tmp, event=ev, session_id="s"))


class TestIamBlockingDecision(_IamTestBase):
    """The core regression: iam findings must reach a block verdict."""

    def test_iam_in_default_block_categories(self):
        self.assertIn("iam", self._block_categories())

    def test_denied_write_blocks(self):
        os.environ["PRISMOR_AGENT_ID"] = "readonly-bot"
        ev = {"type": "file_write", "path": "main.py", "agent_event": "PreToolUse"}
        f = iam_mod.check_iam(workspace=self.tmp, event=ev, session_id="s")
        verdict = should_block([f], ev, block_categories=self._block_categories())
        self.assertIsNotNone(verdict)
        self.assertEqual(verdict["category"], "iam")

    def test_denied_shell_blocks(self):
        os.environ["PRISMOR_AGENT_ID"] = "readonly-bot"
        ev = {"type": "shell", "command": "rm x", "agent_event": "PreToolUse"}
        f = iam_mod.check_iam(workspace=self.tmp, event=ev, session_id="s")
        self.assertIsNotNone(should_block([f], ev, block_categories=self._block_categories()))

    def test_denied_network_blocks(self):
        os.environ["PRISMOR_AGENT_ID"] = "readonly-bot"
        ev = {"type": "network", "url": "https://x", "agent_event": "PreToolUse"}
        f = iam_mod.check_iam(workspace=self.tmp, event=ev, session_id="s")
        self.assertIsNotNone(should_block([f], ev, block_categories=self._block_categories()))

    def test_iam_read_denial_blocks_despite_file_read_carveout(self):
        # scoped-reader may only read docs/**; a read elsewhere is an iam denial
        # that must block (the file_read carve-out only spares non-iam reads).
        os.environ["PRISMOR_AGENT_ID"] = "scoped-reader"
        ev = {"type": "file_read", "path": "secrets/key.pem", "agent_event": "PreToolUse"}
        f = iam_mod.check_iam(workspace=self.tmp, event=ev, session_id="s")
        self.assertIsNotNone(f)
        self.assertIsNotNone(should_block([f], ev, block_categories=self._block_categories()))

    def test_allowed_network_does_not_block(self):
        os.environ["PRISMOR_AGENT_ID"] = "researcher"
        ev = {"type": "network", "url": "https://api.example.com", "agent_event": "PreToolUse"}
        self.assertIsNone(iam_mod.check_iam(workspace=self.tmp, event=ev, session_id="s"))


class TestDenyToolsEnforcement(_IamTestBase):
    """deny_tools must take precedence over allowed_tools.

    Regression for the review finding: ``edit-only`` allows Edit but denies
    Write, yet a file_write was allowed because the checker only asked whether
    *any* write-family tool was allowed and never consulted deny_tools.
    """

    def test_denied_write_blocks_when_tool_unknown(self):
        # No metadata.tool_name → a file_write resolves to the literal Write,
        # which edit-only denies. Must block even though Edit is allowed.
        os.environ["PRISMOR_AGENT_ID"] = "edit-only"
        ev = {"type": "file_write", "path": "main.py", "agent_event": "PreToolUse"}
        f = iam_mod.check_iam(workspace=self.tmp, event=ev, session_id="s")
        self.assertIsNotNone(f)
        self.assertEqual(f["category"], "iam")
        self.assertIsNotNone(should_block([f], ev, block_categories=self._block_categories()))

    def test_denied_write_blocks_via_metadata_tool_name(self):
        # An explicit Write tool (from the hook normalizer) is denied.
        os.environ["PRISMOR_AGENT_ID"] = "edit-only"
        ev = {"type": "file_write", "path": "main.py",
              "metadata": {"tool_name": "Write"}, "agent_event": "PreToolUse"}
        self.assertIsNotNone(iam_mod.check_iam(workspace=self.tmp, event=ev, session_id="s"))

    def test_allowed_edit_passes_via_metadata_tool_name(self):
        # The same profile permits Edit; the concrete tool from metadata wins.
        os.environ["PRISMOR_AGENT_ID"] = "edit-only"
        ev = {"type": "file_write", "path": "main.py",
              "metadata": {"tool_name": "Edit"}, "agent_event": "PreToolUse"}
        self.assertIsNone(iam_mod.check_iam(workspace=self.tmp, event=ev, session_id="s"))


class TestIamHookDispatchEndToEnd(_IamTestBase):
    """Drive the real hook-dispatch path in enforce mode (not ``iam check``)."""

    def _dispatch(self, payload, agent_id):
        env = dict(os.environ)
        env["PRISMOR_AGENT_ID"] = agent_id
        env["HOME"] = str(self.tmp)  # isolate global ~/.prismor in the subprocess
        return subprocess.run(
            [sys.executable, str(REPO_ROOT / "prismor" / "runtime" / "cli.py"),
             "hook-dispatch", "--agent", "claude",
             "--workspace", str(self.tmp), "--mode", "enforce"],
            input=json.dumps(payload), capture_output=True, text=True, env=env,
        )

    def test_enforce_blocks_denied_write(self):
        payload = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Write",
            "tool_input": {"file_path": "main.py", "content": "x"},
            "session_id": "e2e-write",
        }
        proc = self._dispatch(payload, "readonly-bot")
        self.assertEqual(proc.returncode, 2, f"stdout={proc.stdout}\nstderr={proc.stderr}")
        self.assertIn("iam:readonly-bot", proc.stderr)

    def test_enforce_allows_read(self):
        payload = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "main.py"},
            "session_id": "e2e-read",
        }
        proc = self._dispatch(payload, "readonly-bot")
        self.assertEqual(proc.returncode, 0, f"stdout={proc.stdout}\nstderr={proc.stderr}")


if __name__ == "__main__":
    unittest.main()
