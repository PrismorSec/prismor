"""Tests for session-intent capture (prismor.runtime.intent) used by SDK adapters.

capture_intent must synthesize + persist scoped rules from a goal once per
session, no-op without a goal or when already captured, use the adapter's own
tool names, and never raise. The synthesizer is monkeypatched so the test is
hermetic (no Anthropic SDK / network). Enforcement of the saved rules is covered
by the existing scoped-agent tests. Run:  python3 tests/test_intent_capture.py
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO))

from prismor.runtime import intent as intent_mod  # noqa: E402
from prismor.runtime import scoped_agent  # noqa: E402


class CaptureIntent(unittest.TestCase):
    def _patch(self, target, name, value):
        patcher = mock.patch.object(target, name, value)
        patcher.start()
        self.addCleanup(patcher.stop)

    def setUp(self):
        # Scoped rules live under $PRISMOR_HOME/scoped/<sid>.json (keyed by session
        # id in the prismor home, not the workspace) — isolate it so tests don't
        # collide with each other or the real vault.
        os.environ["PRISMOR_HOME"] = str(Path(tempfile.mkdtemp(prefix="prismor-intent-home-")))
        self.ws = Path(tempfile.mkdtemp(prefix="prismor-intent-"))
        self.calls = []

        def fake_synth(goal, available_tools, workspace):
            self.calls.append({"goal": goal, "tools": list(available_tools)})
            return {"allowed_tools": available_tools, "goal": goal}

        # Patch the names capture_intent imports from scoped_agent. Via
        # mock.patch.object so the stub cannot outlive the test — scoped_agent
        # is shared with the runtime (see tests/conftest.py).
        self._patch(scoped_agent, "synthesize_scoped_rules", fake_synth)

    def test_no_goal_is_noop(self):
        self.assertIsNone(intent_mod.capture_intent("", workspace=self.ws, session_id="s1"))
        self.assertIsNone(intent_mod.capture_intent(None, workspace=self.ws, session_id="s1"))
        self.assertEqual(self.calls, [])

    def test_synthesizes_and_persists(self):
        rules = intent_mod.capture_intent(
            "summarize the repo README", workspace=self.ws, session_id="s1",
            available_tools=["read_file", "search"],
        )
        self.assertIsNotNone(rules)
        # Rules were saved to the session sidecar and load back.
        self.assertIsNotNone(scoped_agent.load_scoped_rules(self.ws, "s1"))
        # The agent's own tool names were passed to the synthesizer (not defaults).
        self.assertEqual(self.calls[0]["tools"], ["read_file", "search"])

    def test_idempotent_per_session(self):
        intent_mod.capture_intent("goal one", workspace=self.ws, session_id="s1", available_tools=["a"])
        intent_mod.capture_intent("goal two", workspace=self.ws, session_id="s1", available_tools=["a"])
        self.assertEqual(len(self.calls), 1, "second capture on the same session must no-op")

    def test_defaults_when_no_tools(self):
        intent_mod.capture_intent("do a thing", workspace=self.ws, session_id="s2")
        self.assertIn("Bash", self.calls[0]["tools"])  # fell back to the default toolset

    def test_never_raises(self):
        def boom(goal, available_tools, workspace):
            raise RuntimeError("synth exploded")

        self._patch(scoped_agent, "synthesize_scoped_rules", boom)
        # Must swallow and return None, not propagate.
        self.assertIsNone(intent_mod.capture_intent("x", workspace=self.ws, session_id="s3"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
