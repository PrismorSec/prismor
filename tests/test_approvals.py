"""Tests for the headless STEP_UP approval client (prismor.runtime.enterprise.approvals).

Exercises the post→poll→decide loop with the HTTP layer + identity monkeypatched
(no real control plane): approved, denied, timeout, not-enrolled, and non-step_up
all resolve to the correct fail-closed / allow verdict. Run:
  python3 tests/test_approvals.py
"""
from __future__ import annotations

import os
import sys
import types
import unittest
from pathlib import Path
from unittest import mock

_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO))

from prismor.runtime.enterprise import approvals  # noqa: E402


def _decision(action="step_up"):
    d = types.SimpleNamespace()
    d.blocking = {
        "action": action,
        "toolName": "mcp__db__query",
        "title": "Prod DB write requires approval",
        "ruleId": "prod-db",
        "severity": "HIGH",
        "evidence_hash": "abc123",
    }
    return d


class ApprovalClient(unittest.TestCase):
    def _patch(self, target, name, value):
        """Patch for the duration of one test.

        These stubs land on shared runtime modules — ``approvals._identity`` IS
        ``prismor.runtime.enterprise.identity`` — so a bare assignment would
        leave the whole process looking enrolled to a fake org for every test
        that ran afterwards. See tests/conftest.py.
        """
        patcher = mock.patch.object(target, name, value)
        patcher.start()
        self.addCleanup(patcher.stop)

    def setUp(self):
        os.environ.pop("PRISMOR_APPROVALS", None)
        os.environ["PRISMOR_APPROVAL_POLL"] = "0.01"
        os.environ["PRISMOR_APPROVAL_TIMEOUT"] = "2"
        self._ident = {"device_key": "prism_dev_x", "api_base": "https://cp.example"}
        self._patch(approvals._identity, "load_identity", lambda: self._ident)
        self._patch(approvals._identity, "revoked_backoff_active", lambda: False)
        self._posts = []
        self._status_seq = []

        def fake_post(ident, body, timeout):
            self._posts.append(body)
            return {"id": "appr_1", "status": "pending"}

        def fake_status(ident, approval_id, timeout):
            return self._status_seq.pop(0) if self._status_seq else "pending"

        self._patch(approvals, "_post_request", fake_post)
        self._patch(approvals, "_get_status", fake_status)

    def test_not_step_up_returns_false(self):
        self.assertFalse(approvals.await_step_up(_decision(action="block")))

    def test_approved(self):
        self._status_seq = ["pending", "approved"]
        self.assertTrue(approvals.await_step_up(_decision(), session_id="s1", agent="langchain"))
        # The request carried the reason + a stable fingerprint.
        self.assertEqual(self._posts[0]["reason"], "Prod DB write requires approval")
        self.assertEqual(len(self._posts[0]["fingerprint"]), 32)

    def test_denied(self):
        self._status_seq = ["pending", "denied"]
        self.assertFalse(approvals.await_step_up(_decision(), session_id="s1"))

    def test_expired_is_fail_closed(self):
        self._status_seq = ["expired"]
        self.assertFalse(approvals.await_step_up(_decision()))

    def test_timeout_fails_closed(self):
        self._status_seq = []  # always "pending" → never decided
        self.assertFalse(approvals.await_step_up(_decision()))

    def test_immediate_approved_on_create(self):
        self._patch(approvals, "_post_request",
                    lambda ident, body, timeout: {"id": "a", "status": "approved"})
        self.assertTrue(approvals.await_step_up(_decision()))

    def test_not_enrolled_fails_closed(self):
        self._patch(approvals._identity, "load_identity", lambda: None)
        self.assertFalse(approvals.await_step_up(_decision()))

    def test_post_failure_fails_closed(self):
        self._patch(approvals, "_post_request", lambda ident, body, timeout: None)
        self.assertFalse(approvals.await_step_up(_decision()))


class ApprovalConfig(ApprovalClient):
    """PRISMOR_APPROVALS master switch + the event-loop-safe async variant."""

    def test_disabled_by_env_fails_closed_without_posting(self):
        os.environ["PRISMOR_APPROVALS"] = "0"
        try:
            self.assertFalse(approvals.await_step_up(_decision(), session_id="s1"))
            self.assertEqual(self._posts, [])  # never reached the control plane
        finally:
            os.environ.pop("PRISMOR_APPROVALS", None)

    def test_enabled_accepts_common_truthy_spellings(self):
        for val in ("1", "true", "on", "yes", ""):
            os.environ["PRISMOR_APPROVALS"] = val
            self.assertTrue(approvals.enabled(), val)
        for val in ("0", "false", "off", "no"):
            os.environ["PRISMOR_APPROVALS"] = val
            self.assertFalse(approvals.enabled(), val)
        os.environ.pop("PRISMOR_APPROVALS", None)

    def test_async_variant_approves_off_the_event_loop(self):
        import asyncio

        self._status_seq = ["pending", "approved"]
        loop_blocked = {"max_gap": 0.0}

        async def heartbeat():
            # If await_step_up ran ON the loop, this coroutine would starve for
            # the full poll duration; a healthy loop keeps ticking every ~1ms.
            import time as _t
            last = _t.monotonic()
            while True:
                await asyncio.sleep(0.001)
                now = _t.monotonic()
                loop_blocked["max_gap"] = max(loop_blocked["max_gap"], now - last)
                last = now

        async def main():
            hb = asyncio.ensure_future(heartbeat())
            ok = await approvals.await_step_up_async(_decision(), session_id="s1", agent="crewai")
            hb.cancel()
            return ok

        self.assertTrue(asyncio.run(main()))
        self.assertLess(loop_blocked["max_gap"], 0.5)

    def test_async_variant_not_step_up_short_circuits(self):
        import asyncio
        self.assertFalse(asyncio.run(approvals.await_step_up_async(_decision(action="block"))))

    def test_async_variant_disabled_short_circuits(self):
        import asyncio
        os.environ["PRISMOR_APPROVALS"] = "off"
        try:
            self.assertFalse(asyncio.run(approvals.await_step_up_async(_decision())))
            self.assertEqual(self._posts, [])
        finally:
            os.environ.pop("PRISMOR_APPROVALS", None)


if __name__ == "__main__":
    unittest.main(verbosity=2)
