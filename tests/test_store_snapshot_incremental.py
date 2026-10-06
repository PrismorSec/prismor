"""A hook call snapshots the session after every event, so the snapshot must
append only the new events rather than rewrite them all (it made each call
O(session): ~5s on a 2.4k-event session).

Run:  python3 tests/test_store_snapshot_incremental.py
"""
from __future__ import annotations

import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prismor.runtime import store

_SESSION = "sess-incr"
_ANALYSIS = {"findings": [], "feedMatches": [], "summary": {"riskScore": 0, "totalFindings": 0}}


def _events(n: int):
    return [{"type": "shell", "command": f"echo {i}", "ts": f"2026-01-01T00:00:{i:02d}Z"}
            for i in range(n)]


class TestSnapshotIncremental(unittest.TestCase):
    def setUp(self):
        self.workspace = Path(tempfile.mkdtemp(prefix="prismor-incr-"))
        os.environ["PRISMOR_HOME"] = str(self.workspace)

    def _snapshot(self, events, append_only=True):
        store.save_session_snapshot(
            workspace=self.workspace, session_id=_SESSION, agent="claude",
            source="test", repo_url=None, events=events, analysis=_ANALYSIS,
            append_only=append_only,
        )
        conn = sqlite3.connect(store.initialize_database(self.workspace))
        try:
            return [r[0] for r in conn.execute(
                "SELECT command_text FROM events WHERE session_id = ? ORDER BY id", (_SESSION,))]
        finally:
            conn.close()

    def test_growing_log_appends_only_new_events(self):
        self._snapshot(_events(3))
        self.assertEqual(self._snapshot(_events(5)), [f"echo {i}" for i in range(5)])
        # Re-snapshotting the same log adds nothing.
        self.assertEqual(len(self._snapshot(_events(5))), 5)

    def test_shorter_log_is_rewritten_in_full(self):
        self._snapshot(_events(5))
        self.assertEqual(self._snapshot(_events(2)), ["echo 0", "echo 1"])

    def test_reparsed_session_is_rewritten_in_full(self):
        """ingest/replay re-parse the whole session: changed rows must be refreshed."""
        self._snapshot(_events(3), append_only=False)
        changed = [dict(e, command=e["command"] + "!") for e in _events(3)]
        self.assertEqual(self._snapshot(changed, append_only=False), ["echo 0!", "echo 1!", "echo 2!"])


if __name__ == "__main__":
    unittest.main()
