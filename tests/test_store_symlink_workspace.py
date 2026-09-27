"""Regression tests for workspace paths traversing symlinks (issue #416).

list_sessions filters on workspace.resolve(), but earlier versions wrote raw
str(workspace) into the sessions row. On any platform where the workspace path
traverses a symlink (such as macOS /tmp -> /private/tmp, container bind-mounts,
or symlinked home dirs), the two paths never matched, resulting in invisible
sessions in `prismor sessions`, `prismor status`, and the dashboard.
"""
from __future__ import annotations

import json
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prismor.runtime import proxy, store


def _analysis() -> dict:
    return {
        "findings": [],
        "feedMatches": [],
        "summary": {"riskScore": 0, "totalFindings": 0},
    }


def _events():
    return [{"type": "shell", "command": "echo test", "ts": "2026-01-01T00:00:00Z"}]


class TestStoreSymlinkWorkspace(unittest.TestCase):
    def setUp(self):
        self._tmp_dir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self._tmp_dir.name).resolve()
        self.real_workspace = self.tmp_path / "real_project"
        self.real_workspace.mkdir(parents=True, exist_ok=True)

        self.symlink_workspace = self.tmp_path / "symlink_project"
        self.symlink_workspace.symlink_to(self.real_workspace, target_is_directory=True)

        self.prismor_home = self.tmp_path / ".prismor-home"
        self.prismor_home.mkdir(parents=True, exist_ok=True)
        self._orig_home = os.environ.get("PRISMOR_HOME")
        os.environ["PRISMOR_HOME"] = str(self.prismor_home)

    def tearDown(self):
        if self._orig_home is not None:
            os.environ["PRISMOR_HOME"] = self._orig_home
        else:
            os.environ.pop("PRISMOR_HOME", None)
        self._tmp_dir.cleanup()

    def test_canonical_workspace_path_resolves_symlinks(self):
        resolved = store.canonical_workspace_path(self.symlink_workspace)
        self.assertEqual(resolved, str(self.real_workspace))
        self.assertEqual(store.canonical_workspace_path(""), "")
        self.assertEqual(store.canonical_workspace_path(None), "")

    def test_save_and_list_sessions_via_symlinked_workspace(self):
        """Saving via symlink_workspace must be visible when queried via real_workspace."""
        session_id = "sess-symlink-write"
        store.save_session_snapshot(
            workspace=self.symlink_workspace,
            session_id=session_id,
            agent="claude",
            source="test",
            repo_url=None,
            events=_events(),
            analysis=_analysis(),
        )

        # Query via real (resolved) workspace path
        sessions_from_real = store.list_sessions(self.real_workspace)
        self.assertEqual(len(sessions_from_real), 1)
        self.assertEqual(sessions_from_real[0]["sessionId"], session_id)
        self.assertEqual(sessions_from_real[0]["workspacePath"], str(self.real_workspace))

        # Query via symlink workspace path
        sessions_from_symlink = store.list_sessions(self.symlink_workspace)
        self.assertEqual(len(sessions_from_symlink), 1)
        self.assertEqual(sessions_from_symlink[0]["sessionId"], session_id)

    def test_legacy_unresolved_workspace_path_matched_by_resolved_query(self):
        """Pre-fix DB rows with un-resolved symlink workspace_path must be found by list_sessions."""
        db_path = store.initialize_database(self.real_workspace)
        conn = sqlite3.connect(db_path)
        try:
            conn.execute(
                """
                INSERT OR REPLACE INTO sessions (
                    session_id, agent, agent_name, source, workspace_path, repo_url,
                    started_at, updated_at, risk_score, findings_count, summary_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "legacy-symlink-session",
                    "claude",
                    "claude",
                    "test",
                    str(self.symlink_workspace),  # raw unresolved symlink path
                    None,
                    "2026-01-01T00:00:00Z",
                    "2026-01-01T00:00:00Z",
                    0,
                    0,
                    json.dumps({"riskScore": 0, "totalFindings": 0}),
                ),
            )
            conn.commit()
        finally:
            conn.close()

        # Query using the resolved real_workspace
        sessions = store.list_sessions(self.real_workspace)
        self.assertTrue(any(s["sessionId"] == "legacy-symlink-session" for s in sessions))

    def test_canonicalize_workspace_paths_migration(self):
        """_canonicalize_workspace_paths_once should update legacy unresolved workspace_path in tables."""
        db_path = store.initialize_database(self.real_workspace)
        conn = sqlite3.connect(db_path)
        try:
            conn.execute(
                """
                INSERT OR REPLACE INTO sessions (
                    session_id, agent, agent_name, source, workspace_path, repo_url,
                    started_at, updated_at, risk_score, findings_count, summary_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "to-migrate-session",
                    "claude",
                    "claude",
                    "test",
                    str(self.symlink_workspace),
                    None,
                    "2026-01-01T00:00:00Z",
                    "2026-01-01T00:00:00Z",
                    0,
                    0,
                    json.dumps({"riskScore": 0, "totalFindings": 0}),
                ),
            )
            conn.commit()

            # Remove migration marker if present to re-run
            marker = db_path.parent / "migrations" / "runtime-state" / "canonicalize-workspace-paths-v2.json"
            if marker.exists():
                marker.unlink()

            store._canonicalize_workspace_paths_once(conn, db_path)

            row = conn.execute("SELECT workspace_path FROM sessions WHERE session_id = ?", ("to-migrate-session",)).fetchone()
            self.assertEqual(row[0], str(self.real_workspace))
            self.assertTrue(marker.exists())
        finally:
            conn.close()

    def test_canonicalize_migration_covers_orphaned_telemetry_rows(self):
        """Rows in token_usage with no sessions row must still be canonicalized (#509)."""
        store.record_token_usage(
            workspace=self.real_workspace,
            session_id="orphan-session",
            message_id="msg-orphan",
            ts="2026-01-01T00:00:00Z",
            model="claude-3-5-sonnet",
            input_tokens=100,
            output_tokens=50,
            cache_read_tokens=0,
            cache_creation_tokens=0,
        )
        db_path = store.get_db_path(self.real_workspace)
        conn = sqlite3.connect(db_path)
        try:
            conn.execute("UPDATE token_usage SET workspace_path = ?", (str(self.symlink_workspace),))
            conn.commit()
            self.assertIsNone(conn.execute("SELECT 1 FROM sessions WHERE session_id = 'orphan-session'").fetchone())
            marker = db_path.parent / "migrations" / "runtime-state" / "canonicalize-workspace-paths-v2.json"
            marker.unlink(missing_ok=True)

            store._canonicalize_workspace_paths_once(conn, db_path)

            row = conn.execute("SELECT workspace_path FROM token_usage WHERE session_id = 'orphan-session'").fetchone()
            self.assertEqual(row[0], str(self.real_workspace))
        finally:
            conn.close()

    def test_proxy_default_workspace_resolves_symlinks(self):
        """default_workspace() must return a resolved Path even when PRISMOR_HOME is behind a symlink."""
        sym_home = self.tmp_path / "symlink_home"
        sym_home.symlink_to(self.prismor_home, target_is_directory=True)
        os.environ["PRISMOR_HOME"] = str(sym_home)

        ws = proxy.default_workspace()
        self.assertEqual(ws, (self.prismor_home / "surfaces" / "proxy").resolve())

    def test_token_usage_across_symlink_workspace(self):
        """Token stats must be queryable across symlink and resolved workspace paths."""
        store.record_token_usage(
            workspace=self.symlink_workspace,
            session_id="token-sym-session",
            message_id="msg-1",
            ts="2026-01-01T00:00:00Z",
            model="claude-3-5-sonnet",
            input_tokens=100,
            output_tokens=50,
            cache_read_tokens=10,
            cache_creation_tokens=5,
        )

        stats_symlink = store.get_token_stats(self.symlink_workspace, hours=24 * 365 * 10)
        stats_real = store.get_token_stats(self.real_workspace, hours=24 * 365 * 10)

        self.assertGreater(stats_symlink["inputTokens"], 0)
        self.assertEqual(stats_symlink["inputTokens"], stats_real["inputTokens"])


if __name__ == "__main__":
    unittest.main()
