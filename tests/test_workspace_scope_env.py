"""PRISMOR_WORKSPACE_SCOPE — the escape hatch for repo-less deployed workloads.

Scope decides whether the org policy overlay merges, and that overlay is what
carries the telemetry sink. A container has no git remote, so an org that claims
repo patterns leaves it 'local' and it reports nothing, silently. The env var
settles it — but it must NOT let a deployment downgrade a repo the org claims.
Run: python3 tests/test_workspace_scope_env.py
"""
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from unittest import mock

_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO))

from prismor.runtime.enterprise import workspace_scope as ws  # noqa: E402


class EnvScopeOverride(unittest.TestCase):
    def _patch(self, target, name, value):
        """Patch for the duration of one test.

        ``ws._identity`` IS ``prismor.runtime.enterprise.identity``: assigning
        to it directly would leave every later test on this process reading as
        enrolled to org_1, with a claimed-repo pattern set. See tests/conftest.py.
        """
        patcher = mock.patch.object(target, name, value)
        patcher.start()
        self.addCleanup(patcher.stop)

    def setUp(self):
        os.environ.pop("PRISMOR_WORKSPACE_SCOPE", None)
        self.addCleanup(os.environ.pop, "PRISMOR_WORKSPACE_SCOPE", None)
        self._ident = {"org_id": "org_1", "device_key": "k", "api_base": "https://cp.example"}
        self._patch(ws._identity, "load_identity", lambda: self._ident)
        self._patch(ws._identity, "revoked_info", lambda: None)
        self._patch(ws, "detect_git_remote", lambda _w: None)   # a container: no remote
        self._patch(ws, "org_managed_patterns", lambda: ["github.com/acme/*"])
        self._patch(ws, "_load_overrides", lambda: {})

    def test_repoless_workload_is_local_without_the_override(self):
        # The status quo this exists to fix: silent, total non-reporting.
        r = ws.resolve_scope(Path("/srv/agent"))
        self.assertEqual(r["scope"], "local")
        self.assertEqual(r["reason"], "personal")

    def test_managed_opts_a_repoless_workload_in(self):
        os.environ["PRISMOR_WORKSPACE_SCOPE"] = "managed"
        r = ws.resolve_scope(Path("/srv/agent"))
        self.assertEqual(r["scope"], "managed")
        self.assertEqual(r["reason"], "env_override")
        self.assertEqual(r["org_id"], "org_1")

    def test_personal_and_local_opt_out(self):
        for val in ("personal", "local"):
            os.environ["PRISMOR_WORKSPACE_SCOPE"] = val
            r = ws.resolve_scope(Path("/srv/agent"))
            self.assertEqual(r["scope"], "local", val)
            self.assertEqual(r["reason"], "env_opt_out", val)

    def test_case_and_whitespace_tolerant(self):
        os.environ["PRISMOR_WORKSPACE_SCOPE"] = "  MANAGED  "
        self.assertEqual(ws.resolve_scope(Path("/srv/agent"))["scope"], "managed")

    def test_garbage_value_is_ignored_not_fatal(self):
        os.environ["PRISMOR_WORKSPACE_SCOPE"] = "yes-please"
        r = ws.resolve_scope(Path("/srv/agent"))
        self.assertEqual(r["scope"], "local")
        self.assertEqual(r["reason"], "personal")  # fell through, did not raise

    def test_cannot_downgrade_a_repo_the_org_claims(self):
        # The security property: an org-claimed remote outranks the env var, so
        # a deployment cannot opt company code out of governance.
        self._patch(ws, "detect_git_remote", lambda _w: "github.com/acme/payments")
        os.environ["PRISMOR_WORKSPACE_SCOPE"] = "personal"
        r = ws.resolve_scope(Path("/srv/agent"))
        self.assertEqual(r["scope"], "managed")
        self.assertEqual(r["reason"], "org_claimed")

    def test_unenrolled_stays_local_regardless(self):
        self._patch(ws._identity, "load_identity", lambda: None)
        os.environ["PRISMOR_WORKSPACE_SCOPE"] = "managed"
        r = ws.resolve_scope(Path("/srv/agent"))
        self.assertEqual(r["scope"], "local")
        self.assertEqual(r["reason"], "not_enrolled")

    def test_env_outranks_the_on_disk_override(self):
        # A container's $PRISMOR_HOME is often read-only, so the env var has to
        # win over a stale file written into the image.
        self._patch(ws, "_load_overrides",
                    lambda: {str(Path("/srv/agent").resolve()): "personal"})
        os.environ["PRISMOR_WORKSPACE_SCOPE"] = "managed"
        r = ws.resolve_scope(Path("/srv/agent"))
        self.assertEqual(r["scope"], "managed")
        self.assertEqual(r["reason"], "env_override")


if __name__ == "__main__":
    unittest.main(verbosity=2)
