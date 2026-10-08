"""Regression tests for the dashboard-facing queries in store.py.

get_findings_page() and get_events_page() had no test coverage at all before
PrismorSec/prismor#129 and #130 — both queries built session data through the
real ingest path (save_session_snapshot + analyze_events) and asserted on the
API-shaped output, the same way `prismor ingest` / the dashboard actually do.
"""

import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prismor.runtime.cli import analyze_events
from prismor.runtime.scoped_agent import save_scoped_rules
from prismor.runtime.store import (
    canonical_workspace_path,
    get_dependency_usage,
    get_network_calls,
    get_events_page,
    get_findings_page,
    get_policy_precedence,
    get_policy_rule_catalog,
    get_session_scoped_detail,
    persist_runtime_findings,
    save_session_snapshot,
    set_project_rule_states,
    write_policy_layer,
    write_supply_chain_event,
)
from supplychain.ecosystems.detector import PackageSpec
from supplychain.ecosystems.metadata import PackageMetadata
from supplychain.scoring.engine import PackageVerdict, Signal


class TestDashboardQueries(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.workspace = Path(self._tmp.name)
        self._orig_prismor_home = os.environ.get("PRISMOR_HOME")
        os.environ["PRISMOR_HOME"] = str(self.workspace / ".prismor-home")
        # Patch list_registered_workspaces rather than calling the real
        # register_workspace(), which writes to global machine state.
        patcher = patch("prismor.runtime.store.list_registered_workspaces", return_value=[self.workspace])
        patcher.start()
        self.addCleanup(patcher.stop)

        # A mix of one allowed (benign) and one blocked (destructive) shell
        # event in the same session — the exact shape that exposed both bugs.
        self.events = [
            {"type": "shell", "command": "ls -la", "ts": "2026-01-01T00:00:00Z"},
            {"type": "shell", "command": "rm -rf /", "ts": "2026-01-01T00:00:01Z"},
        ]
        analysis = analyze_events(self.events, repo_root=self.workspace, workspace=self.workspace)
        save_session_snapshot(
            workspace=self.workspace,
            session_id="test-session",
            agent="claude",
            source="ingest",
            repo_url=None,
            events=self.events,
            analysis=analysis,
        )

    def tearDown(self):
        if self._orig_prismor_home is None:
            os.environ.pop("PRISMOR_HOME", None)
        else:
            os.environ["PRISMOR_HOME"] = self._orig_prismor_home
        self._tmp.cleanup()

    def test_findings_page_returns_the_stored_finding(self):
        # Regression for #129: a correlated OFFSET subquery made this always
        # raise (silently swallowed), so `items`/`total` were always empty.
        data = get_findings_page()
        self.assertEqual(data["total"], 1)
        self.assertEqual(data["items"][0]["category"], "dangerous_command")
        self.assertIn("rm -rf /", data["items"][0]["trigger"]["detail"])

    def test_events_page_marks_only_the_actual_finding_as_blocked(self):
        # Regression for #130: verdict/severity were computed from
        # `s.findings_count > 0` (session-wide), so the benign `ls -la` event
        # also showed up as "blocked"/"critical" just because the session
        # contained an unrelated blocked event.
        data = get_events_page()
        by_action = {item["action"]: item for item in data["items"]}
        self.assertEqual(by_action["shell: ls -la"]["verdict"], "allowed")
        self.assertEqual(by_action["shell: rm -rf /"]["verdict"], "blocked")
        self.assertEqual(by_action["shell: rm -rf /"]["severity"], "critical")

    def test_session_detail_links_each_finding_to_its_own_event(self):
        # The recent-blocked list joins a finding to its event by position in
        # the session. It used to count earlier events per (finding, event)
        # pair, which timed the dashboard's session page out on large
        # sessions; the rewrite must still pick the finding's own event.
        detail = get_session_scoped_detail(self.workspace, "test-session")
        stamps = [item["ts"] for item in detail["recent_blocked"]]
        self.assertIn("2026-01-01T00:00:01Z", stamps)      # the rm -rf event
        self.assertNotIn("2026-01-01T00:00:00Z", stamps)   # not the ls before it

    def test_events_page_verdict_filter_uses_per_event_match(self):
        allowed_only = get_events_page(verdict="allowed")
        actions = [item["action"] for item in allowed_only["items"]]
        self.assertIn("shell: ls -la", actions)
        self.assertNotIn("shell: rm -rf /", actions)

        blocked_only = get_events_page(verdict="blocked")
        actions = [item["action"] for item in blocked_only["items"]]
        self.assertIn("shell: rm -rf /", actions)
        self.assertNotIn("shell: ls -la", actions)

    def test_events_page_infers_scoped_agent_blocks(self):
        session_id = "scoped-session"
        save_scoped_rules(
            self.workspace,
            session_id,
            {
                "allowed_tools": ["Read"],
                "deny_tools": ["Bash"],
                "allowed_paths": ["**"],
                "deny_network": True,
            },
        )
        save_session_snapshot(
            workspace=self.workspace,
            session_id=session_id,
            agent="codex",
            source="hook",
            repo_url=None,
            events=[
                {
                    "type": "shell",
                    "agent_event": "PreToolUse",
                    "command": "prismor status",
                    "ts": "2026-01-01T00:00:02Z",
                    "metadata": {"tool_name": "Bash"},
                }
            ],
            analysis={"summary": {"riskScore": 0, "totalFindings": 0}, "findings": []},
        )

        blocked = get_events_page(verdict="blocked")
        event = next(item for item in blocked["items"] if item["sessionId"] == session_id)
        self.assertEqual(event["verdict"], "blocked")
        self.assertEqual(event["toolTag"], "Bash")
        self.assertEqual(event["policy"]["ruleId"], "scoped-agent")
        self.assertIn("explicitly denied", event["policy"]["evidence"])

        detail = get_session_scoped_detail(self.workspace, session_id)
        self.assertEqual(detail["recent_events"][0]["verdict"], "blocked")
        self.assertEqual(detail["recent_events"][0]["policy"]["ruleId"], "scoped-agent")

    def test_scoped_rules_can_block_concrete_mcp_tool_tags(self):
        session_id = "scoped-mcp-session"
        save_scoped_rules(
            self.workspace,
            session_id,
            {
                "allowed_tools": ["Read"],
                "deny_tools": ["mcp__node_repl__js"],
                "allowed_paths": ["**"],
                "deny_network": False,
            },
        )
        save_session_snapshot(
            workspace=self.workspace,
            session_id=session_id,
            agent="codex",
            source="hook",
            repo_url=None,
            events=[
                {
                    "type": "tool_result",
                    "agent_event": "PostToolUse",
                    "ts": "2026-01-01T00:00:02Z",
                    "metadata": {"tool_name": "mcp__node_repl__js"},
                }
            ],
            analysis={"summary": {"riskScore": 0, "totalFindings": 0}, "findings": []},
        )

        blocked = get_events_page(verdict="blocked")
        event = next(item for item in blocked["items"] if item["sessionId"] == session_id)
        self.assertEqual(event["toolTag"], "mcp__node_repl__js")
        self.assertEqual(event["policy"]["ruleId"], "scoped-agent")
        self.assertIn("explicitly denied", event["policy"]["evidence"])

        detail = get_session_scoped_detail(self.workspace, session_id)
        self.assertEqual(detail["recent_events"][0]["verdict"], "blocked")
        self.assertEqual(detail["recent_events"][0]["toolTag"], "mcp__node_repl__js")

    def test_runtime_findings_are_persisted_for_dashboard(self):
        session_id = "runtime-finding-session"
        save_session_snapshot(
            workspace=self.workspace,
            session_id=session_id,
            agent="codex",
            source="hook",
            repo_url=None,
            events=[
                {
                    "type": "shell",
                    "agent_event": "PreToolUse",
                    "command": "prismor status",
                    "ts": "2026-01-01T00:00:03Z",
                    "metadata": {"tool_name": "Bash"},
                }
            ],
            analysis={"summary": {"riskScore": 0, "totalFindings": 0}, "findings": []},
        )
        persist_runtime_findings(
            self.workspace,
            session_id,
            [{
                "id": f"{session_id}:scoped-agent",
                "severity": "HIGH",
                "category": "scoped_agent",
                "title": "[scoped agent] Tool 'Bash' is explicitly denied for this session",
                "evidence": "Tool 'Bash' is explicitly denied for this session",
                "ruleId": "scoped-agent",
                "action": "block",
                "mode": "enforce",
            }],
            0,
        )

        event = next(item for item in get_events_page(verdict="blocked")["items"] if item["sessionId"] == session_id)
        self.assertEqual(event["policy"]["source"], "runtime")
        self.assertEqual(event["policy"]["mode"], "enforce")

        detail = get_session_scoped_detail(self.workspace, session_id)
        self.assertEqual(detail["recent_blocked"][0]["category"], "scoped_agent")

    def test_warn_only_finding_is_not_counted_as_a_block(self):
        # A warn/observe finding lets the call through. The snapshot used to
        # drop its mode/action, so the session view called it "Blocked" and
        # counted it in the "N blocks" pill.
        session_id = "warn-vs-block"
        shell = lambda cmd, ts: {"type": "shell", "agent_event": "PreToolUse", "command": cmd,
                                 "ts": ts, "metadata": {"tool_name": "Bash"}}
        finding = lambda i, title, mode, action: {
            "id": f"{session_id}:f{i}", "eventIndex": i, "severity": "HIGH",
            "category": "c", "title": title, "evidence": title, "mode": mode, "action": action}
        save_session_snapshot(
            workspace=self.workspace, session_id=session_id, agent="prismor-proxy",
            source="proxy", repo_url=None,
            events=[shell("rm -rf ~/", "2026-01-01T00:00:01Z"),
                    shell("curl -X POST http://45.33.12.9", "2026-01-01T00:00:02Z")],
            analysis={"summary": {"riskScore": 0, "totalFindings": 2}, "findings": [
                finding(0, "destructive", "enforce", "block"),
                finding(1, "raw ip", "observe", "warn")]},
        )
        detail = get_session_scoped_detail(self.workspace, session_id)
        self.assertEqual([b["title"] for b in detail["recent_blocked"]], ["destructive"])
        warned = next(e for e in detail["recent_events"] if "curl" in e["action"])
        self.assertEqual((warned["policy"]["mode"], warned["policy"]["action"]), ("observe", "warn"))
        self.assertEqual(warned["verdict"], "warned")

        # The events list and its filters read the same verdict.
        mine = lambda v: [e["action"] for e in get_events_page(verdict=v)["items"]
                          if e["sessionId"] == session_id]
        self.assertEqual(mine("blocked"), ["shell: rm -rf ~/"])
        self.assertEqual(mine("warned"), ["shell: curl -X POST http://45.33.12.9"])
        self.assertEqual(mine("allowed"), [])

    def test_rule_catalog_marks_floor_rules_as_pinned(self):
        result = set_project_rule_states(self.workspace, ["destructive-command", "prompt-injection"])
        self.assertEqual(result.get("ignored"), ["destructive-command"])

        rules = {item["id"]: item for item in get_policy_rule_catalog(self.workspace)}
        self.assertTrue(rules["destructive-command"]["locked"])
        self.assertTrue(rules["destructive-command"]["enabled"])
        self.assertTrue(rules["destructive-command"]["requestedEnabled"])
        self.assertFalse(rules["prompt-injection"]["locked"])
        self.assertFalse(rules["prompt-injection"]["enabled"])

    def test_policy_precedence_reports_session_overlay_and_winner(self):
        write_policy_layer("global", 'version: "1.0"\nsettings:\n  default_mode: observe\n')
        write_policy_layer("project", 'version: "1.0"\nsettings:\n  default_mode: enforce\n', self.workspace)

        with patch("prismor.runtime.store.get_enrollment", return_value={"org_id": "org_123", "device_id": "dev_123"}), \
             patch("prismor.runtime.store._enterprise_remote_cache", return_value='version: "1.0"\nsettings:\n  default_mode: enforce\n'):
            precedence = get_policy_precedence(
                self.workspace,
                {"allowed_tools": ["Read"], "deny_tools": ["Bash"], "deny_network": True},
            )

        self.assertEqual(precedence["winner"], "enterprise")
        self.assertEqual(precedence["chain"][0]["scope"], "session")
        self.assertTrue(precedence["chain"][0]["exists"])
        self.assertTrue(precedence["chain"][0]["winning"])
        self.assertEqual(next(item for item in precedence["chain"] if item["scope"] == "enterprise")["mode"], "enforce")


class TestSupplyChainEventIndex(unittest.TestCase):
    """write_supply_chain_event() inserted findings without event_index, so
    the matching event in get_events_page() could never resolve to a
    finding — those events fell back to "allowed" even when a package was
    actually blocked. Discovered while verifying #130's fix.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.workspace = Path(self._tmp.name)
        self._orig_prismor_home = os.environ.get("PRISMOR_HOME")
        os.environ["PRISMOR_HOME"] = str(self.workspace / ".prismor-home")
        patcher = patch("prismor.runtime.store.list_registered_workspaces", return_value=[self.workspace])
        patcher.start()
        self.addCleanup(patcher.stop)

        spec = PackageSpec(raw="lodash@4.17.19", name="lodash", source="registry", version="4.17.19")
        meta = PackageMetadata(
            name="lodash", ecosystem="npm", version="4.17.19", age_days=5185,
            maintainer_count=1, has_install_script=False, source="registry",
        )
        verdict = PackageVerdict(
            spec=spec, meta=meta, score=75, verdict="block",
            signals=[Signal(id="ioc_ghsa", points=30, description="Command Injection in lodash")],
        )
        write_supply_chain_event(
            workspace=self.workspace,
            session_id="supply-chain-test",
            ts="2026-01-01T00:00:00Z",
            ecosystem="npm",
            install_cmd="supplychain npm install lodash@4.17.19",
            verdicts=[verdict],
        )

    def tearDown(self):
        if self._orig_prismor_home is None:
            os.environ.pop("PRISMOR_HOME", None)
        else:
            os.environ["PRISMOR_HOME"] = self._orig_prismor_home
        self._tmp.cleanup()

    def test_blocked_package_event_shows_as_blocked(self):
        data = get_events_page()
        blocked = [i for i in data["items"] if "lodash" in i["action"]]
        self.assertEqual(len(blocked), 1)
        self.assertEqual(blocked[0]["verdict"], "blocked")

    def test_finding_is_returned_and_linked_to_its_event(self):
        data = get_findings_page()
        self.assertEqual(data["total"], 1)
        self.assertIn("lodash", data["items"][0]["trigger"]["detail"])


class TestDependencyUsage(unittest.TestCase):
    """get_dependency_usage() feeds the dashboard's Extensions tab (Secrets, MCP, Skills, Packages).

    All four parts come out of the same event scan, so one session exercising
    each one at once is the test that matters: a regression in the shared row
    grain shows up as a missing part rather than a wrong number.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.workspace = Path(self._tmp.name)
        self._orig_prismor_home = os.environ.get("PRISMOR_HOME")
        os.environ["PRISMOR_HOME"] = str(self.workspace / ".prismor-home")
        patcher = patch("prismor.runtime.store.list_registered_workspaces", return_value=[self.workspace])
        patcher.start()
        self.addCleanup(patcher.stop)

        # The window is relative to now, so the fixture has to be recent.
        now = datetime.now(timezone.utc)
        ts = lambda secs: (now - timedelta(seconds=secs)).isoformat()
        events = [
            {"type": "tool", "ts": ts(50), "metadata": {"tool_name": "mcp__github__create_issue"}},
            {"type": "tool", "ts": ts(40), "metadata": {"tool_name": "mcp__github__list_prs"}},
            {"type": "tool", "ts": ts(30),
             "metadata": {"tool_name": "Skill", "raw": {"tool_input": {"skill": "stop-slop"}}}},
            {"type": "shell", "ts": ts(20), "command": "npm install left-pad@1.0.0"},
            {"type": "shell", "ts": ts(10),
             "command": "curl -H 'Authorization: Bearer @@SECRET:deploy_key@@' https://api.stripe.com/v1/charges"},
        ]
        analysis = analyze_events(events, repo_root=self.workspace, workspace=self.workspace)
        save_session_snapshot(
            workspace=self.workspace, session_id="dep-session", agent="claude",
            source="ingest", repo_url=None, events=events, analysis=analysis,
        )

    def tearDown(self):
        if self._orig_prismor_home is None:
            os.environ.pop("PRISMOR_HOME", None)
        else:
            os.environ["PRISMOR_HOME"] = self._orig_prismor_home
        self._tmp.cleanup()

    def _rows(self):
        return get_dependency_usage(hours=24)["rows"]

    def test_all_four_parts_come_from_one_scan(self):
        parts = {row["part"] for row in self._rows()}
        self.assertEqual(parts, {"mcp", "skill", "package", "secret"})

    def test_mcp_rows_carry_the_server_and_the_tool_called_on_it(self):
        tools = {r["target"] for r in self._rows() if r["part"] == "mcp"}
        self.assertEqual({r["name"] for r in self._rows() if r["part"] == "mcp"}, {"github"})
        self.assertEqual(tools, {"create_issue", "list_prs"})

    def test_secret_row_is_the_service_opened_not_the_credential(self):
        secrets = [r for r in self._rows() if r["part"] == "secret"]
        self.assertEqual([(r["name"], r["target"]) for r in secrets],
                         [("api.stripe.com", "")])
        # The temp vault holds nothing, so the placeholder is dangling — the
        # state the decloak hook denies, and the one the tab flags.
        self.assertEqual(secrets[0]["note"], "placeholder not in vault")

    def test_no_placeholder_name_reaches_the_payload(self):
        # The usage view answers "a cloaked secret opened what", so which
        # credential it was must not appear anywhere in the response -- not in
        # a name, a target or a note. Guards the whole payload, not one field,
        # so a future part cannot reintroduce it.
        self.assertNotIn("deploy_key", json.dumps(get_dependency_usage(hours=24)))

    def test_package_row_uses_the_supply_chain_install_parser(self):
        packages = [r for r in self._rows() if r["part"] == "package"]
        self.assertEqual([(r["name"], r["target"], r["note"]) for r in packages],
                         [("left-pad", "npm", "1.0.0")])

    def test_rows_are_grouped_per_session_so_the_dashboard_can_regroup_them(self):
        for row in self._rows():
            self.assertEqual(row["session"], "dep-session")
            self.assertEqual(row["agent"], "claude")
            self.assertEqual(row["workspace"], canonical_workspace_path(self.workspace))

    def test_repeated_use_of_one_dependency_counts_calls_not_rows(self):
        # Two calls on the same MCP tool collapse into one row with calls=2;
        # the tab's totals are sums of `calls`, not of row counts.
        events = [{"type": "tool", "ts": datetime.now(timezone.utc).isoformat(),
                   "metadata": {"tool_name": "mcp__github__create_issue"}}] * 2
        analysis = analyze_events(events, repo_root=self.workspace, workspace=self.workspace)
        save_session_snapshot(workspace=self.workspace, session_id="repeat-session", agent="codex",
                              source="ingest", repo_url=None, events=events, analysis=analysis)
        repeat = [r for r in self._rows() if r["session"] == "repeat-session"]
        self.assertEqual(len(repeat), 1)
        self.assertEqual(repeat[0]["calls"], 2)
        self.assertEqual(repeat[0]["agent"], "codex")

    def test_window_excludes_anything_older_than_the_window(self):
        self.assertEqual(get_dependency_usage(hours=0)["rows"], [])


class TestNetworkCalls(unittest.TestCase):
    """get_network_calls() backs the overview's Top network calls table."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.workspace = Path(self._tmp.name)
        self._orig_prismor_home = os.environ.get("PRISMOR_HOME")
        os.environ["PRISMOR_HOME"] = str(self.workspace / ".prismor-home")
        patcher = patch("prismor.runtime.store.list_registered_workspaces", return_value=[self.workspace])
        patcher.start()
        self.addCleanup(patcher.stop)

        now = datetime.now(timezone.utc)
        ts = lambda secs: (now - timedelta(seconds=secs)).isoformat()
        # index 0 shell->api.example.com, 1 url->files.example.net,
        # 2 shell->localhost, 3 shell->blocked.example.org
        self.events = [
            {"type": "shell", "ts": ts(50), "command": "curl https://api.example.com/v1/ping"},
            {"type": "network", "ts": ts(40), "url": "https://files.example.net/pkg.tgz"},
            {"type": "shell", "ts": ts(30), "command": "curl http://localhost:8080/health"},
            {"type": "shell", "ts": ts(20), "command": "curl https://blocked.example.org/x"},
        ]
        analysis = analyze_events(self.events, repo_root=self.workspace, workspace=self.workspace)
        save_session_snapshot(
            workspace=self.workspace, session_id="net-session", agent="claude",
            source="ingest", repo_url=None, events=self.events, analysis=analysis,
        )

    def tearDown(self):
        if self._orig_prismor_home is None:
            os.environ.pop("PRISMOR_HOME", None)
        else:
            os.environ["PRISMOR_HOME"] = self._orig_prismor_home
        self._tmp.cleanup()

    def _by_host(self, hours=24):
        return {h["host"]: h for h in get_network_calls(hours=hours)["hosts"]}

    def _flag(self, event_index, category, action="block", mode="enforce"):
        persist_runtime_findings(
            workspace=self.workspace, session_id="net-session", event_index=event_index,
            findings=[{"id": f"net-session:{category}-{event_index}", "severity": "HIGH",
                       "category": category, "title": "t", "evidence": "e",
                       "action": action, "mode": mode}],
        )

    def test_destinations_come_from_both_shell_commands_and_url_events(self):
        hosts = self._by_host()
        self.assertIn("api.example.com", hosts)      # curl in a shell command
        self.assertIn("files.example.net", hosts)    # the url field of a network event

    def test_loopback_is_marked_private_so_the_table_can_lead_with_egress(self):
        hosts = self._by_host()
        self.assertTrue(hosts["localhost"]["private"])
        self.assertFalse(hosts["api.example.com"]["private"])

    def test_an_enforced_network_finding_counts_the_call_as_blocked(self):
        self._flag(3, "network_isolation", action="block", mode="enforce")
        host = self._by_host()["blocked.example.org"]
        self.assertEqual((host["blocked"], host["warned"]), (1, 0))

    def test_a_warn_only_network_finding_counts_as_warned_not_blocked(self):
        self._flag(3, "network_isolation", action="warn", mode="observe")
        host = self._by_host()["blocked.example.org"]
        self.assertEqual((host["blocked"], host["warned"]), (0, 1))

    def test_a_finding_about_something_else_is_not_a_blocked_network_call(self):
        # The event carried a finding, but about a secret in the command, not
        # about where it was going. Counting it would overstate blocked egress.
        self._flag(0, "secret_exfiltration", action="block", mode="enforce")
        host = self._by_host()["api.example.com"]
        self.assertEqual((host["calls"], host["blocked"], host["warned"]), (1, 0, 0))

    def test_rows_carry_the_agent_and_session_that_made_the_call(self):
        host = self._by_host()["api.example.com"]
        self.assertEqual(host["agents"], ["claude"])
        self.assertEqual(host["sessions"], 1)

    def test_counts_split_external_from_local_hosts(self):
        data = get_network_calls(hours=24)
        self.assertEqual(data["hostCount"], 4)
        self.assertEqual(data["externalCount"], 3)   # localhost is the fourth

    def test_finding_join_survives_a_session_that_began_before_the_cutoff(self):
        # findings.event_index is a position in the WHOLE session. Numbering the
        # events inside the time window instead restarts at 0, which joined a
        # session's findings onto the wrong events -- dropping the block here
        # entirely -- whenever the session started before the cutoff.
        old = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
        recent = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
        events = [
            {"type": "shell", "ts": old, "command": "curl https://old.example.com/a"},
            {"type": "shell", "ts": old, "command": "curl https://old.example.com/b"},
            {"type": "shell", "ts": old, "command": "curl https://old.example.com/c"},
            {"type": "shell", "ts": recent, "command": "curl https://recent.example.com/x"},
        ]
        analysis = analyze_events(events, repo_root=self.workspace, workspace=self.workspace)
        save_session_snapshot(workspace=self.workspace, session_id="spanning", agent="claude",
                              source="ingest", repo_url=None, events=events, analysis=analysis)
        persist_runtime_findings(
            workspace=self.workspace, session_id="spanning", event_index=3,
            findings=[{"id": "spanning:net-3", "severity": "HIGH", "category": "network_isolation",
                       "title": "t", "evidence": "e", "action": "block", "mode": "enforce"}])
        # A one-day window sees only the last event, whose index is still 3.
        host = self._by_host(hours=24)["recent.example.com"]
        self.assertEqual((host["calls"], host["blocked"]), (1, 1))

    def test_window_excludes_anything_older_than_the_window(self):
        self.assertEqual(get_network_calls(hours=0)["hosts"], [])

if __name__ == "__main__":
    unittest.main()
