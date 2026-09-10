"""Custom MCP guardrail rules: block / require-human-approval on MCP tool calls.

Covers the `mcp` event-type alias and the MCP-identity match fields
(tool_name / mcp_server / mcp_tool / outbound_payload) that let a customer write
their own policy rule targeting a specific MCP server or tool — the core
"custom guardrails for MCPs" feature.

Two levels:
  * Unit — PolicyEngine.evaluate + should_block, on synthetic MCP-shaped events
    (the shape _classify_mcp_event produces for local stdio and remote servers).
  * End-to-end — a custom step_up rule drives the Claude hook dispatcher to an
    inline "ask" (permissionDecision), and a custom block rule exits 2.

Run:  python3 tests/test_mcp_guardrails.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO))

from prismor.runtime.policy_engine import PolicyEngine  # noqa: E402
from prismor.runtime.hooks import should_block  # noqa: E402
from prismor.runtime.runtime import evaluate_tool_call  # noqa: E402


def _engine(policy_yaml: str) -> PolicyEngine:
    d = Path(tempfile.mkdtemp(prefix="prismor-mcp-guard-"))
    pp = d / "policy.yaml"
    pp.write_text(policy_yaml)
    return PolicyEngine(workspace=d, policy_path=pp)


def _stdio_mcp_event(tool_name: str, args: dict, agent_event: str = "PreToolUse") -> dict:
    """Shape a local stdio MCP call the way _classify_mcp_event does.

    Pre-call: ``response`` carries the serialized arguments. Post-call
    (agent_event="PostToolUse"): ``response`` carries the tool's output.
    """
    return {
        "type": "tool_result",
        "agent_event": agent_event,
        "response": json.dumps(args) if isinstance(args, dict) else str(args),
        "mcp_server": tool_name.split("__")[1],
        "mcp_tool": tool_name.split("__", 2)[-1],
        "metadata": {"tool_name": tool_name},
    }


def _remote_mcp_event(tool_name: str, url: str, args: dict) -> dict:
    """Shape a remote MCP pre-call: classified as network + outbound_payload."""
    return {
        "type": "network",
        "agent_event": "PreToolUse",
        "url": url,
        "outbound_payload": json.dumps(args),
        "mcp_server": tool_name.split("__")[1],
        "mcp_tool": tool_name.split("__", 2)[-1],
        "metadata": {"tool_name": tool_name},
    }


# ── Unit: mcp alias + match fields ─────────────────────────────────────────

_APPROVE_TOOL = """
version: "1.0"
settings:
  default_mode: enforce
rules:
  - id: github-mcp-writes-need-approval
    severity: HIGH
    category: mcp_guardrail
    title: GitHub MCP writes require human approval
    event_types: [mcp]
    action: step_up
    patterns:
      - "^mcp__github__(create|merge|delete)_"
"""

_BLOCK_SERVER = """
version: "1.0"
settings:
  default_mode: enforce
rules:
  - id: block-prod-db-mcp
    severity: CRITICAL
    category: mcp_guardrail
    title: Prod database MCP is blocked
    event_types: [mcp]
    fields: [mcp_server]
    action: block
    patterns:
      - "^prod-db$"
"""

_ARG_GUARD = """
version: "1.0"
settings:
  default_mode: enforce
rules:
  - id: mcp-arg-secret-guard
    severity: HIGH
    category: mcp_guardrail
    title: MCP call arguments carry a forbidden token
    event_types: [mcp]
    fields: [outbound_payload]
    action: block
    patterns:
      - "FORBIDDEN_ARG_TOKEN"
"""


class McpAliasMatching(unittest.TestCase):
    def _findings(self, eng, event):
        return eng.evaluate(event, index=0, session_id="s1")

    def test_default_field_matches_tool_tag(self):
        eng = _engine(_APPROVE_TOOL)
        f = self._findings(eng, _stdio_mcp_event("mcp__github__create_pr", {"title": "x"}))
        self.assertTrue(any(x["ruleId"] == "github-mcp-writes-need-approval" for x in f))

    def test_readonly_tool_does_not_trip_write_rule(self):
        eng = _engine(_APPROVE_TOOL)
        f = self._findings(eng, _stdio_mcp_event("mcp__github__get_pr", {"n": 1}))
        self.assertEqual(f, [])

    def test_step_up_action_carried_and_blocks(self):
        eng = _engine(_APPROVE_TOOL)
        ev = _stdio_mcp_event("mcp__github__merge_pr", {"n": 7})
        f = self._findings(eng, ev)
        self.assertTrue(f)
        self.assertEqual(f[0]["action"], "step_up")
        self.assertEqual(f[0]["mode"], "enforce")
        blk = should_block(f, ev)
        self.assertIsNotNone(blk)
        self.assertEqual(str(blk.get("action")), "step_up")

    def test_mcp_server_field_matches_remote(self):
        eng = _engine(_BLOCK_SERVER)
        ev = _remote_mcp_event("mcp__prod-db__query", "https://db.example/mcp", {"sql": "select 1"})
        f = self._findings(eng, ev)
        self.assertTrue(any(x["ruleId"] == "block-prod-db-mcp" for x in f))
        self.assertIsNotNone(should_block(f, ev))

    def test_outbound_payload_field_matches_remote_args(self):
        eng = _engine(_ARG_GUARD)
        ev = _remote_mcp_event("mcp__x__do", "https://x.example/mcp", {"v": "FORBIDDEN_ARG_TOKEN"})
        f = self._findings(eng, ev)
        self.assertTrue(any(x["ruleId"] == "mcp-arg-secret-guard" for x in f))

    def test_alias_does_not_fire_on_non_mcp_event(self):
        # A plain shell event must never trip an mcp-alias rule, even if its text
        # happens to contain the tool tag.
        eng = _engine(_APPROVE_TOOL)
        ev = {"type": "shell", "agent_event": "PreToolUse",
              "command": "echo mcp__github__create_pr", "metadata": {"tool_name": "Bash"}}
        self.assertEqual(self._findings(eng, ev), [])


# ── Unit: transport-agnostic mcp_args field ────────────────────────────────

_MCP_ARGS_GUARD = """
version: "1.0"
settings:
  default_mode: enforce
rules:
  - id: mcp-args-guard
    severity: HIGH
    category: mcp_guardrail
    title: MCP call arguments carry a forbidden token
    event_types: [mcp]
    fields: [mcp_args]
    action: block
    patterns:
      - "FORBIDDEN_ARG_TOKEN"
"""


class McpArgsField(unittest.TestCase):
    """`mcp_args` matches call arguments on BOTH transports, and never output."""

    def setUp(self):
        self.eng = _engine(_MCP_ARGS_GUARD)

    def test_matches_stdio_pre_call_args(self):
        ev = _stdio_mcp_event("mcp__x__do", {"v": "FORBIDDEN_ARG_TOKEN"})
        f = self.eng.evaluate(ev, index=0, session_id="s1")
        self.assertTrue(any(x["ruleId"] == "mcp-args-guard" for x in f))

    def test_matches_remote_pre_call_args(self):
        ev = _remote_mcp_event("mcp__x__do", "https://x.example/mcp", {"v": "FORBIDDEN_ARG_TOKEN"})
        f = self.eng.evaluate(ev, index=0, session_id="s1")
        self.assertTrue(any(x["ruleId"] == "mcp-args-guard" for x in f))

    def test_does_not_match_stdio_post_call_output(self):
        # On PostToolUse, `response` is the tool's OUTPUT — an args guardrail
        # must not fire on it (that would silently also scan tool output).
        ev = _stdio_mcp_event("mcp__x__do", "output: FORBIDDEN_ARG_TOKEN",
                              agent_event="PostToolUse")
        f = self.eng.evaluate(ev, index=0, session_id="s1")
        self.assertEqual([x for x in f if x["ruleId"] == "mcp-args-guard"], [])


# ── Default policy: MCP argument egress destinations ───────────────────────

# (label, arguments) pairs that all name the same forbidden destination in a
# destination-shaped argument. Every one must block on both transports.
_METADATA_ARGS = [
    ("aws imds path", {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}),
    ("no trailing slash", {"url": "http://169.254.169.254"}),
    ("no scheme", {"url": "169.254.169.254/latest/meta-data/"}),
    ("google metadata", {"url": "http://metadata.google.internal/computeMetadata/v1/"}),
    ("google bare host", {"url": "http://metadata.google.internal"}),
    ("ecs credential relay", {"url": "http://169.254.170.2/v2/credentials/"}),
    ("userinfo prefix", {"url": "http://example.com@169.254.169.254/latest/"}),
    ("ipv6-mapped in brackets", {"url": "http://[::ffff:169.254.169.254]/latest/"}),
    ("hex-encoded host", {"url": "http://0xa9fea9fe/latest/"}),
    ("decimal-encoded host", {"url": "http://2852039166/latest/"}),
    ("uppercase scheme", {"url": "HTTP://169.254.169.254/latest/"}),
    ("argument named base_url", {"base_url": "http://169.254.169.254/latest/"}),
    ("argument named target", {"target": "http://169.254.169.254/latest/"}),
    ("host and path split apart", {"host": "169.254.169.254", "path": "/latest/meta-data/"}),
    ("nested request object", {"request": {"url": "http://169.254.169.254/latest/"}}),
]

_BENIGN_ARGS = [
    ("plain https destination", {"url": "https://example.com"}),
    ("api destination", {"url": "https://api.github.com/repos/o/r"}),
    ("prose mentioning imds", {"message": "The server returned 169.254.169.254"}),
    ("question about imds", {"query": "what is 169.254.169.254 used for"}),
    ("imds inside a longer url path", {"url": "https://docs.example.com/169.254.169.254"}),
]


class McpArgumentEgress(unittest.TestCase):
    """An allowed MCP server can still be asked to fetch a denied destination.

    The destination lives in the call arguments, not in the server `url`, and
    it has to be screened on both transports: a remote server serializes its
    arguments into ``outbound_payload``, a local stdio server into ``response``.
    """

    def setUp(self):
        self.ws = Path(tempfile.mkdtemp(prefix="prismor-mcp-egress-ws-"))

    def _decide(self, event: dict):
        return evaluate_tool_call(
            event=event,
            workspace=self.ws,
            agent="claude",
            mode="enforce",
            session_id="mcp-argument-egress",
            persist=False,
            register_agent=False,
        )

    def _remote(self, args: dict):
        return self._decide(_remote_mcp_event(
            "mcp__db__fetch", "https://db.example.com/mcp", args))

    def _stdio(self, args: dict):
        return self._decide(_stdio_mcp_event("mcp__db__fetch", args))

    def test_metadata_destination_blocks_over_remote_transport(self):
        for label, args in _METADATA_ARGS:
            with self.subTest(label):
                decision = self._remote(args)
                self.assertFalse(decision.allow)
                self.assertEqual(decision.rule_id, "mcp-arg-metadata-endpoint")

    def test_metadata_destination_blocks_over_stdio_transport(self):
        # A local stdio MCP server with a fetch tool reaches IMDS just as well
        # as a remote one; the rule must not depend on the transport.
        for label, args in _METADATA_ARGS:
            with self.subTest(label):
                decision = self._stdio(args)
                self.assertFalse(decision.allow)
                self.assertEqual(decision.rule_id, "mcp-arg-metadata-endpoint")

    def test_benign_arguments_are_allowed_on_both_transports(self):
        for label, args in _BENIGN_ARGS:
            with self.subTest(label):
                self.assertTrue(self._remote(args).allow)
                self.assertTrue(self._stdio(args).allow)

    def test_does_not_fire_on_stdio_tool_output(self):
        # Post-call `response` is the tool's OUTPUT. An argument guardrail that
        # matched it would silently start screening tool results too.
        event = _stdio_mcp_event(
            "mcp__db__fetch",
            {"url": "http://169.254.169.254/latest/meta-data/"},
            agent_event="PostToolUse")
        self.assertTrue(self._decide(event).allow)


# ── End-to-end: Claude hook dispatcher ─────────────────────────────────────

_E2E_POLICY = """
version: "1.0"
settings:
  default_mode: enforce
rules:
  - id: approve-github-mcp-writes
    severity: HIGH
    category: mcp_guardrail
    title: Approve GitHub MCP writes
    event_types: [mcp]
    action: step_up
    patterns:
      - "^mcp__github__create_"
  - id: block-prod-db-mcp
    severity: CRITICAL
    category: mcp_guardrail
    title: Prod DB MCP blocked
    event_types: [mcp]
    fields: [mcp_server]
    action: block
    patterns:
      - "^prod-db$"
"""


class ClaudeMcpGuardrailE2E(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp(prefix="prismor-mcp-guard-home-"))
        self.ws = Path(tempfile.mkdtemp(prefix="prismor-mcp-guard-ws-"))
        (self.ws / ".prismor").mkdir(parents=True, exist_ok=True)
        (self.ws / ".prismor" / "policy.yaml").write_text(_E2E_POLICY)

    def _dispatch(self, tool_name: str, tool_input: dict):
        payload = {
            "hook_event_name": "PreToolUse",
            "tool_name": tool_name,
            "tool_input": tool_input,
            "session_id": "mcp-guard-session",
        }
        env = dict(os.environ)
        env["PRISMOR_HOME"] = str(self.home)
        env["PRISMOR_SECRETS_DIR"] = str(self.home / "secrets")
        env["PYTHONPATH"] = str(_REPO)
        return subprocess.run(
            [sys.executable, "-m", "prismor.runtime.immunity_cli", "hook-dispatch",
             "--agent", "claude", "--workspace", str(self.ws), "--mode", "enforce"],
            input=json.dumps(payload), capture_output=True, text=True, env=env,
        )

    def test_step_up_emits_ask(self):
        proc = self._dispatch("mcp__github__create_pr", {"title": "add feature"})
        self.assertEqual(proc.returncode, 0, f"stderr={proc.stderr!r}")
        out = json.loads(proc.stdout)
        self.assertEqual(
            out["hookSpecificOutput"]["permissionDecision"], "ask",
            f"stdout={proc.stdout!r}",
        )

    def test_block_server_exits_2(self):
        proc = self._dispatch("mcp__prod-db__query", {"sql": "delete from users"})
        self.assertEqual(proc.returncode, 2, f"stdout={proc.stdout!r} stderr={proc.stderr!r}")

    def test_clean_mcp_call_passes(self):
        proc = self._dispatch("mcp__github__get_pr", {"n": 1})
        self.assertEqual(proc.returncode, 0, proc.stderr)


# ── End-to-end: REMOTE MCP server (.mcp.json → network classification) ─────

_REMOTE_ARGS_POLICY = """
version: "1.0"
settings:
  default_mode: enforce
rules:
  - id: remote-mcp-args-guard
    severity: HIGH
    category: mcp_guardrail
    title: Remote MCP arguments carry a forbidden token
    event_types: [mcp]
    fields: [mcp_args]
    action: block
    patterns:
      - "FORBIDDEN_ARG_TOKEN"
"""


class RemoteMcpServerE2E(unittest.TestCase):
    """Proves the full remote pipeline: the workspace .mcp.json marks the server
    remote, _classify_mcp_event routes the pre-call as a `network` event with
    the args in outbound_payload, and an `mcp` rule on mcp_args blocks it."""

    def setUp(self):
        self.home = Path(tempfile.mkdtemp(prefix="prismor-mcp-remote-home-"))
        self.ws = Path(tempfile.mkdtemp(prefix="prismor-mcp-remote-ws-"))
        (self.ws / ".prismor").mkdir(parents=True, exist_ok=True)
        (self.ws / ".prismor" / "policy.yaml").write_text(_REMOTE_ARGS_POLICY)
        (self.ws / ".mcp.json").write_text(json.dumps({
            "mcpServers": {"prod-db": {"url": "https://db.example/mcp"}}
        }))

    def _dispatch(self, tool_name: str, tool_input: dict):
        payload = {
            "hook_event_name": "PreToolUse",
            "tool_name": tool_name,
            "tool_input": tool_input,
            "session_id": "mcp-remote-session",
        }
        env = dict(os.environ)
        env["PRISMOR_HOME"] = str(self.home)
        env["PRISMOR_SECRETS_DIR"] = str(self.home / "secrets")
        env["PYTHONPATH"] = str(_REPO)
        return subprocess.run(
            [sys.executable, "-m", "prismor.runtime.immunity_cli", "hook-dispatch",
             "--agent", "claude", "--workspace", str(self.ws), "--mode", "enforce"],
            input=json.dumps(payload), capture_output=True, text=True, env=env,
        )

    def test_remote_args_guard_blocks(self):
        proc = self._dispatch("mcp__prod-db__query", {"sql": "FORBIDDEN_ARG_TOKEN"})
        self.assertEqual(proc.returncode, 2, f"stdout={proc.stdout!r} stderr={proc.stderr!r}")
        self.assertIn("forbidden token", proc.stderr.lower())

    def test_remote_clean_args_pass(self):
        proc = self._dispatch("mcp__prod-db__query", {"sql": "select 1"})
        self.assertEqual(proc.returncode, 0, f"stdout={proc.stdout!r} stderr={proc.stderr!r}")


# ── Copilot: MCP classification + inline approval surface ──────────────────


class CopilotMcpGuardrails(unittest.TestCase):
    """Copilot supports the inline 'ask' surface, so its MCP calls must be
    classified like the other agents' — otherwise `mcp` rules never fire."""

    def test_normalizer_classifies_mcp_tool(self):
        from prismor.runtime.hooks import _normalize_copilot
        ws = Path(tempfile.mkdtemp(prefix="prismor-copilot-ws-"))
        ev = _normalize_copilot(
            {"hookEventName": "PreToolUse",
             "toolName": "mcp__github__create_pr",
             "toolArgs": json.dumps({"title": "x"})},
            "s1", ws,
        )
        self.assertEqual(ev.get("mcp_server"), "github")
        self.assertEqual(ev.get("mcp_tool"), "create_pr")
        self.assertIn("title", ev.get("response", ""))

    def test_non_mcp_tool_unaffected(self):
        from prismor.runtime.hooks import _normalize_copilot
        ws = Path(tempfile.mkdtemp(prefix="prismor-copilot-ws-"))
        ev = _normalize_copilot(
            {"hookEventName": "PreToolUse", "toolName": "SomethingElse",
             "toolArgs": "{}"},
            "s1", ws,
        )
        self.assertEqual(ev.get("type"), "tool_result")
        self.assertNotIn("mcp_server", ev)


class CopilotMcpGuardrailE2E(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp(prefix="prismor-copilot-home-"))
        self.ws = Path(tempfile.mkdtemp(prefix="prismor-copilot-e2e-ws-"))
        (self.ws / ".prismor").mkdir(parents=True, exist_ok=True)
        (self.ws / ".prismor" / "policy.yaml").write_text(_E2E_POLICY)

    def _dispatch(self, tool_name: str, tool_args: dict):
        payload = {
            "hookEventName": "PreToolUse",
            "toolName": tool_name,
            "toolArgs": json.dumps(tool_args),
            "session_id": "copilot-mcp-session",
        }
        env = dict(os.environ)
        env["PRISMOR_HOME"] = str(self.home)
        env["PRISMOR_SECRETS_DIR"] = str(self.home / "secrets")
        env["PYTHONPATH"] = str(_REPO)
        return subprocess.run(
            [sys.executable, "-m", "prismor.runtime.immunity_cli", "hook-dispatch",
             "--agent", "copilot", "--workspace", str(self.ws), "--mode", "enforce"],
            input=json.dumps(payload), capture_output=True, text=True, env=env,
        )

    def test_step_up_emits_ask(self):
        proc = self._dispatch("mcp__github__create_pr", {"title": "add feature"})
        self.assertEqual(proc.returncode, 0, f"stderr={proc.stderr!r}")
        out = json.loads(proc.stdout)
        self.assertEqual(out["permissionDecision"], "ask", f"stdout={proc.stdout!r}")

    def test_block_emits_deny(self):
        proc = self._dispatch("mcp__prod-db__query", {"sql": "drop table users"})
        out = json.loads(proc.stdout)
        self.assertEqual(out["permissionDecision"], "deny", f"stdout={proc.stdout!r}")

    def test_clean_mcp_call_passes(self):
        proc = self._dispatch("mcp__github__get_pr", {"n": 1})
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotIn("permissionDecision", proc.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
