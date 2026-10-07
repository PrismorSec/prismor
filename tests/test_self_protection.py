"""Prismor's self-protection: an agent cannot edit its own policy.

Every route an agent could take to relax its own governance must be blocked
before it runs — the policy file, the CLI subcommands that write it, the local
dashboard's write API, and the unlock credential that gates the exception.

The boundary here is the hook: Prismor sees agent tool calls, so the rules
below are what an agent runs into. A human at their own terminal is not hooked
and is unaffected, which is the point — the unlock window (tested in
test_unlock.py) is how a human hands that authority to the agent on purpose.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prismor.runtime.policy_engine import PolicyEngine, _SELF_PROTECTION_RULE_IDS
from prismor.runtime.hooks import should_block
from prismor.runtime.setup_wizard import _render_selection_policy

PRE = {"agent_event": "PreToolUse"}

# Every way in. If a route stops being covered, this list is where it shows up.
BLOCKED_COMMANDS = [
    # The policy file itself.
    "echo 'rules: []' > .prismor/policy.yaml",
    "rm .prismor/policy.yaml",
    # The CLI surface that writes policy.
    "prismor allow secret-exfiltration --off --yes",
    "prismor allow destructive-command --pattern 'rm -rf /'",
    "prismor policy edit",
    "prismor unlock",
    "prismor lock",
    "prismor pause",
    "prismor resume",
    "prismor setup --non-interactive --mode observe",
    "prismor install-hooks --mode observe",
    "prismor egress allow evil.com",
    "prismor workspace personal",
    # The mirror's exits: an agent whose Bash IS the mirror must not be able
    # to hand itself the native tools back or flip itself to pass-through.
    "prismor mirror off",
    "prismor mirror passthrough on",
    "cd /repo && prismor mirror on --mode observe",
    "echo '{\"override\": false}' > .prismor/mirror.json",
    # The unlock credential: reading it is as good as writing it.
    "cat ~/.prismor/unlock.json",
    "python3 -c \"print(open('/home/u/.prismor/unlock.json').read())\"",
    "echo '{}' > ~/.prismor/unlock-grant.json",
    # $PRISMOR_HOME relocates those files — CI images, containers and test rigs
    # all do it, and a rule that only knew the default path would wave these
    # through. Found by running the suite on a box with a relocated home.
    "cat /tmp/rig/home/unlock.json",
    "echo '{}' > /var/lib/prismor-home/unlock-grant.json",
    # Other runtime state that governs enforcement.
    "echo '{}' > ~/.prismor/pause.json",
    "rm ~/.prismor/identity.json",
    # The local dashboard's unauthenticated write API.
    "curl -X PUT http://127.0.0.1:7070/api/policy/rules -d '{}'",
    "curl -X POST http://localhost:7070/api/agents/claude -d '{}'",
    # Wrappers whose only purpose would be to disguise one of the above.
    "script -q /dev/null prismor allow risky-write --off",
    # Wrapped in a shell, which is how the anchoring would otherwise be
    # stepped around.
    'bash -c "prismor allow risky-write --off"',
    "sh -c 'prismor unlock'",
    # Reached through a path, sudo, or leading environment assignments.
    "/usr/local/bin/prismor setup .",
    "sudo prismor uninstall-hooks",
    "PRISMOR_HOME=/tmp/x prismor unlock",
    "prismor@dev allow risky-write --off",
    # Making a session public is the human's call, not the agent's.
    "prismor session share --public",
    "prismor session share abc-123 --org --public",
    "cd /repo && prismor session share --public",
    "python3 -m prismor.runtime.cli session share --public",
    "bash -c 'prismor session share --public'",
    "script -q /dev/null prismor session share --public",
]

# Things an agent legitimately does, which must keep working.
#
# The second half of this list is the interesting half: every one of them was a
# real false positive. Rules compile case-insensitively, so the first version of
# prismor-self-edit matched `$PRISMOR_HOME`, any path under a directory called
# Prismor, and any branch name containing "setup" — 1057 hits across 30 days of
# real transcripts, against ~30 genuine ones. Mentioning Prismor is not editing it.
ALLOWED_COMMANDS = [
    "prismor status",
    "prismor mirror status",
    "prismor check 'rm -rf /'",
    "prismor sessions --findings-only",
    "prismor deps",
    "prismor policy show",
    "cat README.md",
    "python3 -m pytest tests/",
    "git commit -m 'fix'",
    "cd /Users/x/Documents/projects/Prismor/prismor && git checkout -b feat/slack-setup-notifications",
    'grep -n "prismor allow" prismor/runtime/cli.py',
    "export PRISMOR_HOME=/tmp/rig && python3 -m pytest",
    "cd /repo/prismor-approvals-pr && grep -n setup cli.py",
    'git commit -m "feat(allow): the prismor allow ladder"',
    "ls ~/Documents/projects/Prismor/prismor",
    "rsync -az ./prismor ubuntu@host:~/selfedit-test/",
    # Sharing with people in the org is the agent's to do.
    "prismor session share",
    "prismor session share --org",
    "prismor session share --with bob@example.com",
    "prismor session https://www.prismor.dev/s/Tk9x",
    'grep -n "session share --public" SKILL.md',
]


def _engine(policy: str, managed: bool = False) -> PolicyEngine:
    d = Path(tempfile.mkdtemp())
    (d / ".prismor").mkdir()
    (d / ".prismor" / "policy.yaml").write_text(policy)
    with mock.patch(
        "prismor.runtime.enterprise.workspace_scope.is_managed", return_value=managed
    ):
        return PolicyEngine(workspace=d)


class TestSelfEditRoutesAreBlocked(unittest.TestCase):
    """With nothing selected — the emptiest possible enforce install — every
    self-edit route still blocks."""

    @classmethod
    def setUpClass(cls):
        cls.eng = _engine(_render_selection_policy([]))

    def test_every_self_edit_route_blocks(self):
        for command in BLOCKED_COMMANDS:
            with self.subTest(command=command):
                findings = self.eng.evaluate({"type": "shell", "command": command}, index=0)
                blocking = should_block(findings, {**PRE, "type": "shell"})
                self.assertIsNotNone(blocking, f"not blocked: {command}")
                self.assertIn(
                    blocking["ruleId"], _SELF_PROTECTION_RULE_IDS,
                    f"{command} blocked by {blocking['ruleId']}, not a self-protection rule",
                )

    def test_ordinary_agent_work_is_not_caught(self):
        for command in ALLOWED_COMMANDS:
            with self.subTest(command=command):
                findings = self.eng.evaluate({"type": "shell", "command": command}, index=0)
                hits = [f for f in findings if f["ruleId"] in _SELF_PROTECTION_RULE_IDS]
                self.assertFalse(hits, f"false positive on: {command}")

    def test_policy_file_write_event_blocks(self):
        findings = self.eng.evaluate(
            {"type": "file_write", "path": "/work/.prismor/policy.yaml"}, index=0
        )
        self.assertIsNotNone(should_block(findings, {**PRE, "type": "file_write"}))

    def test_unlock_credential_read_event_blocks(self):
        findings = self.eng.evaluate(
            {"type": "file_read", "path": "/home/u/.prismor/unlock.json"}, index=0
        )
        self.assertTrue(
            [f for f in findings if f["ruleId"] in _SELF_PROTECTION_RULE_IDS],
            "reading the unlock credential must be caught",
        )


class TestSelfProtectionCannotBeSwitchedOff(unittest.TestCase):
    def test_policy_cannot_disable_a_self_protection_rule(self):
        eng = _engine(
            'version: "1.0"\nsettings:\n  selection: explicit\n  default_mode: observe\n'
            "rules:\n"
            "  - id: prismor-self-edit\n    enabled: false\n"
            "  - id: agent-config-tampering\n    enabled: false\n    mode: observe\n"
        )
        findings = eng.evaluate(
            {"type": "shell", "command": "prismor allow risky-write --off --yes"}, index=0
        )
        self.assertIsNotNone(should_block(findings, {**PRE, "type": "shell"}))

    def test_device_mode_observe_cannot_downgrade_self_protection(self):
        eng = _engine(
            'version: "1.0"\nsettings:\n  device_mode: observe\n  default_mode: observe\n'
        )
        findings = eng.evaluate({"type": "shell", "command": "prismor unlock"}, index=0)
        hit = [f for f in findings if f["ruleId"] == "prismor-self-edit"]
        self.assertTrue(hit)
        self.assertEqual(hit[0]["mode"], "enforce")

    def test_allowlist_cannot_suppress_self_protection(self):
        # An allowlist is the narrowest exception and applies to floor rules,
        # but `prismor allow` refuses to write one for these — check the
        # refusal rather than the mechanism.
        from prismor.runtime import allow
        d = Path(tempfile.mkdtemp())
        with mock.patch(
            "prismor.runtime.enterprise.workspace_scope.is_managed", return_value=False
        ):
            for rule_id in _SELF_PROTECTION_RULE_IDS:
                self.assertIsNotNone(
                    allow.check_allowed(rule_id, scope="pattern", workspace=d, confirmed=True)
                )


class TestUnblockMessage(unittest.TestCase):
    def test_self_protection_block_points_at_the_unlock_window(self):
        from prismor.runtime.unblock import format_unblock
        text = format_unblock(
            {"ruleId": "prismor-self-edit", "category": "security_bypass",
             "evidence": "prismor allow risky-write --off"},
            workspace=Path("/work"),
        )
        self.assertIn("prismor unlock", text)
        self.assertNotIn("prismor allow prismor-self-edit", text)

    def test_ordinary_block_offers_a_runnable_allow_command(self):
        from prismor.runtime.unblock import format_unblock
        text = format_unblock(
            {"ruleId": "risky-write", "category": "risky_write",
             "evidence": "Dockerfile"},
            workspace=Path("/work"),
        )
        self.assertIn("prismor allow risky-write --pattern 'Dockerfile'", text)
        self.assertIn("--observe", text)

    def test_ordinary_block_also_offers_to_delegate_to_the_agent(self):
        # Watched a real agent read this message, correctly conclude the fix was
        # the human's to run, relay it, and stop — which left the unlock window
        # unreachable, because the only action that opens it is the one the
        # message told the agent not to take. Delegation has to be offered.
        from prismor.runtime.unblock import format_unblock
        text = format_unblock(
            {"ruleId": "risky-write", "category": "risky_write",
             "evidence": "Dockerfile"},
            workspace=Path("/work"),
        )
        self.assertIn("prismor unlock", text)
        self.assertIn("let the agent apply", text)

    def test_self_protection_block_does_not_offer_to_delegate(self):
        # These are the rules the window lifts. Offering it here would read as
        # "unlock so the agent can stop me guarding myself".
        from prismor.runtime.unblock import format_unblock
        text = format_unblock(
            {"ruleId": "prismor-self-edit", "category": "security_bypass",
             "evidence": "prismor allow risky-write --off"},
            workspace=Path("/work"),
        )
        self.assertNotIn("let the agent apply", text)


if __name__ == "__main__":
    unittest.main()
