"""Self-protection rules must fire on local intent, not on any mention of a path.

Two regressions, both of which made the hooked agent unable to do ordinary work
while not actually protecting anything extra:

  * issue #343 - `agent-config-tampering` blocked read-only inspection
    (`cat`/`ls`/`stat`/`grep`) of a settings file and reported it as
    "modification/deletion". A rule's patterns are one alternation applied to
    every field it names, so the bare-path forms meant for a `file_write`
    `path` were also tested against `command`; being `$`-anchored, they matched
    any command that happened to END with the path.

  * issue #344 - `prismor-self-edit` fired on `ssh`/`docker`/`kubectl`
    invocations, because the `;` separating statements inside the remote
    command's quoted argument satisfied the rule's `(^|[;&|`]|$()` anchor. The
    local policy has no jurisdiction over another host's Prismor, and the
    remediation it prints ("run it yourself") is for the wrong machine.

The negative cases matter as much as the positive ones. A "does the command
start with ssh?" guard would have fixed the reported symptom while opening
`ssh -V; prismor allow` as a one-line bypass of a rule that is deliberately
non-overridable, so those forms are asserted explicitly below.

Run:  python3 tests/test_local_jurisdiction.py
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["PRISMOR_HOME"] = tempfile.mkdtemp(prefix="prismor-jurisdiction-")

from prismor.runtime.hooks import should_block
from prismor.runtime.policy_engine import PolicyEngine

_SELF = ("prismor-self-edit",)
_CFG = ("agent-config-tampering", "agent-config-tampering-path")

# Assembled so this file's own text does not trip the rules it is testing when
# an agent reads or greps it.
_RM = "\x72m"

_ENGINE = PolicyEngine()


def _blocks(command: str, rule_ids, event_type: str = "shell") -> bool:
    """Does one of ``rule_ids`` actually BLOCK this event?

    Scoped to the rules under test on purpose: unrelated rules (the semantic
    guard, for one) may legitimately fire on the same string, and this suite is
    about jurisdiction, not about those.
    """
    event = ({"type": event_type, "command": command} if event_type == "shell"
             else {"type": event_type, "path": command})
    event["agent_event"] = "PreToolUse"
    findings = [f for f in _ENGINE.evaluate(event, 0) if f["ruleId"] in rule_ids]
    return bool(should_block(findings, event))


class TestReadsAreNotTampering(unittest.TestCase):
    """#343: inspecting agent config is diagnosis, not modification."""

    def test_read_only_inspection_is_allowed(self):
        for command in (
            "cat ~/.claude/settings.json",
            "ls -la ~/.claude/settings.json",
            "stat -c %y ~/.claude/settings.json",
            "grep hooks ~/.claude/settings.json",
            "head -5 ~/.claude/settings.local.json",
            "cat ~/.prismor/policy.yaml",
            "diff ~/.claude/settings.json /tmp/x",
        ):
            with self.subTest(command=command):
                self.assertFalse(_blocks(command, _CFG))

    def test_mutation_still_blocks(self):
        for command in (
            f"{_RM} ~/.claude/settings.json",
            f"{_RM} -f ~/.claude/settings.local.json",
            "echo x > ~/.claude/settings.json",
            "mv /tmp/x ~/.claude/settings.json",
            "cp /tmp/x ~/.claude/settings.json",
            "truncate -s0 ~/.claude/settings.json",
            # Neither of these was blocked before the split: `tee` was missing
            # from the verb list entirely, and the shell pattern lacked
            # `(\.local)?`, so both leaned on the over-broad bare-path form.
            "tee ~/.claude/settings.json < /tmp/x",
            "sed -i 's/a/b/' ~/.claude/settings.json",
            f"{_RM} ~/.prismor/policy.yaml",
            "echo x > ~/.prismor/policy.yaml",
            f"{_RM} ~/.prismor-warden/policy.yaml",
        ):
            with self.subTest(command=command):
                self.assertTrue(_blocks(command, _CFG))

    def test_a_read_after_an_unrelated_mutating_command_is_allowed(self):
        """The verb must govern the path, not merely precede it somewhere.

        `[^\\n]*` between the verb and the path let any earlier command supply
        the verb, so an ordinary install-then-inspect turned into "modification
        /deletion" of the settings file.
        """
        for command in (
            "pip install requests; cat ~/.claude/settings.json",
            "npm install && cat ~/.claude/settings.json",
            f"{_RM} /tmp/scratch; cat ~/.claude/settings.json",
            f"{_RM} -rf build | cat ~/.claude/settings.json",
            "sed -n '1p' /tmp/x; grep hooks ~/.prismor/policy.yaml",
        ):
            with self.subTest(command=command):
                self.assertFalse(_blocks(command, _CFG))

    def test_mutation_in_a_later_segment_still_blocks(self):
        """The converse: the segment that mutates is the one that matters."""
        for command in (
            f"echo hi; {_RM} ~/.claude/settings.json",
            f"cd /tmp && {_RM} ~/.prismor/policy.yaml",
        ):
            with self.subTest(command=command):
                self.assertTrue(_blocks(command, _CFG))

    def test_file_write_path_surface_still_blocks(self):
        # How an agent's Write/Edit tool actually reaches the file. The path
        # rule keeps the `(^|/)...$` form, so a directory containing a space
        # is still covered.
        for path in (
            "/home/u/.claude/settings.json",
            "/home/u/.claude/settings.local.json",
            "/Users/x/My Project/.claude/settings.json",
            "/home/u/.prismor/policy.yaml",
            "/home/u/.prismor-warden/policy.yaml",
        ):
            with self.subTest(path=path):
                self.assertTrue(_blocks(path, _CFG, "file_write"))

    def test_unrelated_write_is_untouched(self):
        self.assertFalse(_blocks("/home/u/notes.md", _CFG, "file_write"))


class TestRemoteContextIsNotSelfEdit(unittest.TestCase):
    """#344: a remote/container payload is a different install's policy."""

    def test_remote_execution_does_not_block(self):
        for command in (
            'ssh host "export A=1; prismor unlock --set-password"',
            'ssh -i key user@host "export PRISMOR_HOME=/tmp/x; prismor unlock --set-password"',
            'ssh user@remotehost "prismor unlock --set-password"',
            'docker run img sh -c "prismor pause"',
            'docker exec c sh -c "cd /app; prismor allow"',
            'podman exec c sh -c "prismor allow"',
            'kubectl exec pod -- sh -c "prismor pause"',
        ):
            with self.subTest(command=command):
                self.assertFalse(_blocks(command, _SELF))

    def test_remote_agent_config_edit_does_not_block(self):
        self.assertFalse(_blocks(f'ssh host "{_RM} ~/.claude/settings.json"', _CFG))

    def test_local_self_edit_still_blocks(self):
        for command in (
            "prismor unlock --set-password",
            "prismor allow",
            "prismor pause",
            "sudo prismor uninstall",
            "echo hi; prismor allow",
            "PRISMOR_HOME=/tmp/x prismor unlock --set-password",
            'bash -c "prismor allow"',
            'sh -c "prismor allow"',
            "prismor policy edit",
            "prismor egress allow evil.com",
            "cat ~/.prismor/unlock.json",
        ):
            with self.subTest(command=command):
                self.assertTrue(_blocks(command, _SELF))

    def test_remote_command_does_not_shelter_a_local_one(self):
        """The bypass a "starts with ssh/docker" guard would have opened.

        In each of these the prismor invocation runs on THIS machine; only the
        earlier segment is remote. The match must sit inside the remote
        command's own quoted argument to be exempt.
        """
        for command in (
            "ssh -V; prismor allow",
            "docker ps; prismor allow",
            'echo "ssh"; prismor allow',
            'ssh host "x"; prismor allow',
            'ssh host "uptime" && prismor unlock --set-password',
        ):
            with self.subTest(command=command):
                self.assertTrue(_blocks(command, _SELF))

    def test_local_command_substitutions_in_remote_commands_still_block(self):
        """#607: substitutions inside double quotes execute on the local machine."""
        for command in (
            'ssh host "echo $(cat ~/.prismor/unlock.json)"',
            'ssh host "echo `cat ~/.prismor/unlock.json`"',
            'docker run img sh -c "echo $(cat ~/.prismor/unlock.json)"',
        ):
            with self.subTest(command=command):
                self.assertTrue(_blocks(command, _SELF))

        for command in (
            'ssh host "echo $(echo x > ~/.prismor/policy.yaml)"',
        ):
            with self.subTest(command=command):
                self.assertTrue(_blocks(command, _CFG))

    def test_local_ssh_options_still_block(self):
        """#607: SSH options such as ProxyCommand execute on the local machine."""
        for command in (
            "ssh -o ProxyCommand='cat ~/.prismor/unlock.json' host",
            'ssh -o ProxyCommand="cat ~/.prismor/unlock.json" host',
            "ssh -o ProxyCommand 'cat ~/.prismor/unlock.json' host",
            "ssh -oProxyCommand='cat ~/.prismor/unlock.json' host",
            'ssh -o "ProxyCommand=cat ~/.prismor/unlock.json" host',
            'ssh -o "ProxyCommand cat ~/.prismor/unlock.json" host',
            "ssh -o KnownHostsCommand='cat ~/.prismor/unlock.json' host",
            "ssh -i '~/.prismor/unlock.json' host",
            # The whole option quoted as one word, or glued with escaped spaces.
            'ssh "-oProxyCommand=cat ~/.prismor/unlock.json" host',
            "ssh '-oProxyCommand cat ~/.prismor/unlock.json' host",
            'ssh -oProxyCommand=sh\\ -c\\ "cat ~/.prismor/unlock.json" host',
            'sshpass -p pw ssh -o ProxyCommand="cat ~/.prismor/unlock.json" host',
        ):
            with self.subTest(command=command):
                self.assertTrue(_blocks(command, _SELF))

        for command in (
            "ssh -o ProxyCommand='echo x > ~/.prismor/policy.yaml' host",
            "ssh -o LocalCommand='echo x > ~/.prismor/policy.yaml' host",
        ):
            with self.subTest(command=command):
                self.assertTrue(_blocks(command, _CFG))

    def test_quotes_nested_in_local_commands_still_block(self):
        """#607: a quoted span is only remote when ssh/docker itself receives it."""
        for command in (
            # An unquoted substitution runs locally to build ssh's argv.
            'ssh host $(sh -c "cat ~/.prismor/unlock.json")',
            'ssh host `sh -c "cat ~/.prismor/unlock.json"`',
            'ssh host <(sh -c "cat ~/.prismor/unlock.json")',
            # A newline ends the ssh command like `;` does.
            'ssh host true\nsh -c "cat ~/.prismor/unlock.json"',
            # File-copy subcommands and flag values read this machine's files.
            'docker cp "$HOME/.prismor/unlock.json" c:/tmp/x',
            'kubectl cp "$HOME/.prismor/unlock.json" pod:/tmp/x',
        ):
            with self.subTest(command=command):
                self.assertTrue(_blocks(command, _SELF))

    def test_confirmed_remote_payloads_remain_exempt(self):
        """#607: confirmed remote payloads without local substitution remain exempt."""
        for command in (
            'ssh host "cat ~/.prismor/unlock.json"',
            "ssh host 'cat ~/.prismor/unlock.json'",
            "ssh host 'echo $(cat ~/.prismor/unlock.json)'",
            'ssh host "echo $(hostname); prismor unlock --set-password"',
            'ssh -T user@host "cat ~/.prismor/unlock.json"',
            'ssh host -t "cat ~/.prismor/unlock.json"',
            'ssh -p 2222 -o StrictHostKeyChecking=no host "cat ~/.prismor/unlock.json"',
            'ssh -- host "cat ~/.prismor/unlock.json"',
            'sshpass -p pw ssh host "cat ~/.prismor/unlock.json"',
            'docker exec -it c sh -c "cat ~/.prismor/unlock.json"',
            'kubectl exec pod -- sh -c "cat ~/.prismor/unlock.json"',
        ):
            with self.subTest(command=command):
                self.assertFalse(_blocks(command, _SELF))


class TestRemoteExemptionIsNarrow(unittest.TestCase):
    """The exemption is about jurisdiction, never about danger."""

    def test_remote_destructive_command_still_blocks(self):
        # `ssh host "rm -rf /"` destroys a real machine. Only rules whose
        # subject is *this* install's own configuration are exempted.
        event = {"type": "shell", "agent_event": "PreToolUse",
                 "command": 'ssh host "%s -rf /"' % _RM}
        findings = _ENGINE.evaluate(event, 0)
        self.assertTrue(
            bool(should_block(findings, event)),
            "a destructive payload must still block inside an ssh argument",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
