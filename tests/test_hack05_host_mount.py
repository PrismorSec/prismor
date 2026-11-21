"""A container or chroot that can see this install is not a remote payload."""

import tempfile
import unittest
from pathlib import Path

from prismor.runtime.hooks import should_block
from prismor.runtime.policy_engine import PolicyEngine


def _findings(command: str):
    with tempfile.TemporaryDirectory() as tmp:
        eng = PolicyEngine(workspace=Path(tmp))
        return eng.evaluate({"type": "shell", "command": command}, index=0)


def _blocks(command: str) -> bool:
    return should_block(
        _findings(command), {"type": "shell", "agent_event": "PreToolUse"}
    ) is not None


class TestHostMount(unittest.TestCase):
    def test_home_mount_and_chroot_root_block(self):
        for command in (
            'docker run -v "$HOME:/h" alpine sh -c "echo x > /h/.prismor/policy.yaml"',
            "chroot / sh -c 'prismor allow risky-write --off'",
        ):
            self.assertTrue(_blocks(command), command)

    def test_remote_ssh_self_edit_stays_inert(self):
        command = 'ssh host "export A=1; prismor unlock --set-password"'
        self.assertFalse(_blocks(command))
        self.assertFalse(_blocks('docker run img sh -c "prismor pause"'))
        self.assertFalse(_blocks('docker run -v /tmp:/tmp alpine sh -c "prismor pause"'))

    def test_everyday_home_mounts_stay_quiet(self):
        for command in (
            "docker run --rm -v ~/project:/app node:20 npm test",
            "docker run --rm -v $HOME/.aws:/root/.aws:ro amazon/aws-cli s3 ls",
            'docker run --rm -v "$PWD":/app -w /app node:20 npm ci',
        ):
            self.assertFalse(_blocks(command), command)
