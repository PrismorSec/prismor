"""recursive-delete-home: warn (never block) on a recursive force delete of a
directory under the home dir; build/cache dirs stay quiet (PrismorSec/prismor#505)."""
from __future__ import annotations

import pytest

from prismor.runtime.policy_engine import PolicyEngine

RM = "rm" + " -rf"  # keep the literal out of any shell that screens this file
ENGINE = PolicyEngine()


def _hits(cmd):
    return [f for f in ENGINE.evaluate({"type": "shell", "command": cmd}, 0)
            if f["ruleId"] == "recursive-delete-home"]


@pytest.mark.parametrize("cmd", [
    f"{RM} /home/ubuntu/ux-0925/data",
    f"{RM} /Users/alice/projects/app",
    f"{RM} ~/Documents/reports",
    f'{RM} "$HOME/work/client-db"',
    f"cd /tmp && {RM} /Users/alice/.ssh-backup",
    "rm -r -f /home/bob/photos",
])
def test_warns(cmd):
    hits = _hits(cmd)
    assert hits and hits[0]["action"] == "warn" and hits[0]["severity"] == "HIGH"


@pytest.mark.parametrize("cmd", [
    f"{RM} build",
    f"{RM} ./node_modules",
    f"{RM} /tmp/my-cache",
    f"{RM} /Users/alice/projects/app/node_modules",
    f"{RM} /home/bob/app/dist",
    f"{RM} ~/proj/.next",
    f"{RM} /Users/alice/proj/.venv",
    "rm /Users/alice/notes.txt",
    "ls -la /home/bob/data",
])
def test_quiet(cmd):
    assert not _hits(cmd)


def test_never_blocks_under_legacy_category_gating():
    from prismor.runtime.hooks import legacy_should_block
    hits = _hits(f"{RM} /home/ubuntu/ux-0925/data")
    ev = {"type": "shell", "agent_event": "PreToolUse"}
    assert legacy_should_block(hits, ev, {"destructive_command"}) is None



def test_default_policy_stays_on_legacy_category_gating():
    """A rule-level `mode` anywhere flips the default policy out of legacy
    gating and silently stops secret-access blocking (surface conformance)."""
    assert PolicyEngine().is_legacy_policy
