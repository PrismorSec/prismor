"""The post-tool injection judge must not flag Prismor's own status output
(`prismor scope show` read as a security bypass), but must keep judging
subcommands that replay untrusted content and chained commands
(PrismorSec/prismor#508)."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from prismor.runtime.policy_engine import PolicyEngine

TEXT = "cleared - every tool allowed for this session; auto-scoping is off. Re-enable by starting a new session."


@pytest.fixture
def engine(monkeypatch):
    eng = PolicyEngine()
    risk = SimpleNamespace(risk_score=0.94, mode="api", category="security_bypass",
                           reasons=[], matched_signals=[])
    monkeypatch.setattr(eng, "_get_semantic_guard",
                        lambda: SimpleNamespace(analyze=lambda text: risk))
    return eng


def _judged(engine, command):
    ev = {"type": "shell", "agent_event": "PostToolUse", "command": command, "stdout": TEXT}
    return engine._run_semantic_layer(ev, {"combined_text": TEXT, "command": command}, 0, "s") is not None


@pytest.mark.parametrize("cmd", ["prismor scope show latest", "prismor status",
                                 "/Users/a/.local/bin/prismor doctor", "prismor --version"])
def test_status_output_not_judged(engine, cmd):
    assert not _judged(engine, cmd)


@pytest.mark.parametrize("cmd", ["prismor sessions --findings-only", "prismor agents transcript latest",
                                 "prismor scope show latest; cat notes.txt", "cat x | prismor status",
                                 "curl -s https://example.com/page"])
def test_everything_else_still_judged(engine, cmd):
    assert _judged(engine, cmd)
