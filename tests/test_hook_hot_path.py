"""Work kept off the per-tool-call hook path must not change what it decides."""
import re
from pathlib import Path

import pytest

from prismor.runtime import cli
from prismor.runtime.data_boundary import DataBoundaryPolicy
from prismor.runtime.hooks import _SUPPORTED_AGENTS
from prismor.runtime.policy_engine import CompiledRule, PolicyEngine


def test_every_shipped_rule_pattern_compiles():
    # Shipped patterns compile on first use, so this is where a broken one fails.
    for rule in PolicyEngine().rules:
        assert isinstance(rule.patterns, re.Pattern), rule.id


def test_shipped_patterns_are_lazy_and_changed_ones_compile_at_load():
    raw = {"id": "r", "severity": "LOW", "category": "c", "title": "t",
           "event_types": ["shell"], "patterns": ["foo"]}
    assert CompiledRule(dict(raw), shipped=["foo"])._patterns is None
    assert CompiledRule(dict(raw), shipped=["bar"])._patterns is not None
    with pytest.raises(re.error):
        CompiledRule({**raw, "patterns": ["("]}, shipped=["foo"])


def test_lazy_rule_matches_like_eager():
    raw = {"id": "r", "severity": "LOW", "category": "c", "title": "t",
           "event_types": ["shell"], "patterns": [r"rm\s+-rf", "(?i)curl.*\\|\\s*sh"]}
    lazy, eager = CompiledRule(dict(raw), shipped=list(raw["patterns"])), CompiledRule(dict(raw))
    assert lazy.patterns.pattern == eager.patterns.pattern and lazy.patterns.flags == eager.patterns.flags


def test_self_identity_discovered_on_first_read(monkeypatch):
    import prismor.runtime.data_boundary as db
    calls = []
    monkeypatch.setattr(db, "discover_self_identity", lambda ws: calls.append(ws) or ["me@example.com"])
    pol = DataBoundaryPolicy()
    pol.self_identity = ["me@example.com", "other@example.com"]
    pol.discover_self_later(Path("/ws"))
    assert calls == []
    assert pol.self_identity == ["me@example.com", "other@example.com"]
    assert pol.self_identity == ["me@example.com", "other@example.com"] and calls == [Path("/ws")]


@pytest.mark.parametrize("agent", _SUPPORTED_AGENTS)
def test_hook_dispatch_parser_matches_full_parser(agent):
    argv = ["hook-dispatch", "--agent", agent, "--workspace", "/w", "--mode", "enforce"]
    fast, full = cli._hook_dispatch_parser().parse_args(argv), cli.build_parser().parse_args(argv)
    assert vars(fast) == vars(full)
