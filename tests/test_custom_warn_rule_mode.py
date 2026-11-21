"""A rule an admin writes with `action: warn` reports; it does not block just
because the policy's default_mode is enforce (#720). Its own `mode: enforce`
still blocks, and shipped rules keep following default_mode."""
import yaml

from prismor.runtime.policy_engine import PolicyEngine


def _engine(tmp_path, rule):
    (tmp_path / ".prismor").mkdir()
    (tmp_path / ".prismor" / "policy.yaml").write_text(yaml.safe_dump(
        {"settings": {"default_mode": "enforce"}, "rules": [rule]}))
    return PolicyEngine(workspace=tmp_path)


def _rule(**extra):
    return {"id": "heads-up", "severity": "LOW", "category": "custom", "title": "Heads-up",
            "event_types": ["tool_result"], "fields": ["response"], "patterns": ["heads-up"], **extra}


def _mode(eng, rid):
    return eng.explain_mode(next(r for r in eng.rules if r.id == rid))[0]


def test_custom_warn_rule_observes_under_enforce_default(tmp_path):
    assert _mode(_engine(tmp_path, _rule(action="warn")), "heads-up") == "observe"


def test_its_own_mode_enforce_still_blocks(tmp_path):
    assert _mode(_engine(tmp_path, _rule(action="warn", mode="enforce")), "heads-up") == "enforce"


def test_a_rule_without_an_action_still_follows_default_mode(tmp_path):
    assert _mode(_engine(tmp_path, _rule()), "heads-up") == "enforce"


def test_shipped_warn_rules_keep_following_default_mode(tmp_path):
    eng = _engine(tmp_path, _rule(action="block"))
    shipped = [r for r in eng.rules if r.action == "warn" and not r.warn_only]
    assert shipped, "default_policy.yaml ships warn rules"
    assert all(eng.explain_mode(r)[0] == "enforce" for r in shipped)
