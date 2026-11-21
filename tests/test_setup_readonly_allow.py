"""Setup pre-approves the read-only commands its CLAUDE.md block tells the
agent to run, so a manual-approval Claude Code session doesn't open on a
permission prompt for `prismor status` (demo finding #4)."""
import json

from prismor.runtime import setup_wizard as wizard


def test_rules_are_exact_and_read_only():
    for rule in wizard._READONLY_ALLOW_RULES:
        assert rule.startswith("Bash(prismor ") and rule.endswith(")")
        assert ":*" not in rule and "*" not in rule  # no prefix/wildcard rules
        sub = rule[len("Bash(prismor "):-1].split()[0]
        assert sub in {"status", "cloak", "query"}
    assert "Bash(prismor status)" in wizard._READONLY_ALLOW_RULES
    # The block it backs up actually tells the agent to run that command.
    assert "Run `prismor status` at the start of every session" in wizard._AGENT_CONTEXT_BLOCK


def test_merges_into_existing_settings_without_duplicates(tmp_path):
    settings = tmp_path / ".claude" / "settings.json"
    settings.parent.mkdir()
    settings.write_text(json.dumps({
        "hooks": {"PreToolUse": []},
        "permissions": {"allow": ["Bash(npm test)"], "deny": ["Bash(curl:*)"]},
    }))
    wizard._allow_readonly_commands(settings)
    wizard._allow_readonly_commands(settings)
    data = json.loads(settings.read_text())
    allow = data["permissions"]["allow"]
    assert allow[0] == "Bash(npm test)"
    assert allow.count("Bash(prismor status)") == 1
    assert data["permissions"]["deny"] == ["Bash(curl:*)"]
    assert data["hooks"] == {"PreToolUse": []}


def test_creates_settings_when_missing(tmp_path):
    settings = tmp_path / ".claude" / "settings.json"
    wizard._allow_readonly_commands(settings)
    assert "Bash(prismor status)" in json.loads(settings.read_text())["permissions"]["allow"]


def test_leaves_unparseable_settings_alone(tmp_path):
    settings = tmp_path / "settings.json"
    settings.write_text("{ not json")
    assert wizard._allow_readonly_commands(settings).startswith("skipped")
    assert settings.read_text() == "{ not json"
