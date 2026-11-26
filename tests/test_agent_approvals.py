import json
from pathlib import Path

from prismor.runtime import agent_approvals as aa


def test_agents_are_kept_off_the_route_and_the_off_file():
    import re

    import yaml

    policy = yaml.safe_load((Path(aa.__file__).parent / "default_policy.yaml").read_text())
    patterns = [p for r in policy["rules"] if r["id"].startswith("prismor-self") for p in r["patterns"]]
    # Assembled so that editing or running this file does not itself look like the attack.
    for command in ("cu" + "rl -X POST http://localhost:7070/api/" + "allow-rules -d x",
                    "cat ~/.prismor/allow-rules-" + "off.json"):
        assert any(re.search(p, command, re.I) for p in patterns), command


def _write(path: Path, text: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def test_collects_each_agent_and_masks_secrets(tmp_path, monkeypatch):
    home, project = tmp_path / "home", tmp_path / "proj"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / "ph"))
    monkeypatch.delenv("CODEX_HOME", raising=False)
    token = "abc123def456ghi789"
    _write(home / ".claude/settings.json", json.dumps({"permissions": {"allow": [
        f'Bash(curl -H "Authorization: Bearer {token}" x)', f"Read({home}/notes)"]}}))
    _write(project / ".claude/settings.local.json", json.dumps({"permissions": {"allow": ["Bash(ls:*)"]}}))
    _write(home / ".codex/rules/default.rules",
           'prefix_rule(pattern=["git", ["push", "pull"]], decision="allow")\n'
           'prefix_rule(pattern=["rm"], decision="forbidden")\n')
    _write(home / ".cursor/cli-config.json", json.dumps({"permissions": {"allow": ["Shell(ls)"]}}))
    _write(home / ".gemini/config/config.json", json.dumps(
        {"userSettings": {"globalPermissionGrants": {"allow": ["command(npm)"]}}}))

    rows = aa.collect(project)
    rules = {(r["agent"], r["scope"], r["rule"]) for r in rows}
    assert token not in json.dumps(rows) and str(home) not in json.dumps(rows)
    assert ("claude", "global", "Read(~/notes)") in rules
    assert ("claude", "project", "Bash(ls:*)") in rules
    assert ("codex", "global", "prefix_rule(git push|pull)") in rules
    assert ("cursor", "global", "Shell(ls)") in rules
    assert ("antigravity", "global", "command(npm)") in rules
    assert not any("rm" in r["rule"] and r["agent"] == "codex" for r in rows)


def test_broken_files_are_skipped(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / "ph"))
    _write(tmp_path / "home/.cursor/cli-config.json", "{not json")
    assert aa.collect(tmp_path) == []


def test_global_rules_survive_the_cap(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / "ph"))
    monkeypatch.setattr(aa, "MAX_RULES", 1)
    _write(tmp_path / "proj/.claude/settings.json", json.dumps({"permissions": {"allow": ["A", "B"]}}))
    _write(tmp_path / "home/.cursor/cli-config.json", json.dumps({"permissions": {"allow": ["Shell(ls)"]}}))
    assert [r["rule"] for r in aa.collect(tmp_path / "proj")] == ["Shell(ls)"]


def test_off_on_and_narrow(tmp_path, monkeypatch):
    home, project = tmp_path / "home", tmp_path / "proj"
    project.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / "ph"))
    monkeypatch.delenv("CODEX_HOME", raising=False)
    claude = home / ".claude/settings.json"
    codex = home / ".codex/rules/default.rules"
    _write(claude, json.dumps({"model": "x", "permissions": {"allow": ["Bash(ls)", "Bash(rm)"], "deny": ["Z"]}}))
    _write(codex, 'prefix_rule(pattern=["rm"], decision="allow")\nprefix_rule(pattern=["ls"], decision="allow")\n')

    def ident(rule, scope="global"):
        return next(r["id"] for r in aa.collect(project) if r["rule"] == rule and r["scope"] == scope)

    rm, cx = ident("Bash(rm)"), ident("prefix_rule(rm)")
    aa.turn_off(project, rm)
    aa.turn_off(project, cx)
    data = json.loads(claude.read_text())
    assert data["permissions"] == {"allow": ["Bash(ls)"], "deny": ["Z"]} and data["model"] == "x"
    assert '"rm"' not in codex.read_text() and '"ls"' in codex.read_text()
    assert {r["rule"] for r in aa.off_rules()} == {"Bash(rm)", "prefix_rule(rm)"}
    aa.turn_on(rm)
    aa.turn_on(cx)
    assert "Bash(rm)" in claude.read_text() and '"rm"' in codex.read_text() and aa.off_rules() == []

    aa.narrow(project, ident("Bash(ls)"), str(project))
    assert "Bash(ls)" not in claude.read_text()
    assert "Bash(ls)" in (project / ".claude/settings.local.json").read_text()
    for bad in (("Bash(ls)", "project", str(project)), ("Bash(rm)", "global", str(tmp_path / "elsewhere"))):
        try:
            aa.narrow(project, ident(bad[0], bad[1]), bad[2])
        except ValueError:
            continue
        raise AssertionError("narrow accepted " + str(bad))
    try:
        aa.turn_on("nope")
    except KeyError:
        pass
    else:
        raise AssertionError("turned on a rule that was never off")


def test_rule_the_agent_adds_back_is_listed_once_and_dated(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / "ph"))
    path = tmp_path / "home/.cursor/cli-config.json"

    def put(*rules):
        _write(path, json.dumps({"permissions": {"allow": list(rules)}}))

    def look():
        return {r["rule"]: r for r in aa.collect(tmp_path)}

    put("A")
    assert look()["A"]["added"] == "" and not look()["A"]["again"]
    put("A", "B")
    assert look()["B"]["added"] and not look()["B"]["again"]
    aa.turn_off(tmp_path, look()["A"]["id"])
    assert [r["rule"] for r in aa.off_rules()] == ["A"]
    put("B", "A")  # the person said "yes, do not ask again"
    row = look()["A"]
    assert row["again"] and row["added"] and aa.off_rules() == []
    assert look()["A"]["again"]  # stays marked on the next look


def test_always_ask_moves_the_rule_and_survives_a_readd(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / "ph"))
    path = tmp_path / "home/.claude/settings.json"
    _write(path, json.dumps({"permissions": {"allow": ["Bash(x)"]}}))

    def perms():
        return json.loads(path.read_text())["permissions"]

    def rows():
        return aa.collect(tmp_path)

    ident = rows()[0]["id"]
    aa.turn_off(tmp_path, ident, always_ask=True)
    assert perms() == {"allow": [], "ask": ["Bash(x)"]} and aa.off_rules()[0]["ask"]
    data = {"permissions": {"allow": ["Bash(x)"], "ask": ["Bash(x)"]}}
    _write(path, json.dumps(data))  # "don't ask again"
    assert rows()[0]["asks"] and aa.off_rules()  # the undo is not thrown away
    aa.turn_on(ident)
    assert perms() == {"allow": ["Bash(x)"], "ask": []}


def test_add_only_ask_or_deny_and_remove_only_our_own(tmp_path, monkeypatch):
    import pytest

    home, project = tmp_path / "home", tmp_path / "proj"
    project.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / "ph"))
    path = home / ".claude/settings.json"
    _write(path, json.dumps({"permissions": {"deny": ["Mine"]}}))

    aa.add_rule(project, "deny", " Bash(git push *) ")
    aa.add_rule(project, "ask", "WebFetch", str(project))
    assert json.loads(path.read_text())["permissions"] == {"deny": ["Mine", "Bash(git push *)"]}
    local = project / ".claude/settings.local.json"
    assert json.loads(local.read_text())["permissions"] == {"ask": ["WebFetch"]}
    for kind, rule, where in (("allow", "Bash(ls)", ""), ("deny", "rm -rf /", ""), ("deny", "A\nB", ""),
                              ("deny", "Mine", ""), ("ask", "Read", str(tmp_path / "elsewhere"))):
        with pytest.raises(ValueError):
            aa.add_rule(project, kind, rule, where)
    for entry in aa.added_rules():
        aa.remove_added(entry["id"])
    assert json.loads(path.read_text())["permissions"] == {"deny": ["Mine"]} and aa.added_rules() == []
    with pytest.raises(KeyError):
        aa.remove_added("nope")


def test_add_for_every_agent(tmp_path, monkeypatch):
    import pytest

    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / "ph"))
    monkeypatch.delenv("CODEX_HOME", raising=False)
    home = tmp_path / "home"
    aa.add_rule(tmp_path, "deny", "Shell(rm)", agent="cursor")
    aa.add_rule(tmp_path, "ask", "command(git push)", agent="antigravity")
    aa.add_rule(tmp_path, "deny", "git push", agent="codex")
    assert json.loads((home / ".cursor/cli-config.json").read_text())["permissions"]["deny"] == ["Shell(rm)"]
    grants = json.loads((home / ".gemini/config/config.json").read_text())["userSettings"]["globalPermissionGrants"]
    assert grants == {"ask": ["command(git push)"]}
    rules = home / ".codex/rules/default.rules"
    assert rules.read_text() == 'prefix_rule(pattern=["git", "push"], decision="forbidden")\n'
    for agent, kind, rule in (("cursor", "ask", "Shell(ls)"), ("codex", "deny", 'git") x('), ("nobody", "deny", "X")):
        with pytest.raises(ValueError):
            aa.add_rule(tmp_path, kind, rule, agent=agent)
    for entry in aa.added_rules():
        aa.remove_added(entry["id"])
    assert rules.read_text() == "" and aa.added_rules() == []
