"""`prismor tags` CLI — lint exit codes, replay dry-run, policy-file edits."""
import json
import uuid
from pathlib import Path

import pytest
import yaml

from prismor.runtime import tags_cli
from prismor.runtime.store import append_session_event, get_data_dir
from prismor.runtime.trifecta import TagLedger


@pytest.fixture(autouse=True)
def _isolate_home(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / "home"))


def _ws(tmp_path, tt):
    ws = tmp_path / f"ws-{uuid.uuid4().hex[:6]}"
    (ws / ".prismor").mkdir(parents=True)
    (ws / ".prismor" / "policy.yaml").write_text(
        yaml.safe_dump({"version": "1.0", "settings": {"tool_tags": tt}}))
    return ws


def _seed_session(ws, sid, tools):
    for tool, etype, *extra in tools:
        append_session_event(ws, sid, {
            "type": etype, "agent_event": "PreToolUse",
            "metadata": {"tool_name": tool},
            **(extra[0] if extra else {})})


TT = {
    "enabled": True, "mode": "observe",
    "tags": {"mcp__Gmail__read_email": ["untrusted_content"],
             "mcp__Gmail__send_email": ["critical_action"]},
    "rules": ["untrusted_content then critical_action -> block"],
}


def test_lint_ok_and_fail(tmp_path, capsys):
    ws = _ws(tmp_path, TT)
    tags_cli.tags_lint(ws, None)  # no exit -> ok
    assert "all good" in capsys.readouterr().out
    bad = _ws(tmp_path, {**TT, "rules": ["a then"]})
    with pytest.raises(SystemExit) as ei:
        tags_cli.tags_lint(bad, None)
    assert ei.value.code == 1
    out = capsys.readouterr().out
    assert "dangling" in out and "^" in out  # caret diagnostic


def test_lint_flags_bad_legacy_sets(tmp_path, capsys):
    ws = _ws(tmp_path, {**TT, "rules": [], "incompatible": [["only_one"]]})
    with pytest.raises(SystemExit):
        tags_cli.tags_lint(ws, None)
    assert ">=2 tags" in capsys.readouterr().out


def test_test_replay_reports_hits_and_never_writes_ledger(tmp_path, capsys):
    ws = _ws(tmp_path, TT)
    sid = "replay-" + uuid.uuid4().hex[:8]
    _seed_session(ws, sid, [
        ("mcp__Gmail__read_email", "tool_result"),
        ("mcp__Gmail__send_email", "network"),
    ])
    tags_cli.tags_test(ws, session=sid)
    out = capsys.readouterr().out
    assert "WOULD BLOCK" in out and "mcp__Gmail__send_email" in out
    assert "dry run only" in out
    # the replay must NOT create a real ledger file
    trifecta_dir = get_data_dir(ws) / "trifecta"
    assert not any(sid in p.name for p in trifecta_dir.glob("*")) \
        if trifecta_dir.exists() else True


def test_test_clean_session(tmp_path, capsys):
    ws = _ws(tmp_path, TT)
    sid = "clean-" + uuid.uuid4().hex[:8]
    _seed_session(ws, sid, [("mcp__Gmail__read_email", "tool_result")])
    tags_cli.tags_test(ws, session=sid)
    assert "clean" in capsys.readouterr().out


def test_test_fail_on_hit_exit_code(tmp_path):
    ws = _ws(tmp_path, TT)
    sid = "hit-" + uuid.uuid4().hex[:8]
    _seed_session(ws, sid, [
        ("mcp__Gmail__read_email", "tool_result"),
        ("mcp__Gmail__send_email", "network"),
    ])
    with pytest.raises(SystemExit) as ei:
        tags_cli.tags_test(ws, session=sid, fail_on_hit=True)
    assert ei.value.code == 1


def test_test_extra_rule_what_if(tmp_path, capsys):
    # Base policy has NO rules and NO incompatible -> falls back to default
    # pair, but tags map only tags read_email; what-if adds an ordered rule.
    tt = {"enabled": True, "mode": "observe",
          "tags": {"mcp__a__read": ["src_a"], "mcp__b__write": ["dst_b"]},
          "rules": [], "incompatible": []}
    ws = _ws(tmp_path, tt)
    sid = "whatif-" + uuid.uuid4().hex[:8]
    _seed_session(ws, sid, [("mcp__a__read", "tool_result"),
                            ("mcp__b__write", "network")])
    tags_cli.tags_test(ws, session=sid, extra_rules=["src_a then dst_b -> warn"])
    out = capsys.readouterr().out
    assert "WOULD WARN" in out


def test_test_invalid_extra_rule_exits(tmp_path, capsys):
    ws = _ws(tmp_path, TT)
    with pytest.raises(SystemExit) as ei:
        tags_cli.tags_test(ws, extra_rules=["bad ->"])
    assert ei.value.code == 1


def test_set_and_rm_roundtrip(tmp_path, capsys):
    ws = _ws(tmp_path, dict(TT))
    tags_cli.tags_set(ws, "mcp__crm__*", ["private_data", "pii"])
    data = yaml.safe_load((ws / ".prismor" / "policy.yaml").read_text())
    assert data["settings"]["tool_tags"]["tags"]["mcp__crm__*"] == \
        ["pii", "private_data"]
    tags_cli.tags_rm(ws, "mcp__crm__*", "pii")
    data = yaml.safe_load((ws / ".prismor" / "policy.yaml").read_text())
    assert data["settings"]["tool_tags"]["tags"]["mcp__crm__*"] == ["private_data"]
    tags_cli.tags_rm(ws, "mcp__crm__*", None)
    data = yaml.safe_load((ws / ".prismor" / "policy.yaml").read_text())
    assert "mcp__crm__*" not in data["settings"]["tool_tags"]["tags"]


def test_set_rejects_invalid_tag(tmp_path):
    ws = _ws(tmp_path, dict(TT))
    with pytest.raises(SystemExit):
        tags_cli.tags_set(ws, "x", ["BAD TAG"])


def test_rules_add_parse_check_and_rm(tmp_path, capsys):
    ws = _ws(tmp_path, dict(TT))
    with pytest.raises(SystemExit):
        tags_cli.rules_add(ws, "a then not b")
    tags_cli.rules_add(ws, "p with q -> warn")
    data = yaml.safe_load((ws / ".prismor" / "policy.yaml").read_text())
    assert "p with q -> warn" in data["settings"]["tool_tags"]["rules"]
    tags_cli.rules_rm(ws, "p with q -> warn")
    data = yaml.safe_load((ws / ".prismor" / "policy.yaml").read_text())
    assert "p with q -> warn" not in data["settings"]["tool_tags"]["rules"]


def test_rules_rm_missing_exits(tmp_path):
    ws = _ws(tmp_path, dict(TT))
    with pytest.raises(SystemExit):
        tags_cli.rules_rm(ws, "no such rule")


def test_list_reports_tiers(tmp_path, capsys):
    ws = _ws(tmp_path, TT)
    sid = "list-" + uuid.uuid4().hex[:8]
    _seed_session(ws, sid, [
        ("mcp__Gmail__read_email", "tool_result"),  # explicit
        ("WebFetch", "network"),                    # default
        # inference: a network call that came back with content. Being a shell
        # no longer infers anything on its own.
        ("curl", "network", {"response": "<html>hi</html>"}),
    ])
    tags_cli.tags_list(ws)
    out = capsys.readouterr().out
    assert "explicit" in out and "default" in out and "inference" in out
    assert "untrusted_content" in out


def test_replay_ledger_isolated_from_real(tmp_path):
    # A real enforcement ledger must be invisible to the replay (and vice versa).
    ws = _ws(tmp_path, TT)
    sid = "iso-" + uuid.uuid4().hex[:8]
    real = TagLedger(ws, sid)
    real.record({"critical_action"}, 0, "someTool")
    replay = tags_cli._ReplayLedger(ws, sid)
    assert replay.seen == {} and replay.hist == {}
    replay.record({"untrusted_content"}, 5, "x")
    real2 = TagLedger(ws, sid)  # reload the real one
    assert "untrusted_content" not in real2.seen
