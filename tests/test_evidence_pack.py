"""Authority scope on trail records + `prismor trail export` evidence pack (#943).

Run: python3 -m pytest tests/test_evidence_pack.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO))

IAM = ("agents:\n  reviewer:\n    allowed_tools: [Read, {allowed}]\n    deny_tools: [Write]\n")
POLICY = (
    'version: "1.0"\nrules:\n'
    "  - id: t-restricted\n    title: restricted account\n    severity: CRITICAL\n"
    "    category: custom-authz\n    event_types: [shell]\n"
    "    when: \"resource.attr.status == 'restricted'\"\n    action: block\n    mode: enforce\n"
)


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("PRISMOR_AGENT_ID", "reviewer")
    for mod in [m for m in sys.modules if m.startswith("prismor.runtime.enterprise.")]:
        sys.modules.pop(mod, None)
    ws = tmp_path / "ws"
    (ws / ".prismor").mkdir(parents=True)
    (ws / ".prismor" / "policy.yaml").write_text(POLICY)
    (ws / ".prismor" / "iam.yaml").write_text(IAM.format(allowed="Bash"))
    return ws


def _call(ws, status, sid="s1"):
    from prismor.runtime.runtime import evaluate_tool_call
    event = {"type": "shell", "command": "freeze_account account=ACC-1",
             "agent": "python-sdk", "agent_event": "PreToolUse",
             "metadata": {"tool_name": "Bash", "framework": "python-sdk"}}
    return evaluate_tool_call(event=event, workspace=ws, agent="python-sdk", agent_name="freezer",
                              session_id=sid, resource={"kind": "account", "id": "ACC-1",
                                                        "attr": {"status": status}},
                              register_agent=False, flush_at_exit=False)


def _trail():
    from prismor.runtime.enterprise import audit_trail
    return [json.loads(l) for l in audit_trail.trail_path().read_text().splitlines()]


def test_every_record_has_authority_that_survives_profile_change(env):
    from prismor.runtime.enterprise import authority
    _call(env, "active")
    (env / ".prismor" / "iam.yaml").write_text(IAM.format(allowed="Edit"))
    _call(env, "active")
    first, second = [r for r in _trail() if r["record_type"] == "action"][-2:]
    assert first["authority_hash"] and second["authority_hash"]
    snap = authority.load(first["authority_hash"])
    assert snap["iam_profile"]["id"] == "reviewer"
    assert "Bash" in snap["iam_profile"]["allowed_tools"]
    assert first["authority_hash"] != second["authority_hash"]
    assert "Edit" in authority.load(second["authority_hash"])["iam_profile"]["allowed_tools"]
    assert "Bash" in authority.load(first["authority_hash"])["iam_profile"]["allowed_tools"]


def test_authority_hash_is_in_the_record_hash(env):
    from prismor.runtime.enterprise import audit_trail
    _call(env, "active")
    rec = _trail()[-1]
    rec["authority_hash"] = "0" * 64
    assert audit_trail.compute_hash(rec) != rec["hash"]


def test_export_then_verify_offline(env, tmp_path):
    from prismor.runtime.enterprise import evidence_pack
    _call(env, "active")
    _call(env, "restricted")
    _call(env, "active", sid="other")
    pack = tmp_path / "pack"
    man = evidence_pack.export(pack, session="s1")
    assert man["decisions"] == 2 and not man["missing_authority"]
    decisions = [json.loads(l) for l in (pack / "decisions.jsonl").read_text().splitlines()]
    assert [d["enforcement_outcome"] for d in decisions] == ["allowed", "refused"]
    assert decisions[1]["refusing_rule"] == "t-restricted"
    assert decisions[1]["resource"]["attr"]["status"] == "restricted"
    for d in decisions:
        assert (pack / "authority" / f"{d['authority_hash']}.json").is_file()
    assert "t-restricted" in (pack / "timeline.md").read_text()
    rep = evidence_pack.verify_pack(pack)
    assert rep["ok"], rep["errors"]
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads((_REPO / "docs" / "schemas" / "decisions.schema.json").read_text())
    for d in decisions:
        jsonschema.validate(d, schema)


def _pack(env, tmp_path):
    from prismor.runtime.enterprise import evidence_pack
    _call(env, "restricted")
    pack = tmp_path / "pack"
    evidence_pack.export(pack, session="s1")
    return evidence_pack, pack


def test_edited_decision_fails(env, tmp_path):
    ep, pack = _pack(env, tmp_path)
    p = pack / "decisions.jsonl"
    p.write_text(p.read_text().replace('"refused"', '"allowed"'))
    rep = ep.verify_pack(pack)
    assert not rep["ok"] and any("decisions.jsonl" in e for e in rep["errors"])


def test_edited_snapshot_fails(env, tmp_path):
    ep, pack = _pack(env, tmp_path)
    snap = next((pack / "authority").glob("*.json"))
    data = json.loads(snap.read_text())
    data["iam_profile"]["deny_tools"] = []
    snap.write_text(json.dumps(data))
    errs = ep.verify_pack(pack)["errors"]
    assert any("does not match its hash" in e for e in errs)


def test_edited_record_fails_even_with_rebuilt_manifest(env, tmp_path):
    """Rewriting a record and re-hashing the manifest still fails: the
    record's own chain hash no longer matches."""
    ep, pack = _pack(env, tmp_path)
    p = pack / "records.jsonl"
    rec = json.loads(p.read_text().splitlines()[0])
    rec["verdict"] = "allowed"
    p.write_text(json.dumps(rec) + "\n")
    errs = ep.verify_pack(pack)["errors"]
    assert any("hash mismatch" in e for e in errs)


def test_cli_export_and_verify(env, tmp_path, capsys):
    import argparse
    from prismor.runtime import cli
    _call(env, "active")
    out = tmp_path / "cli-pack"
    cli._run_trail(argparse.Namespace(trail_command="export", session="s1", since=None, until=None,
                                      out=str(out), verify=None, pubkey=None, json=False))
    assert "wrote 1 decisions" in capsys.readouterr().out
    with pytest.raises(SystemExit) as code:
        cli._run_trail(argparse.Namespace(trail_command="export", verify=str(out), pubkey=None, json=False))
    assert code.value.code == 0
