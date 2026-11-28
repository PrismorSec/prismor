"""`prismor explain` re-runs a recorded event and says whether the cloak
wrapper unwrapped, which rule fires now, and the machine's shell."""
import pathlib
import tempfile

import pytest

from prismor.runtime import explain_event

HOOKS = "/Users/me/.local/pipx/venvs/prismor/lib/python3.14/site-packages/prismor/runtime/cloaking/hooks"


@pytest.fixture
def vault(monkeypatch):
    v = tempfile.mkdtemp(prefix="prismor-vault-")
    monkeypatch.setenv("PRISMOR_SECRETS_DIR", v)
    return v


def _fake_session(monkeypatch, cmds, recorded_index):
    session = {
        "events": [{"raw": {"type": "shell", "tool_name": "Bash", "command": c}} for c in cmds],
        "findings": [{"eventIndex": recorded_index, "severity": "CRITICAL",
                      "title": "Access to Prismor plaintext secret vault", "evidence": "..."}],
    }
    monkeypatch.setattr("prismor.runtime.store.get_session", lambda ws, sid: session)


def test_broken_wrapper_is_explained(monkeypatch, vault, tmp_path):
    broken = ("{ __prismor_cmd=$'echo \\'a �\\200\\224 b\\''; eval \"$__prismor_cmd\"$'\\n'; }"
              f" 2>&1 | PRISMOR_SECRETS_DIR={vault} PRISMOR_CLOAK_SESSION=s1 {HOOKS}/scrub-stream.sh; exit ${{PIPESTATUS[0]}}")
    _fake_session(monkeypatch, ["ls", broken], 1)
    info = explain_event.explain(tmp_path, "s1")
    assert [e["index"] for e in info["events"]] == [1]
    ev = info["events"][0]
    assert ev["cloak_wrapper"] == "does not unwrap"
    assert any(f["ruleId"] == "prismor-vault-access" and f["title"].startswith("Prismor could not unwrap")
               for f in ev["now"])
    assert set(info["shell"]) == {"bash", "locale"}
    text = explain_event.format_explain(info)
    assert "cloak wrapper: does not unwrap" in text and "\n#1 shell Bash" in text


def test_clean_wrapper_unwraps_and_is_allowed(monkeypatch, vault, tmp_path):
    ok = ("{ __prismor_cmd=$'ls -la'; eval \"$__prismor_cmd\"$'\\n'; }"
          f" 2>&1 | PRISMOR_SECRETS_DIR={vault} PRISMOR_CLOAK_SESSION=s1 {HOOKS}/scrub-stream.sh; exit ${{PIPESTATUS[0]}}")
    _fake_session(monkeypatch, [ok], 0)
    ev = explain_event.explain(tmp_path, "s1", event=0)["events"][0]
    assert ev["cloak_wrapper"] == "unwraps now"
    assert not any(f.get("ruleId") == "prismor-vault-access" for f in ev["now"])


def test_unknown_session_or_event(monkeypatch, tmp_path):
    monkeypatch.setattr("prismor.runtime.store.get_session", lambda ws, sid: None)
    with pytest.raises(LookupError):
        explain_event.explain(tmp_path, "nope")
    _fake_session(monkeypatch, ["ls"], 0)
    with pytest.raises(LookupError):
        explain_event.explain(tmp_path, "s1", event=5)


def test_device_status_reports_shell(monkeypatch):
    from prismor.runtime.enterprise import heartbeat
    monkeypatch.setenv("LC_ALL", "en_US.UTF-8")
    rec = heartbeat.device_status_record()
    shell = rec["detail"]["shell"]
    assert shell["locale"] == "en_US.UTF-8"
    assert shell["bash"] is None or shell["bash"][0].isdigit()
