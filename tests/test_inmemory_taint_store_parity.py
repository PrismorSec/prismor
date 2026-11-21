"""GHSA-5vjv-5xrf-37jj: InMemoryTaintStore lacked the provenance surface, so
data-boundary screening raised AttributeError and skipped itself."""

import inspect

from prismor.runtime.policy_engine import InMemoryTaintStore, _TaintStore


def test_in_memory_store_has_disk_store_surface():
    public = {n for n, _ in inspect.getmembers(_TaintStore) if not n.startswith("_")}
    missing = public - {n for n in dir(InMemoryTaintStore) if not n.startswith("_")}
    assert not missing, f"InMemoryTaintStore missing {sorted(missing)}"
    store = InMemoryTaintStore()
    assert store.sources == [] and store.installed == set()


def test_in_memory_store_provenance_lifecycle():
    store = InMemoryTaintStore()
    assert store.latest_source(0) is None
    store.add_source("skill", "https://x.test/SKILL.md", "X.test", 3)
    store.add_installed(["Jq", ""])
    assert store.latest_source(5)["host"] == "x.test"
    assert store.latest_source(100) is None  # decayed past the window
    assert store.installed == {"jq"}


def test_data_boundary_runs_with_in_memory_store(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / "home"))
    from prismor.runtime.hooks import normalize_payload
    from prismor.runtime.runtime import evaluate_tool_call

    ws = tmp_path / "ws"
    ws.mkdir()
    payload = {
        "hook_event_name": "PreToolUse", "tool_name": "Bash",
        "tool_input": {"command": "cat docs/fixture-public.txt"},
        "session_id": "p005", "cwd": str(ws), "timestamp": "2026-10-15T00:00:00Z",
    }
    event = normalize_payload(agent="claude", payload=payload, workspace=ws)["event"]
    evaluate_tool_call(
        event=event, workspace=ws, repo_root=ws, agent="claude", mode="enforce",
        session_id="p005", persist=False, record=False, register_agent=False,
        flush_at_exit=False, taint_store=InMemoryTaintStore(), explain=True,
    )
    assert "data_boundary evaluation error" not in capsys.readouterr().err
