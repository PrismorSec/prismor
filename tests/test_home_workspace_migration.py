"""Workspace == $HOME: ~/.prismor is the live store, so the one-time legacy
migration must not treat it as a source and re-run on every hook call."""
from prismor.runtime import store


def test_home_workspace_migrates_once(tmp_path, monkeypatch):
    home = tmp_path / ".prismor"
    monkeypatch.setattr(store, "prismor_home", lambda: home)
    (tmp_path / ".prismor-warden").mkdir()
    (tmp_path / ".prismor-warden" / "warden.db").write_bytes(b"")
    calls = []
    monkeypatch.setattr(store, "_merge_sqlite_db_once", lambda s, d: calls.append(s))

    store.get_data_dir(tmp_path)
    assert calls and all(c.parent != home for c in calls)

    # The live store changes under normal use; that must not re-trigger the merge.
    (home / "sessions").mkdir(exist_ok=True)
    (home / "sessions" / "s.jsonl").write_text("{}\n")
    calls.clear()
    store.get_data_dir(tmp_path)
    assert calls == []
