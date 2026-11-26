"""GHSA-v6vw-pfgj-4mg8: what an open unlock window lifts, and that the lift is
in the signed trail. Drives the real hook-dispatch in a subprocess."""
import json
import os
import subprocess
import sys

root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, root)


def _dispatch(tmp_path, command, cwd=None, pinned=True):
    env = {k: v for k, v in os.environ.items() if not k.startswith("PRISMOR_")}
    env.update(HOME=str(tmp_path), PRISMOR_HOME=str(tmp_path / "home"))
    boot = f"import sys; sys.path.insert(0, {root!r}); from prismor.runtime.immunity_cli import main; main(sys.argv[1:])"
    payload = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "session_id": "s1",
               "cwd": str(cwd or tmp_path), "tool_input": {"command": command}}
    return subprocess.run(
        [sys.executable, "-c", boot, "hook-dispatch", "--agent", "claude",
         *(["--workspace", str(tmp_path)] if pinned else []), "--mode", "enforce"],
        input=json.dumps(payload), capture_output=True, text=True, env=env, cwd=tmp_path, timeout=60)


def _open_window(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / "home"))
    from prismor.runtime import unlock
    unlock.set_password("correct horse battery")
    unlock.open_window(workspace=tmp_path)
    assert unlock.is_open(tmp_path)


def _trail(tmp_path):
    p = tmp_path / "home" / "audit" / "trail.jsonl"
    return [json.loads(l) for l in p.read_text().splitlines()] if p.exists() else []


def test_window_lifts_policy_edit_and_signs_the_lift(tmp_path, monkeypatch):
    _open_window(tmp_path, monkeypatch)
    r = _dispatch(tmp_path, "prismor allow risky-write --off --yes")
    assert r.returncode == 0, r.stderr
    lifts = [x for x in _trail(tmp_path)
             if x.get("record_type") == "approval" and x.get("status") == "unlock_window"]
    assert lifts and lifts[0]["rules"] == ["prismor-self-edit"]


def test_window_never_lifts_credential_or_trail(tmp_path, monkeypatch):
    _open_window(tmp_path, monkeypatch)
    for command in ("cat ~/.prismor/unlock.json",
                    "echo '{}' > ~/.prismor/unlock-grant.json",
                    "cat ~/.prismor/receipt_signing_key.pem",
                    "rm ~/.prismor/audit/trail.jsonl",
                    "cat ~/.prismor/pause.key"):
        assert _dispatch(tmp_path, command).returncode == 2, command


def test_closed_window_still_blocks(tmp_path):
    assert _dispatch(tmp_path, "prismor allow risky-write --off --yes").returncode == 2


# The window's folder: `prismor unlock` and a global hook (no --workspace) must
# resolve it the same way, or the window a person opened is ignored.
EDIT = "prismor allow risky-write --off --yes"


def _policy_dir(path):
    (path / ".prismor").mkdir(parents=True)
    (path / ".prismor" / "policy.yaml").write_text("{}\n")
    return path


def _open_from(tmp_path, monkeypatch, where):
    """`prismor unlock` typed in ``where``."""
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("HOME", str(tmp_path))
    from prismor.runtime import unlock
    from prismor.runtime.store import infer_default_workspace
    unlock.set_password("correct horse battery")
    unlock.open_window(workspace=infer_default_workspace(where))


def test_window_covers_subfolder_of_policy_dir_without_git(tmp_path, monkeypatch):
    sub = _policy_dir(tmp_path / "proj") / "sub"
    sub.mkdir()
    _open_from(tmp_path, monkeypatch, sub)
    r = _dispatch(tmp_path, EDIT, cwd=sub, pinned=False)
    assert r.returncode == 0, r.stderr


def test_window_covers_nested_policy_dir_inside_git_repo(tmp_path, monkeypatch):
    (tmp_path / "repo" / ".git").mkdir(parents=True)
    nested = _policy_dir(tmp_path / "repo" / "nested")
    _open_from(tmp_path, monkeypatch, nested)
    r = _dispatch(tmp_path, EDIT, cwd=nested, pinned=False)
    assert r.returncode == 0, r.stderr


def test_window_does_not_cover_other_folders_and_names_its_own(tmp_path, monkeypatch):
    proj = _policy_dir(tmp_path / "proj")
    (proj / "inner" / ".git").mkdir(parents=True)
    _policy_dir(proj / "other")
    (tmp_path / "unrelated").mkdir()
    # A repo that happens to be called "prismor" has a runtime/ folder: that
    # must not resolve to the folder holding the repo.
    (proj / "prismor" / ".git").mkdir(parents=True)
    (proj / "prismor" / "runtime").mkdir()
    _open_from(tmp_path, monkeypatch, proj)
    for cwd in (proj / "inner", proj / "other", tmp_path / "unrelated",
                proj / "prismor" / "runtime"):
        r = _dispatch(tmp_path, EDIT, cwd=cwd, pinned=False)
        assert r.returncode == 2, cwd
        assert f"covers {proj.resolve()}" in r.stdout + r.stderr, (cwd, r.stdout, r.stderr)


def test_no_unlock_hint_for_what_no_window_lifts(tmp_path, monkeypatch):
    proj = _policy_dir(tmp_path / "proj")
    (tmp_path / "unrelated").mkdir()
    _open_from(tmp_path, monkeypatch, proj)
    r = _dispatch(tmp_path, "cat ~/.prismor/unlock.json", cwd=tmp_path / "unrelated", pinned=False)
    assert r.returncode == 2
    assert "covers" not in r.stdout + r.stderr
