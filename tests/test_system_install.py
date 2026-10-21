"""System (machine-wide) install: one root setup governs every user (Linux).

SYSTEM_DIR and the agents' system hook paths are redirected into tmp_path, so
these run unprivileged; the root/Linux gate itself is checked separately.
"""
from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from prismor.runtime import hooks, system_install


@pytest.fixture
def sysdir(tmp_path, monkeypatch):
    d = tmp_path / "etc-prismor"
    monkeypatch.setattr(system_install, "SYSTEM_DIR", d)
    monkeypatch.setattr(hooks, "SYSTEM_HOOK_PATHS", {
        "claude": tmp_path / "etc-claude-code" / "managed-settings.d" / "50-prismor.json",
        "cursor": tmp_path / "etc-cursor" / "hooks.json",
        "gemini": tmp_path / "etc-gemini-cli" / "settings.json",
    })
    return d


def _manage(d: Path) -> None:
    d.mkdir(parents=True, exist_ok=True)
    (d / "system.json").write_text("{}", encoding="utf-8")


def test_unmanaged_machine_keeps_per_user_paths(sysdir):
    from prismor.runtime import pause, unlock
    from prismor.runtime.enterprise import identity
    from prismor.runtime.store import prismor_home
    assert not system_install.is_system_managed()
    assert identity.identity_path() == prismor_home() / "identity.json"
    assert pause.pause_path() == prismor_home() / "pause.json"
    assert unlock.credential_path() == prismor_home() / "unlock.json"


def test_managed_machine_moves_policy_state_under_system_dir(sysdir):
    from prismor.runtime import floor_off, pause, store, unlock
    from prismor.runtime.enterprise import identity
    _manage(sysdir)
    for path in (identity.identity_path(), pause.pause_path(), unlock.credential_path(),
                 unlock.grant_path(), floor_off.path(), store._global_policy_path()):
        assert path.parent == sysdir, path


def test_managed_identity_and_pause_are_world_readable(sysdir):
    from prismor.runtime import pause
    from prismor.runtime.enterprise import identity
    _manage(sysdir)
    p = identity.save_identity({"device_id": "d", "device_key": "prism_dev_x"})
    assert stat.S_IMODE(p.stat().st_mode) == 0o600  # the key is admin-only
    assert identity.load_identity()["device_id"] == "d"
    pause.set_paused(60)
    assert stat.S_IMODE(pause.pause_path().stat().st_mode) == 0o644


def test_user_policy_file_cannot_weaken_a_system_selection(sysdir, tmp_path, monkeypatch):
    from prismor.runtime.enterprise import workspace_scope
    from prismor.runtime.policy_engine import PolicyEngine
    from prismor.runtime.setup_wizard import _render_selection_policy
    from prismor.runtime.store import prismor_home
    monkeypatch.setattr(workspace_scope, "is_managed", lambda _ws: False)
    ws = tmp_path / "ws"
    ws.mkdir()

    def mode(rule_id):
        eng = PolicyEngine(workspace=ws)
        return eng._resolve_mode(next(r for r in eng.rules if r.id == rule_id))

    # The user's own file selects nothing, so under it the rule only observes.
    prismor_home().mkdir(parents=True, exist_ok=True)
    (prismor_home() / "policy.yaml").write_text(_render_selection_policy([]), encoding="utf-8")
    assert mode("destructive-command") != "enforce"
    _manage(sysdir)
    (sysdir / "policy.yaml").write_text(_render_selection_policy(["destructive-command"]), encoding="utf-8")
    assert mode("destructive-command") == "enforce"


def test_system_hooks_install_readable_and_uninstall(sysdir, tmp_path):
    _manage(sysdir)
    repo_root = Path(__file__).resolve().parent.parent
    res = hooks.install_hooks(repo_root=repo_root, workspace=Path("/"), agent="all",
                              scope="system", mode="enforce")
    assert {r["agent"] for r in res} == {"claude", "cursor", "gemini"}
    claude = hooks.SYSTEM_HOOK_PATHS["claude"]
    cfg = json.loads(claude.read_text())
    cmd = cfg["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
    assert str(sysdir / "hook-dispatch.py") in cmd and "--workspace" not in cmd
    assert stat.S_IMODE(claude.stat().st_mode) == 0o644
    assert stat.S_IMODE((sysdir / "hook-dispatch.py").stat().st_mode) == 0o644
    assert hooks.hook_installed("claude", "system", tmp_path)
    hooks.uninstall_hooks(repo_root=repo_root, workspace=Path("/"), agent="all", scope="system")
    assert not hooks.hook_installed("claude", "system", tmp_path)


def test_system_scope_rejects_agents_without_a_machine_location(sysdir):
    with pytest.raises(ValueError, match="no machine-wide hook location"):
        hooks._config_path("windsurf", "system", Path("/"))


def test_unreadable_interpreter_is_caught(tmp_path):
    if system_install.unreadable_by_others(tmp_path) is not None:
        pytest.skip("tmp dir is private (macOS per-user TMPDIR)")
    private = tmp_path / "root-home"
    (private / "bin").mkdir(parents=True)
    py = private / "bin" / "python3"
    py.write_text("", encoding="utf-8")
    py.chmod(0o755)
    assert system_install.unreadable_by_others(py) is None
    private.chmod(0o700)
    try:
        assert system_install.unreadable_by_others(py) == private
    finally:
        private.chmod(0o755)


@pytest.mark.skipif(os.name == "nt", reason="geteuid is POSIX")
def test_system_install_refuses_without_root(monkeypatch):
    monkeypatch.setattr(system_install.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(system_install.sys, "platform", "linux")
    assert "root" in system_install.check_supported()


def test_permission_hint_only_for_system_files(sysdir):
    err = PermissionError(13, "Permission denied", str(sysdir / "pause.json"))
    assert "system-wide" in system_install.permission_hint(err)
    assert system_install.permission_hint(PermissionError(13, "x", "/tmp/other")) is None


def test_enroll_status_exits_nonzero_when_not_enrolled(tmp_path):
    from prismor.runtime import cli
    with pytest.raises(SystemExit) as exc:
        cli.main(["--workspace", str(tmp_path), "enroll-status"])
    assert exc.value.code == 1


def test_mkdir_public_opens_every_created_dir_under_strict_umask(tmp_path):
    old = os.umask(0o077)
    try:
        target = tmp_path / "etc-claude-code" / "managed-settings.d"
        system_install.mkdir_public(target)
    finally:
        os.umask(old)
    for d in (target, target.parent):
        assert stat.S_IMODE(d.stat().st_mode) == 0o755, d


def test_pause_is_root_only_on_a_system_install(sysdir, tmp_path, monkeypatch):
    from prismor.runtime import cli
    _manage(sysdir)
    monkeypatch.setattr(system_install.os, "geteuid", lambda: 1000)
    assert "admin-only" in cli._pause_refusal("pause", tmp_path)
    monkeypatch.setattr(system_install.os, "geteuid", lambda: 0)
    assert cli._pause_refusal("pause", tmp_path) is None  # MDM script: no terminal needed


def _codex_req(sysdir, tmp_path, monkeypatch):
    path = tmp_path / "etc-codex" / "requirements.toml"
    hooks.SYSTEM_HOOK_PATHS["codex"] = path
    _manage(sysdir)
    return path


def _install_codex():
    repo_root = Path(__file__).resolve().parent.parent
    return hooks.install_hooks(repo_root=repo_root, workspace=Path("/"), agent="codex",
                               scope="system", mode="enforce")


def test_codex_requirements_written_as_managed_hooks(sysdir, tmp_path, monkeypatch):
    path = _codex_req(sysdir, tmp_path, monkeypatch)
    _install_codex()
    data = hooks._toml_loads(path.read_text())
    assert data["features"]["hooks"] is True
    assert data["hooks"]["managed_dir"] == str(sysdir)
    cmd = data["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
    assert str(sysdir / "hook-dispatch.py") in cmd and "--agent codex" in cmd
    assert stat.S_IMODE(path.stat().st_mode) == 0o644
    _install_codex()  # idempotent: one block, still valid TOML
    assert path.read_text().count(hooks._CODEX_REQ_BEGIN) == 1


def test_codex_keeps_an_orgs_requirements_and_uninstalls_cleanly(sysdir, tmp_path, monkeypatch):
    path = _codex_req(sysdir, tmp_path, monkeypatch)
    path.parent.mkdir(parents=True)
    path.write_text('allowed_sandbox_modes = ["read-only"]\n')
    _install_codex()
    assert hooks._toml_loads(path.read_text())["allowed_sandbox_modes"] == ["read-only"]
    hooks.uninstall_hooks(repo_root=Path("."), workspace=Path("/"), agent="codex", scope="system")
    assert path.read_text() == 'allowed_sandbox_modes = ["read-only"]\n'


def test_codex_refuses_to_redeclare_an_orgs_hooks_table(sysdir, tmp_path, monkeypatch):
    path = _codex_req(sysdir, tmp_path, monkeypatch)
    path.parent.mkdir(parents=True)
    original = "[features]\nhooks = false\n"
    path.write_text(original)
    with pytest.raises(ValueError, match="Merge this into it by hand"):
        _install_codex()
    assert path.read_text() == original


def test_device_key_is_admin_only_and_users_see_a_keyless_identity(sysdir, monkeypatch):
    from prismor.runtime.enterprise import identity
    _manage(sysdir)
    p = identity.save_identity({"device_id": "d1", "org_id": "o1", "device_key": "prism_dev_secret"})
    assert stat.S_IMODE(p.stat().st_mode) == 0o600
    public = sysdir / "identity-public.json"
    assert stat.S_IMODE(public.stat().st_mode) == 0o644
    assert "prism_dev_secret" not in public.read_text()
    # A user's process can't read the private file: no key, still enrolled.
    monkeypatch.setattr(identity, "load_identity", lambda: None)
    assert identity.keyless_identity()["device_id"] == "d1"
    assert identity.is_enrolled()


def test_keyless_user_spools_telemetry_instead_of_calling_out(sysdir, monkeypatch):
    import urllib.request
    from prismor.runtime import sinks
    from prismor.runtime.enterprise import identity, telemetry_spool
    _manage(sysdir)
    identity.save_identity({"device_id": "d1", "org_id": "o1", "device_key": "k"})
    monkeypatch.setattr(identity, "load_identity", lambda: None)
    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: (_ for _ in ()).throw(AssertionError("network")))
    sinks.upload_telemetry([{"id": "e1", "verdict": "blocked"}])
    assert telemetry_spool.pending_count() == 1


def test_system_sync_uploads_every_users_spool(sysdir, tmp_path, monkeypatch):
    from prismor.runtime import sinks
    from prismor.runtime.enterprise import identity, remote_policy, telemetry_spool
    _manage(sysdir)
    identity.save_identity({"device_id": "d1", "org_id": "o1", "device_key": "k"})
    homes = []
    for user in ("alice", "bob"):
        h = tmp_path / user / ".prismor"
        h.mkdir(parents=True)
        monkeypatch.setenv("PRISMOR_HOME", str(h))
        telemetry_spool.append([{"id": f"{user}-1"}, {"id": f"{user}-2"}])
        homes.append(h)
    monkeypatch.delenv("PRISMOR_HOME")
    monkeypatch.setattr(system_install, "user_prismor_homes", lambda: homes)
    monkeypatch.setattr(remote_policy, "fetch", lambda force=False: True)
    sent = []

    def fake_upload(records, **_):
        sent.extend(telemetry_spool.drain(500) + records)
    monkeypatch.setattr(sinks, "upload_telemetry", fake_upload)
    res = system_install.sync()
    assert res["policy_pulled"] and res["homes"] == 2
    assert res["pending_before"] == 4 and res["pending_after"] == 0
    assert sorted(r["id"] for r in sent if "id" in r) == ["alice-1", "alice-2", "bob-1", "bob-2"]
    assert [r.get("type") for r in sent].count("device_status") == 1  # the machine's own status


def test_repo_policy_file_is_ignored_unless_admin_allows_it(sysdir, tmp_path, monkeypatch):
    from prismor.runtime.enterprise import workspace_scope
    from prismor.runtime.policy_engine import PolicyEngine
    from prismor.runtime.setup_wizard import _render_selection_policy
    monkeypatch.setattr(workspace_scope, "is_managed", lambda _ws: False)
    ws = tmp_path / "repo"
    (ws / ".prismor").mkdir(parents=True)
    (ws / ".prismor" / "policy.yaml").write_text(_render_selection_policy([]), encoding="utf-8")
    _manage(sysdir)
    sel = _render_selection_policy(["destructive-command"])

    (sysdir / "policy.yaml").write_text(sel, encoding="utf-8")
    eng = PolicyEngine(workspace=ws)
    assert eng.project_policy_ignored == str(ws / ".prismor" / "policy.yaml")
    assert eng._resolve_mode(next(r for r in eng.rules if r.id == "destructive-command")) == "enforce"
    (sysdir / "policy.yaml").write_text(sel.replace("settings:\n", "settings:\n  allow_project_policy: true\n"),
                                        encoding="utf-8")
    assert PolicyEngine(workspace=ws).project_policy_ignored is None


def test_local_agents_yaml_cannot_switch_an_agent_to_observe(sysdir, tmp_path):
    from prismor.runtime import agents
    from prismor.runtime.store import prismor_home
    prismor_home().mkdir(parents=True, exist_ok=True)
    (prismor_home() / "agents.yaml").write_text("agents:\n  claude:\n    mode: observe\n", encoding="utf-8")
    agents._CONFIG_CACHE.clear()
    assert agents.resolve_agent_control("claude", tmp_path).mode == "observe"
    _manage(sysdir)
    agents._CONFIG_CACHE.clear()
    assert agents.resolve_agent_control("claude", tmp_path).mode is None


def test_system_install_forbids_personal_workspaces(sysdir):
    from prismor.runtime.enterprise import workspace_scope
    assert workspace_scope.org_allows_personal()
    _manage(sysdir)
    assert not workspace_scope.org_allows_personal()


def test_block_message_points_users_at_their_admin(sysdir, monkeypatch):
    from prismor.runtime import unblock
    _manage(sysdir)
    monkeypatch.setattr(system_install, "is_elevated", lambda: False)
    text = unblock.format_unblock({"ruleId": "destructive-command", "severity": "critical"})
    assert "administrator" in text
    assert "prismor allow" not in text and "prismor unlock" not in text
