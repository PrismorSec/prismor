"""Tests for shadow-AI remediation (runtime/remediate.py).

This module writes to the developer's agent config files, so the tests care
about two things above all: that it never claims a fix it did not make, and
that it never touches something it was not asked to.

Every lever is stubbed here — installing real hooks, migrating a real gateway
and vaulting real keys are covered by their own suites. What is under test is
the decision layer: what gets planned, what gets refused and why, and what the
caller is told afterwards.

Run: python3 -m pytest tests/test_remediate.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO))

from prismor.runtime import remediate  # noqa: E402


# ── fixtures ─────────────────────────────────────────────────────────────────

def agent(name="Cursor", agent_id="cursor", managed=False, coverable=True):
    return {"id": agent_id, "name": name, "managed": managed, "coverable": coverable}


def mcp(name="weather", source="/ws/.mcp.json", managed=False, is_gateway=False):
    return {"name": name, "source": source, "managed": managed, "is_gateway": is_gateway}


def write_mcp_config(tmp_path, name=".mcp.json", key="mcpServers",
                     servers=None, raw=None):
    """A real config on disk. Planning reads the file to decide whether its
    shape can be rewritten, so a fabricated path would always read as
    unmigratable."""
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    if raw is not None:
        path.write_text(raw, encoding="utf-8")
    else:
        body = servers if servers is not None else {"weather": {"command": "npx"}}
        path.write_text(json.dumps({key: body}), encoding="utf-8")
    return str(path)


def cred(provider="openai", location="/ws/.env", kind="file", managed=False):
    return {"provider": provider, "location": location,
            "location_kind": kind, "managed": managed}


def report(agents=(), servers=(), creds=()):
    return {"agents": list(agents), "mcp": list(servers), "credentials": list(creds)}


# ── planning: agents ─────────────────────────────────────────────────────────

class TestPlanAgents:
    def test_unhooked_agent_is_planned(self):
        p = remediate.plan(report(agents=[agent()]))
        assert len(p.fixable) == 1
        action = p.fixable[0]
        assert action.kind == "agent" and action.subject == "cursor"
        assert "install-hooks" in action.command

    def test_governed_agent_is_left_alone(self):
        assert remediate.plan(report(agents=[agent(managed=True)])).actions == []

    def test_agent_without_a_hook_surface_is_refused_with_a_reason(self):
        # Warp/Trae have no hook Prismor can install. Planning one
        # would produce a fix that silently does nothing.
        p = remediate.plan(report(agents=[agent("Warp", "warp", coverable=False)]))
        assert p.fixable == []
        assert len(p.skipped) == 1
        assert "no hook" in p.skipped[0].detail

    def test_subject_is_the_agent_id_not_the_display_name(self):
        # install_hooks takes the registry id; passing "Gemini CLI (Google)"
        # would fail on an agent whose display name has spaces or parentheses.
        p = remediate.plan(report(agents=[agent("Gemini CLI (Google)", "gemini")]))
        assert p.fixable[0].subject == "gemini"


# ── planning: MCP ────────────────────────────────────────────────────────────

class TestPlanMcp:
    def test_workspace_mcp_json_is_planned(self, tmp_path):
        src = write_mcp_config(tmp_path)
        p = remediate.plan(report(servers=[mcp(source=src)]))
        assert len(p.fixable) == 1 and p.fixable[0].kind == "mcp"
        assert p.fixable[0].subject == src

    def test_a_cursor_config_is_now_migratable(self, tmp_path):
        """Regression: servers declared outside the workspace .mcp.json were
        found by discovery and then refused, so most of what the sweep reported
        could never be governed."""
        src = write_mcp_config(tmp_path, name=".cursor/mcp.json")
        p = remediate.plan(report(servers=[mcp("context7", source=src)]))
        assert len(p.fixable) == 1

    def test_vscode_servers_key_is_recognised(self, tmp_path):
        src = write_mcp_config(tmp_path, name=".vscode/mcp.json", key="servers")
        assert len(remediate.plan(report(servers=[mcp(source=src)])).fixable) == 1

    def test_a_toml_config_is_refused(self, tmp_path):
        src = str(tmp_path / "config.toml")
        Path(src).write_text('[mcp_servers.weather]\ncommand = "npx"\n', encoding="utf-8")
        p = remediate.plan(report(servers=[mcp(source=src)]))
        assert p.fixable == [] and "TOML" in p.skipped[0].detail

    def test_an_unrecognised_block_is_refused(self, tmp_path):
        """Zed declares servers under context_servers. Rewriting a shape we do
        not understand risks destroying the developer's config."""
        src = write_mcp_config(tmp_path, name="settings.json", key="context_servers")
        p = remediate.plan(report(servers=[mcp(source=src)]))
        assert p.fixable == [] and "recognised" in p.skipped[0].detail

    def test_unparseable_json_is_refused(self, tmp_path):
        src = write_mcp_config(tmp_path, name="broken.json", raw="{oops")
        p = remediate.plan(report(servers=[mcp(source=src)]))
        assert p.fixable == [] and "could not be parsed" in p.skipped[0].detail

    def test_a_vanished_file_is_refused(self, tmp_path):
        p = remediate.plan(report(servers=[mcp(source=str(tmp_path / "gone.json"))]))
        assert p.fixable == [] and "no longer exists" in p.skipped[0].detail

    def test_the_shape_is_checked_once_per_file(self, tmp_path, monkeypatch):
        src = write_mcp_config(tmp_path, servers={"a": {}, "b": {}, "c": {}})
        calls = []
        real = remediate._why_not_migratable
        monkeypatch.setattr(remediate, "_why_not_migratable",
                            lambda p: calls.append(p) or real(p))
        remediate.plan(report(servers=[mcp("a", src), mcp("b", src), mcp("c", src)]))
        assert len(calls) == 1

    def test_gateway_entry_is_not_remediated(self):
        assert remediate.plan(report(servers=[mcp(is_gateway=True)])).actions == []

    def test_already_governed_server_is_not_remediated(self):
        assert remediate.plan(report(servers=[mcp(managed=True)])).actions == []


# ── planning: credentials ────────────────────────────────────────────────────

class TestPlanCredentials:
    def test_dotenv_is_planned(self):
        p = remediate.plan(report(creds=[cred()]))
        assert len(p.fixable) == 1 and p.fixable[0].subject == "/ws/.env"

    def test_env_var_is_refused(self):
        # A key exported in the shell cannot be reached from here.
        p = remediate.plan(report(creds=[
            cred(location="OPENAI_API_KEY", kind="env")]))
        assert p.fixable == []
        assert "environment" in p.skipped[0].detail

    @pytest.mark.parametrize("location", [
        "/ws/config.json", "/ws/settings.json", "/home/u/.codex/auth.json",
    ])
    def test_non_dotenv_file_is_refused(self, location):
        # add_env_secrets parses dotenv only; a JSON config would raise.
        p = remediate.plan(report(creds=[cred(location=location)]))
        assert p.fixable == []
        assert "not a dotenv" in p.skipped[0].detail

    @pytest.mark.parametrize("location", ["/ws/.env", "/ws/.env.local", "/ws/.env.production"])
    def test_dotenv_variants_are_accepted(self, location):
        assert len(remediate.plan(report(creds=[cred(location=location)])).fixable) == 1

    def test_cloaked_credential_is_left_alone(self):
        assert remediate.plan(report(creds=[cred(managed=True)])).actions == []


# ── planning: scoping ────────────────────────────────────────────────────────

def test_kinds_limits_what_is_planned(tmp_path):
    full = report(agents=[agent()], servers=[mcp(source=write_mcp_config(tmp_path))],
                  creds=[cred()])
    assert {a.kind for a in remediate.plan(full).fixable} == {"agent", "mcp", "credential"}
    assert {a.kind for a in remediate.plan(full, kinds=("agent",)).fixable} == {"agent"}


def test_plan_touches_nothing(tmp_path, monkeypatch):
    """Planning must be pure — the CLI shows it before asking for consent."""
    called = []
    monkeypatch.setattr(remediate, "_fix_agent", lambda *a, **k: called.append("agent"))
    remediate.plan(report(agents=[agent()], servers=[mcp()], creds=[cred()]))
    assert called == []


def test_empty_report_plans_nothing():
    assert remediate.plan(report()).actions == []


# ── applying ─────────────────────────────────────────────────────────────────

@pytest.fixture()
def levers(monkeypatch):
    """Stub the three side-effecting levers and record what they were asked."""
    calls = {"hooks": [], "gateway": [], "cloak": []}

    import prismor.runtime.hooks as hooks_mod
    import prismor.runtime.mcp_gateway as gw_mod
    import prismor.runtime.cloaking as cloak_mod

    monkeypatch.setattr(hooks_mod, "install_hooks",
                        lambda **kw: calls["hooks"].append(kw) or [])
    monkeypatch.setattr(gw_mod, "migrate_config",
                        lambda p: calls["gateway"].append(p) or gw_mod.MigrationResult(
                            p, "migrated", moved=2, detail="moved 2 server(s)"))
    monkeypatch.setattr(cloak_mod, "add_env_secrets",
                        lambda p: calls["cloak"].append(p) or [{"name": "OPENAI_API_KEY"}])
    return calls


def _apply(rep, tmp_path, **kw):
    return remediate.apply(rep, repo_root=tmp_path, workspace=tmp_path, **kw)


class TestApplyAgents:
    def test_installs_the_global_hook(self, levers, tmp_path):
        results = _apply(report(agents=[agent()]), tmp_path)
        assert [r.status for r in results] == ["fixed"]
        kw = levers["hooks"][0]
        assert kw["agent"] == "cursor"
        # Global, not project: the point is to govern the agent wherever it
        # runs, not only in the directory discover happened to be run from.
        assert kw["scope"] == "global"

    def test_mode_is_threaded_through(self, levers, tmp_path):
        _apply(report(agents=[agent()]), tmp_path, mode="enforce")
        assert levers["hooks"][0]["mode"] == "enforce"

    def test_a_malformed_config_fails_that_agent_only(self, levers, tmp_path, monkeypatch):
        import prismor.runtime.hooks as hooks_mod

        def selective(**kw):
            if kw["agent"] == "cursor":
                raise hooks_mod.HookConfigError("/x/hooks.json is not valid JSON")
            levers["hooks"].append(kw)

        monkeypatch.setattr(hooks_mod, "install_hooks", selective)
        results = _apply(report(agents=[agent("Cursor", "cursor"),
                                        agent("Codex", "codex")]), tmp_path)
        by_target = {r.target: r for r in results}
        assert by_target["Cursor"].status == "failed"
        assert "not valid JSON" in by_target["Cursor"].detail
        # The healthy agent still got fixed — one broken config must not
        # abandon the rest of the run.
        assert by_target["Codex"].status == "fixed"

    def test_an_unexpected_error_is_reported_not_raised(self, levers, tmp_path, monkeypatch):
        import prismor.runtime.hooks as hooks_mod
        monkeypatch.setattr(hooks_mod, "install_hooks",
                            lambda **kw: (_ for _ in ()).throw(OSError("read-only fs")))
        results = _apply(report(agents=[agent()]), tmp_path)
        assert results[0].status == "failed" and "read-only" in results[0].detail


class TestApplyMcp:
    def test_migrates_once_per_file_not_once_per_server(self, levers, tmp_path):
        # One migration moves the whole block, so migrating per server would
        # re-run against an already-rewritten file.
        src = write_mcp_config(tmp_path, servers={"a": {}, "b": {}, "c": {}})
        rep = report(servers=[mcp("a", src), mcp("b", src), mcp("c", src)])
        results = _apply(rep, tmp_path)
        assert len(levers["gateway"]) == 1
        assert [r.status for r in results] == ["fixed", "fixed", "fixed"]

    def test_each_distinct_config_is_migrated(self, levers, tmp_path):
        """The point of the change: a Cursor config and a workspace .mcp.json
        are two files and both must be governed."""
        a = write_mcp_config(tmp_path, name=".mcp.json")
        b = write_mcp_config(tmp_path, name=".cursor/mcp.json")
        _apply(report(servers=[mcp("x", a), mcp("y", b)]), tmp_path)
        assert {str(p) for p in levers["gateway"]} == {a, b}

    def test_a_failed_migration_is_not_reported_as_fixed_for_the_rest(
            self, levers, tmp_path, monkeypatch):
        import prismor.runtime.mcp_gateway as gw_mod
        src = write_mcp_config(tmp_path, servers={"a": {}, "b": {}})
        monkeypatch.setattr(gw_mod, "migrate_config",
                            lambda p: gw_mod.MigrationResult(p, "failed",
                                                             detail="not valid JSON"))
        results = _apply(report(servers=[mcp("a", src), mcp("b", src)]), tmp_path)
        # Neither may claim success — the file was never rewritten.
        assert all(r.status == "failed" for r in results)

    def test_one_bad_config_does_not_stop_another(self, levers, tmp_path, monkeypatch):
        import prismor.runtime.mcp_gateway as gw_mod
        good = write_mcp_config(tmp_path, name=".mcp.json")
        bad = write_mcp_config(tmp_path, name=".cursor/mcp.json")
        monkeypatch.setattr(gw_mod, "migrate_config",
                            lambda p: gw_mod.MigrationResult(p, "failed", detail="boom")
                            if str(p) == bad
                            else gw_mod.MigrationResult(p, "migrated", moved=1))
        results = _apply(report(servers=[mcp("x", good), mcp("y", bad)]), tmp_path)
        by = {r.target: r.status for r in results}
        assert by == {"x": "fixed", "y": "failed"}

    def test_a_migration_that_declines_is_reported_as_skipped(
            self, levers, tmp_path, monkeypatch):
        import prismor.runtime.mcp_gateway as gw_mod
        src = write_mcp_config(tmp_path)
        monkeypatch.setattr(gw_mod, "migrate_config",
                            lambda p: gw_mod.MigrationResult(
                                p, "skipped", detail="already behind the gateway"))
        results = _apply(report(servers=[mcp("a", src)]), tmp_path)
        assert results[0].status == "skipped"


class TestApplyCredentials:
    def test_imports_the_dotenv_once(self, levers, tmp_path):
        rep = report(creds=[cred("openai"), cred("anthropic")])  # same file
        results = _apply(rep, tmp_path)
        assert len(levers["cloak"]) == 1
        assert [r.status for r in results] == ["fixed", "fixed"]

    def test_imports_each_distinct_file(self, levers, tmp_path):
        rep = report(creds=[cred("openai", "/ws/.env"),
                            cred("anthropic", "/ws/.env.local")])
        _apply(rep, tmp_path)
        assert {str(p) for p in levers["cloak"]} == {"/ws/.env", "/ws/.env.local"}

    def test_reports_names_never_values(self, levers, tmp_path):
        results = _apply(report(creds=[cred()]), tmp_path)
        assert "@@SECRET:" in results[0].detail
        assert "1 key(s)" in results[0].detail

    def test_a_failed_import_does_not_mark_the_file_done(
            self, levers, tmp_path, monkeypatch):
        import prismor.runtime.cloaking as cloak_mod
        monkeypatch.setattr(cloak_mod, "add_env_secrets",
                            lambda p: (_ for _ in ()).throw(ValueError("empty file")))
        results = _apply(report(creds=[cred("openai"), cred("anthropic")]), tmp_path)
        assert all(r.status == "failed" for r in results)


# ── the report the operator reads ────────────────────────────────────────────

class TestOutcomeReporting:
    def test_skipped_actions_survive_into_the_results(self, levers, tmp_path):
        # The operator must still be told what was NOT fixed, or they will
        # read "3 fixed" as "nothing left to do".
        rep = report(agents=[agent("Warp", "warp", coverable=False), agent()])
        results = _apply(rep, tmp_path)
        assert {r.status for r in results} == {"skipped", "fixed"}

    def test_summarize_counts_each_status(self, levers, tmp_path, monkeypatch):
        import prismor.runtime.hooks as hooks_mod
        monkeypatch.setattr(hooks_mod, "install_hooks",
                            lambda **kw: (_ for _ in ()).throw(OSError("nope")))
        rep = report(agents=[agent(), agent("Warp", "warp", coverable=False)],
                     creds=[cred()])
        counts = remediate.summarize(_apply(rep, tmp_path))
        assert counts == {"fixed": 1, "skipped": 1, "failed": 1}

    def test_nothing_to_do_yields_no_results(self, levers, tmp_path):
        assert _apply(report(agents=[agent(managed=True)]), tmp_path) == []

    def test_every_result_carries_the_manual_command(self, levers, tmp_path):
        rep = report(agents=[agent()], servers=[mcp()], creds=[cred()])
        for r in _apply(rep, tmp_path):
            if r.status == "fixed":
                assert r.command, f"{r.kind}/{r.target} has no manual equivalent"


def test_apply_reuses_a_supplied_plan(levers, tmp_path):
    """The CLI plans, shows, asks, then applies — it must not re-plan after
    consent, or what the operator approved is not what runs."""
    rep = report(agents=[agent(), agent("Codex", "codex")])
    trimmed = remediate.plan(rep, kinds=("agent",))
    trimmed.actions = [a for a in trimmed.actions if a.subject == "cursor"]
    results = remediate.apply(rep, repo_root=tmp_path, workspace=tmp_path,
                              plan_obj=trimmed)
    assert [r.target for r in results] == ["Cursor"]
    assert len(levers["hooks"]) == 1


# ── the consent gate (discover_cli.run_fix) ──────────────────────────────────

class TestConsentGate:
    """--fix writes to config files, so applying without consent is the one
    failure mode that would make this feature unshippable."""

    @pytest.fixture()
    def cli(self, monkeypatch, capsys):
        from prismor.runtime import discover_cli
        applied = []
        monkeypatch.setattr(remediate, "apply",
                            lambda *a, **k: applied.append(k) or [])
        return discover_cli, applied

    def test_non_tty_without_yes_does_not_apply(self, cli, monkeypatch, tmp_path, capsys):
        discover_cli, applied = cli
        monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
        discover_cli.run_fix(report(agents=[agent()]), workspace=tmp_path,
                             repo_root=tmp_path)
        assert applied == []
        assert "--yes" in capsys.readouterr().out

    def test_yes_applies_without_prompting(self, cli, monkeypatch, tmp_path):
        discover_cli, applied = cli
        monkeypatch.setattr("builtins.input",
                            lambda *a: pytest.fail("must not prompt with --yes"))
        discover_cli.run_fix(report(agents=[agent()]), workspace=tmp_path,
                             repo_root=tmp_path, assume_yes=True)
        assert len(applied) == 1

    def test_declining_the_prompt_changes_nothing(self, cli, monkeypatch, tmp_path, capsys):
        discover_cli, applied = cli
        monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
        monkeypatch.setattr("builtins.input", lambda *a: "n")
        discover_cli.run_fix(report(agents=[agent()]), workspace=tmp_path,
                             repo_root=tmp_path)
        assert applied == []
        assert "Nothing changed" in capsys.readouterr().out

    def test_accepting_the_prompt_applies(self, cli, monkeypatch, tmp_path):
        discover_cli, applied = cli
        monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
        monkeypatch.setattr("builtins.input", lambda *a: "y")
        discover_cli.run_fix(report(agents=[agent()]), workspace=tmp_path,
                             repo_root=tmp_path)
        assert len(applied) == 1

    def test_ctrl_c_at_the_prompt_declines(self, cli, monkeypatch, tmp_path):
        discover_cli, applied = cli
        monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
        monkeypatch.setattr("builtins.input",
                            lambda *a: (_ for _ in ()).throw(KeyboardInterrupt))
        discover_cli.run_fix(report(agents=[agent()]), workspace=tmp_path,
                             repo_root=tmp_path)
        assert applied == []

    def test_nothing_governable_says_so_and_applies_nothing(self, cli, tmp_path, capsys):
        discover_cli, applied = cli
        discover_cli.run_fix(report(agents=[agent(managed=True)]), workspace=tmp_path,
                             repo_root=tmp_path, assume_yes=True)
        assert applied == []
        assert "every discovered surface is governed" in capsys.readouterr().out

    def test_only_unfixable_findings_applies_nothing(self, cli, tmp_path, capsys):
        discover_cli, applied = cli
        discover_cli.run_fix(report(agents=[agent("Warp", "warp", coverable=False)]),
                             workspace=tmp_path, repo_root=tmp_path, assume_yes=True)
        assert applied == []
        out = capsys.readouterr().out
        assert "CANNOT FIX AUTOMATICALLY" in out

    def test_a_section_only_remediates_its_own_kind(self, cli, tmp_path):
        """`discover keys --fix` must not quietly hook agents too. Verified
        live as a subprocess as well, but pinned here so a refactor of the
        CLI's kwargs cannot silently widen the blast radius."""
        discover_cli, applied = cli
        discover_cli.run_fix(
            report(agents=[agent()], creds=[cred()]),
            workspace=tmp_path, repo_root=tmp_path,
            kinds=("credential",), assume_yes=True)
        assert applied[0]["kinds"] == ("credential",)

    def test_the_default_covers_every_kind(self, cli, tmp_path):
        discover_cli, applied = cli
        discover_cli.run_fix(report(agents=[agent()]), workspace=tmp_path,
                             repo_root=tmp_path, assume_yes=True)
        assert set(applied[0]["kinds"]) == set(remediate.FIXABLE_KINDS)

