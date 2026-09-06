"""Governance modes — the compile, and the invariants a compile must not lose.

A mode is a template that writes `.prismor/policy.yaml`, so the risk is not
that the template is ugly, it is that it QUIETLY produces a weaker policy than
the mode's own description promises. These tests pin the places where that
could happen: the cloud-metadata denies that a wholesale `settings.egress`
replace would drop, the `mode_id` stamp that must not collide with the
`settings.mode` alias, and the enforce-selector actually reaching the engine.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prismor.runtime import modes
from prismor.runtime.policy_engine import PolicyEngine, validate_policy


def _workspace() -> Path:
    d = Path(tempfile.mkdtemp())
    (d / ".prismor").mkdir()
    return d


def _unmanaged():
    return mock.patch(
        "prismor.runtime.enterprise.workspace_scope.is_managed", return_value=False
    )


ALL_MODES = list(modes.load_modes())


class TestCatalog(unittest.TestCase):
    def test_three_starter_modes(self):
        """audit-only was dropped: it was the default state plus tag telemetry,
        and `apply <id> --observe` answers the better question (what would THIS
        posture block) for every mode instead of only for a blank one."""
        self.assertEqual(
            ALL_MODES,
            ["dev-safe", "trusted-workspace", "regulated-airgap"],
        )

    def test_every_mode_states_its_residual_risk(self):
        """A mode that only advertises what it stops is a mode people over-trust."""
        for mode_id in ALL_MODES:
            mode = modes.get_mode(mode_id)
            self.assertTrue(mode.get("residual_risk", "").strip(), mode_id)
            self.assertTrue(mode.get("friction"), mode_id)

    def test_unknown_mode_names_the_alternatives(self):
        with self.assertRaises(modes.ModeError) as cm:
            modes.get_mode("no-such-mode")
        self.assertIn("dev-safe", str(cm.exception))


class TestCompile(unittest.TestCase):
    def test_every_mode_compiles_to_a_valid_policy(self):
        for mode_id in ALL_MODES:
            with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as fh:
                fh.write(modes.compile_mode(modes.get_mode(mode_id)))
            self.assertEqual(validate_policy(Path(fh.name)), [], mode_id)

    def test_mode_id_is_stamped_not_as_settings_mode(self):
        """`settings.mode` is already an alias for default_mode (policy_engine._load).

        Stamping provenance there would resolve every rule against a mode NAME
        instead of observe/enforce, so the id has to live under `mode_id`.
        """
        import yaml
        raw = yaml.safe_load(modes.compile_mode(modes.get_mode("dev-safe")))
        self.assertEqual(raw["settings"]["mode_id"], "dev-safe")
        self.assertNotIn("mode", raw["settings"])

    def test_egress_modes_carry_the_cloud_metadata_denies(self):
        """settings.update() replaces `egress` wholesale — a mode that omits the
        default deny list reopens the IMDS credential pivot on every workspace."""
        import yaml
        for mode_id in ALL_MODES:
            egress = yaml.safe_load(
                modes.compile_mode(modes.get_mode(mode_id))
            )["settings"].get("egress") or {}
            if not egress.get("enabled"):
                continue
            hosts = {e["host"] if isinstance(e, dict) else e for e in egress.get("deny") or []}
            self.assertIn("169.254.169.254", hosts, mode_id)
            self.assertIn("metadata.google.internal", hosts, mode_id)

    def test_a_tag_enforcing_mode_must_declare_its_inference_posture(self):
        """The default (inference on) tags every workspace read untrusted, which
        turns `untrusted_content then critical_action` into read-then-anything.
        Inheriting that silently is what made both safe modes unusable."""
        mode = modes.get_mode("dev-safe")
        mode["tool_tags"] = {
            k: v for k, v in mode["tool_tags"].items() if k != "inference_enabled"
        }
        with self.assertRaises(modes.ModeError) as ctx:
            modes.compile_mode(mode)
        self.assertIn("inference_enabled", str(ctx.exception))

    def test_every_tag_enforcing_mode_declares_it(self):
        for mode_id in ALL_MODES:
            tags = modes.get_mode(mode_id).get("tool_tags") or {}
            if tags.get("enabled"):
                self.assertIn("inference_enabled", tags, mode_id)

    def test_dropping_a_metadata_deny_fails_the_compile(self):
        mode = modes.get_mode("dev-safe")
        mode["egress"] = {**mode["egress"], "deny": []}
        with self.assertRaises(modes.ModeError):
            modes.compile_mode(mode)

    def test_all_selector_does_not_make_the_floor_opt_in(self):
        """`selection: explicit` means "only the listed rules block". An `all`
        mode lists none and carries enforcement in default_mode, so setting it
        there would invert the mode into blocking nothing."""
        import yaml
        raw = yaml.safe_load(modes.compile_mode(modes.get_mode("regulated-airgap")))
        self.assertEqual(raw["settings"]["default_mode"], "enforce")
        self.assertNotIn("selection", raw["settings"])


class TestEngineEffect(unittest.TestCase):
    """The compile is only worth anything if the engine reads it back."""

    def _engine(self, mode_id: str) -> PolicyEngine:
        ws = _workspace()
        with _unmanaged():
            modes.apply_mode(ws, mode_id)
            return PolicyEngine(workspace=ws)

    def test_observe_build_blocks_nothing_but_self_protection(self):
        """`--observe` is the honest "nothing blocks" posture — with the one
        exception it does not get to make. Self-protection always enforces, so
        a preview build cannot be used as cover for switching Prismor off."""
        from prismor.runtime.policy_engine import _SELF_PROTECTION_RULE_IDS
        ws = _workspace()
        with _unmanaged():
            modes.apply_mode(ws, "dev-safe", observe=True)
            engine = PolicyEngine(workspace=ws)
        self.assertEqual(engine.default_mode, "observe")
        enforcing = {r.id for r in engine.rules if engine._resolve_mode(r) == "enforce"}
        self.assertEqual(enforcing - set(_SELF_PROTECTION_RULE_IDS), set())
        self.assertTrue(enforcing & set(_SELF_PROTECTION_RULE_IDS))

    def test_dev_safe_enforces_the_floor(self):
        engine = self._engine("dev-safe")
        by_id = {r.id: r for r in engine.rules}
        self.assertEqual(engine._resolve_mode(by_id["destructive-command"]), "enforce")

    def test_dev_safe_gates_privilege_escalation_not_network_binaries(self):
        """curl/wget/nc/ssh are governed by destination, not by name.

        Banning the binary stopped `curl localhost:3000` and `ssh git@github.com`
        while `curl | bash` was already caught precisely by remote-execution.
        """
        engine = self._engine("dev-safe")
        gated = engine.check_command("sudo systemctl restart nginx")
        self.assertTrue(
            any(f["id"].startswith("mode-dev-safe-deny-commands") for f in gated),
            gated,
        )
        for benign in (
            "curl -s localhost:3000/health",
            "curl -sS https://api.github.com/repos/x/y",
            "ssh git@github.com",
            "nc -z localhost 5432",
        ):
            hits = [
                f for f in engine.check_command(benign)
                if f["id"].startswith("mode-dev-safe-deny-commands")
            ]
            self.assertEqual(hits, [], f"{benign} should not hit a mode deny rule")

    def test_dev_safe_enforces_the_supply_chain_rules(self):
        engine = self._engine("dev-safe")
        by_id = {r.id: r for r in engine.rules}
        for rule_id in (
            "dependency-confusion", "pkg-install-from-url", "pkg-suspicious-name",
        ):
            self.assertEqual(
                engine._resolve_mode(by_id[rule_id]), "enforce", rule_id
            )

    def test_dev_safe_enforces_the_data_boundary(self):
        """settings.data_boundary already ships a `secret` class that blocks on
        external destinations; the mode's job is to take it out of observe."""
        engine = self._engine("dev-safe")
        self.assertTrue(engine.data_boundary.enabled)
        self.assertEqual(engine.data_boundary.mode, "enforce")

    def test_read_only_commands_are_auto_approved(self):
        """The largest category of agent work must not be a policy verdict.

        `grep -rn 'sudo' docs/` matches the mode's own deny pattern; the
        commands.allow entries are what stop that being a finding at all.
        """
        engine = self._engine("dev-safe")
        for benign in (
            "grep -rn 'sudo' docs/",
            "rg 'sudo' --type py",
            "ls -la src/",
            "cat README.md",
            "git status",
            "git log --oneline -20",
            "pytest tests/ -q",
        ):
            hits = [
                f for f in engine.check_command(benign)
                if f.get("category") == "mode_command_control"
            ]
            self.assertEqual(hits, [], f"{benign} should be auto-approved")

    def test_the_allowlist_cannot_reach_the_safety_floor(self):
        """A mode may suppress its own generated rules and nothing else."""
        for mode_id in ALL_MODES:
            mode = modes.get_mode(mode_id)
            for entry in modes._command_allowlists(mode):
                for rule_id in entry["rule_ids"]:
                    self.assertTrue(
                        rule_id.startswith(f"mode-{mode_id}-"),
                        f"{mode_id} allowlists non-mode rule {rule_id}",
                    )

    def test_reading_a_workspace_file_does_not_end_the_session(self):
        """The regression this whole re-scope exists for.

        With inference tagging every file_read `untrusted_content`, the first
        Read completed `untrusted_content then critical_action` on the next
        shell call — and the ledger is monotonic, so every command and every
        edit for the rest of the session was denied.
        """
        from prismor.runtime.hooks import should_block
        for mode_id in ("dev-safe", "trusted-workspace"):
            ws = _workspace()
            with _unmanaged():
                modes.apply_mode(ws, mode_id)
                engine = PolicyEngine(workspace=ws)
                (ws / "app.py").write_text("x = 1")
                session = f"cliff-{mode_id}"
                sequence = [
                    {"type": "file_read", "path": str(ws / "app.py"),
                     "agent_event": "PreToolUse", "metadata": {"tool_name": "Read"}},
                    {"type": "shell", "command": "pytest tests/ -q",
                     "agent_event": "PreToolUse", "metadata": {"tool_name": "Bash"}},
                    {"type": "file_write", "path": str(ws / "app.py"),
                     "agent_event": "PreToolUse", "metadata": {"tool_name": "Edit"}},
                    {"type": "shell", "command": "git status",
                     "agent_event": "PreToolUse", "metadata": {"tool_name": "Bash"}},
                ]
                for i, event in enumerate(sequence):
                    findings = engine.evaluate(event, i, session_id=session)
                    self.assertIsNone(
                        should_block(findings, event),
                        f"{mode_id} step {i} ({event['type']}) blocked ordinary work",
                    )

    def test_web_ingest_then_shell_still_blocks(self):
        """The narrowing must not cost the sequence the rule exists for."""
        from prismor.runtime.hooks import should_block
        ws = _workspace()
        with _unmanaged():
            modes.apply_mode(ws, "dev-safe")
            engine = PolicyEngine(workspace=ws)
            session = "trifecta-still-armed"
            fetched = {
                "type": "tool_result", "agent_event": "PostToolUse",
                "response": "{}", "metadata": {"tool_name": "WebFetch"},
            }
            self.assertIsNone(should_block(engine.evaluate(fetched, 0, session_id=session), fetched))
            shell = {
                "type": "shell", "command": "git push origin main",
                "agent_event": "PreToolUse", "metadata": {"tool_name": "Bash"},
            }
            self.assertIsNotNone(
                should_block(engine.evaluate(shell, 1, session_id=session), shell),
                "web ingest then a critical action must still block",
            )

    def test_regulated_airgap_enforces_every_rule(self):
        engine = self._engine("regulated-airgap")
        self.assertEqual(engine.default_mode, "enforce")
        self.assertEqual(engine._resolve_mode(engine.rules[0]), "enforce")

    def test_egress_allowlist_reaches_the_engine(self):
        engine = self._engine("dev-safe")
        self.assertTrue(engine._is_domain_allowed("api.github.com"))
        self.assertFalse(engine._is_domain_allowed("webhook.site"))

    def test_regulated_airgap_denies_the_bash_tool(self):
        """The tool axis lands in agents.yaml, not the policy."""
        import yaml
        ws = _workspace()
        with _unmanaged():
            modes.apply_mode(ws, "regulated-airgap")
        cfg = yaml.safe_load((ws / ".prismor" / "agents.yaml").read_text())
        self.assertIn("Bash", cfg["global_deny_tools"])
        self.assertIn("Write", cfg["global_ask_tools"])


class TestApply(unittest.TestCase):
    def test_refuses_to_clobber_a_hand_written_policy(self):
        ws = _workspace()
        (ws / ".prismor" / "policy.yaml").write_text('version: "1.0"\nrules: []\n')
        with self.assertRaises(modes.ModeError):
            modes.apply_mode(ws, "dev-safe")

    def test_force_clobbers_but_keeps_a_backup(self):
        ws = _workspace()
        (ws / ".prismor" / "policy.yaml").write_text('version: "1.0"\nrules: []\n')
        with _unmanaged():
            modes.apply_mode(ws, "dev-safe", force=True)
        self.assertEqual(modes.active_mode(ws), "dev-safe")
        self.assertIn("rules: []", (ws / ".prismor" / "policy.yaml.bak").read_text())

    def test_reapplying_a_mode_needs_no_force(self):
        ws = _workspace()
        with _unmanaged():
            modes.apply_mode(ws, "dev-safe")
            modes.apply_mode(ws, "trusted-workspace")
        self.assertEqual(modes.active_mode(ws), "trusted-workspace")

    def test_drift_is_reported_not_prevented(self):
        ws = _workspace()
        with _unmanaged():
            modes.apply_mode(ws, "dev-safe")
        self.assertFalse(modes.has_drifted(ws))
        path = ws / ".prismor" / "policy.yaml"
        path.write_text(path.read_text() + "\nallowlists: []\n")
        self.assertTrue(modes.has_drifted(ws))

    def test_unmanaged_workspace_has_no_active_mode(self):
        self.assertIsNone(modes.active_mode(_workspace()))


class TestCoverage(unittest.TestCase):
    def test_coverage_is_computed_from_the_real_ruleset(self):
        _, total = modes._floor_rule_ids()
        self.assertEqual(modes.coverage(modes.get_mode("regulated-airgap")), (total, total))
        blocking, _ = modes.coverage(modes.get_mode("dev-safe"))
        self.assertTrue(0 < blocking < total)


# The benign corpus behind `friction_index`. Weighted toward the shape of real
# agent work: repository navigation and git inspection, build and test, package
# operations, and a few network-shaped commands that are nonetheless ordinary.
# A mode's declared friction is pinned to its measured interruption rate here,
# so the number in `mode explain` cannot drift into a marketing figure the way
# a hand-written one does.
BENIGN_CORPUS = [
    "ls -la src/", "pwd", "cat README.md", "head -50 package.json",
    "tail -n 100 logs/app.log", "find . -name '*.py' -maxdepth 3",
    "stat prismor/runtime/cli.py", "wc -l src/index.ts",
    "grep -rn 'curl' src/", "rg 'wget' --type py",
    "grep -rn 'sudo' docs/", "rg -n 'ssh' Makefile",
    "git status", "git log --oneline -20", "git diff HEAD~1",
    "git show abc123", "git branch -a", "git remote -v",
    "git log --grep 'curl retry'",
    "npm test", "npm run build", "pytest tests/ -q",
    "cargo build --release", "go test ./...", "make lint",
    "python3 -m pytest -k test_modes",
    "docker compose up -d", "docker build -t app .",
    "npm install", "npm ci", "pip install -r requirements.txt",
    "cargo add serde", "uv pip install ruff",
    "git add -A", "git commit -m 'fix: retry curl timeouts'",
    "git push origin feature", "mkdir -p build", "touch src/new.ts",
    "mv old.py new.py",
    "curl -s localhost:3000/health",
    "curl -sS https://api.github.com/repos/x/y",
    "ssh-keygen -t ed25519 -C dev@example.com",
    "ssh git@github.com",
    "nc -z localhost 5432",
]


class TestMeasuredFriction(unittest.TestCase):
    """`friction_index` is an assertion about developer experience. Measure it."""

    def _interruption_rate(self, mode_id):
        from prismor.runtime.hooks import should_block
        ws = _workspace()
        with _unmanaged():
            modes.apply_mode(ws, mode_id)
            engine = PolicyEngine(workspace=ws)
            stopped = []
            for i, cmd in enumerate(BENIGN_CORPUS):
                event = {
                    "type": "shell", "command": cmd, "agent_event": "PreToolUse",
                    "metadata": {"tool_name": "Bash"},
                }
                findings = engine.evaluate(event, i, session_id=f"friction-{mode_id}")
                if should_block(findings, event):
                    stopped.append(cmd)
        return round(len(stopped) / len(BENIGN_CORPUS) * 100), stopped

    def test_declared_friction_matches_the_measured_rate(self):
        for mode_id in ("dev-safe", "trusted-workspace"):
            declared = int(modes.get_mode(mode_id).get("friction_index", 0))
            measured, stopped = self._interruption_rate(mode_id)
            self.assertLessEqual(
                abs(declared - measured), 5,
                f"{mode_id}: declares {declared}% friction, measures {measured}% "
                f"— interrupted {stopped}",
            )

    def test_only_package_installs_interrupt_ordinary_work(self):
        """Whatever the rate is, the things it stops must be defensible."""
        for mode_id in ("dev-safe", "trusted-workspace"):
            _, stopped = self._interruption_rate(mode_id)
            for cmd in stopped:
                self.assertRegex(
                    cmd, r"\b(install|add|ci)\b",
                    f"{mode_id} interrupted non-install command {cmd!r}",
                )


if __name__ == "__main__":
    unittest.main()
