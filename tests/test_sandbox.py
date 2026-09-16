"""Tests for Docker-backed Prismor sandbox support."""

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prismor.runtime import sandbox
from prismor.runtime.cli import build_parser
from prismor.runtime.policy_engine import PolicyEngine, validate_policy


class TestSandboxConfig(unittest.TestCase):
    def test_default_config_is_disabled_and_safe(self):
        cfg = sandbox.effective_config({})
        self.assertFalse(cfg["enabled"])
        self.assertEqual(cfg["backend"], "docker")
        self.assertEqual(cfg["network"], "none")
        self.assertTrue(cfg["read_only_root"])

    def test_policy_engine_loads_sandbox_config(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "policy.yaml"
            p.write_text(
                'version: "1.0"\n'
                "settings:\n"
                "  sandbox:\n"
                "    enabled: true\n"
                "    mode: enforce\n"
                "    network: none\n"
                "rules: []\n",
                encoding="utf-8",
            )
            engine = PolicyEngine(policy_path=p)
            cfg = sandbox.effective_config(engine.sandbox_config)
            self.assertTrue(cfg["enabled"])
            self.assertEqual(cfg["mode"], "enforce")

    def test_schema_accepts_sandbox_settings(self):
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            f.write(
                'version: "1.0"\n'
                "settings:\n"
                "  sandbox:\n"
                "    enabled: true\n"
                "    backend: docker\n"
                "    mode: enforce\n"
                "    network: none\n"
                "rules: []\n"
            )
            path = Path(f.name)
        try:
            self.assertEqual(validate_policy(path), [])
        finally:
            path.unlink(missing_ok=True)


class TestSandboxCommandHandling(unittest.TestCase):
    def test_command_round_trip_encoding(self):
        command = "printf '%s\\n' hello && echo done"
        encoded = sandbox.encode_command(command)
        self.assertEqual(sandbox.decode_command(encoded), command)

    def test_docker_argv_keeps_original_command_as_single_container_arg(self):
        cfg = sandbox.effective_config({
            "image": "example/sandbox:latest",
            "network": "allowlist",
            "resource_limits": {
                "cpus": "2.0",
                "memory": "2g",
                "pids_limit": 128,
                "timeout_seconds": 60,
            },
        })
        command = "echo safe; touch /tmp/proof"
        argv = sandbox.build_docker_argv(command, workspace=Path("/tmp/work"), config=cfg)
        self.assertIn("--network", argv)
        self.assertEqual(argv[argv.index("--network") + 1], "none")
        self.assertIn("--cap-drop", argv)
        self.assertIn("no-new-privileges", argv)
        mount = argv[argv.index("--mount") + 1]
        self.assertEqual(mount, f"type=bind,src={Path('/tmp/work').resolve()},dst=/workspace")
        self.assertEqual(argv[-3:], ["/bin/sh", "-lc", command])

    def test_docker_argv_uses_readonly_for_ro_workspace_mount(self):
        cfg = sandbox.effective_config({"workspace_mount": "ro"})
        argv = sandbox.build_docker_argv("echo ok", workspace=Path("/tmp/work"), config=cfg)
        mount = argv[argv.index("--mount") + 1]
        self.assertEqual(mount, f"type=bind,src={Path('/tmp/work').resolve()},dst=/workspace,readonly")

    def test_claude_updated_input_uses_encoded_runner(self):
        payload = {
            "tool_name": "Bash",
            "tool_input": {"command": "echo hello", "description": "test"},
        }
        update = sandbox.claude_updated_input(
            payload,
            workspace=Path("/tmp/work"),
            mode="enforce",
        )
        self.assertIsNotNone(update)
        updated = update["hookSpecificOutput"]["updatedInput"]
        self.assertEqual(updated["description"], "test")
        self.assertIn("sandbox --workspace /tmp/work run", updated["command"])
        self.assertIn("--encoded", updated["command"])
        self.assertNotIn("echo hello", updated["command"])

    def test_sandbox_run_parser_does_not_clobber_top_level_command(self):
        args = build_parser().parse_args(["sandbox", "run", "--encoded", "abc"])
        self.assertEqual(args.command, "sandbox")
        self.assertEqual(args.sandbox_command, "run")
        self.assertEqual(args.encoded, "abc")


class TestPrivilegeRings(unittest.TestCase):
    def test_no_ring_set_is_fully_backward_compatible(self):
        """Omitting `ring` must reproduce the pre-ring single-tier defaults
        exactly — existing workspace configs must not change behavior."""
        cfg = sandbox.effective_config({"enabled": True})
        self.assertIsNone(cfg["ring"])
        self.assertEqual(cfg["network"], "none")
        self.assertEqual(cfg["workspace_mount"], "rw")
        self.assertEqual(cfg["resource_limits"]["cpus"], "1.0")

    def test_ring_0_is_read_only_and_networkless(self):
        cfg = sandbox.effective_config({"enabled": True, "ring": "0"})
        self.assertEqual(cfg["ring"], "0")
        self.assertEqual(cfg["network"], "none")
        self.assertEqual(cfg["workspace_mount"], "ro")

    def test_ring_2_is_allowlisted_network(self):
        cfg = sandbox.effective_config({"enabled": True, "ring": "2"})
        self.assertEqual(cfg["network"], "allowlist")
        self.assertEqual(cfg["workspace_mount"], "rw")

    def test_ring_3_uses_bridge_not_host(self):
        """No ring preset ever defaults to `host` networking — that's the
        one mode a ring can't hand out automatically."""
        cfg = sandbox.effective_config({"enabled": True, "ring": "3"})
        self.assertEqual(cfg["network"], "bridge")

    def test_rings_are_strictly_increasing_in_resource_ceiling(self):
        limits = [
            sandbox.effective_config({"ring": r})["resource_limits"]
            for r in sandbox.ring_names()
        ]
        cpus = [float(l["cpus"]) for l in limits]
        self.assertEqual(cpus, sorted(cpus))
        self.assertTrue(all(a < b for a, b in zip(cpus, cpus[1:])))

    def test_explicit_field_overrides_ring_default(self):
        """A ring only supplies defaults — an explicitly set field in the
        same config always wins, even a more permissive one than the ring."""
        cfg = sandbox.effective_config({"ring": "0", "network": "bridge"})
        self.assertEqual(cfg["network"], "bridge")
        self.assertEqual(cfg["ring"], "0")

    def test_unknown_ring_value_is_ignored_not_fatal(self):
        cfg = sandbox.effective_config({"ring": "does-not-exist"})
        self.assertIsNone(cfg["ring"])
        self.assertEqual(cfg["network"], "none")  # falls back to plain defaults

    def test_ring_names_are_ascending(self):
        self.assertEqual(sandbox.ring_names(), ["0", "1", "2", "3"])

    def test_ring_label_for_known_and_unknown_ring(self):
        self.assertIn("read-only", sandbox.ring_label("0"))
        self.assertIsNone(sandbox.ring_label(None))
        self.assertIsNone(sandbox.ring_label("nope"))

    def test_status_report_surfaces_ring_and_label(self):
        report = sandbox.status_report({"ring": "1"})
        self.assertEqual(report["ring"], "1")
        self.assertIsNotNone(report["ring_label"])

    def test_policy_engine_loads_ring_from_settings(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "policy.yaml"
            p.write_text(
                'version: "1.0"\n'
                "settings:\n"
                "  sandbox:\n"
                "    enabled: true\n"
                "    ring: \"2\"\n"
                "rules: []\n",
                encoding="utf-8",
            )
            engine = PolicyEngine(policy_path=p)
            cfg = sandbox.effective_config(engine.sandbox_config)
            self.assertEqual(cfg["ring"], "2")
            self.assertEqual(cfg["network"], "allowlist")

    def test_schema_accepts_ring_in_sandbox_settings(self):
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            f.write(
                'version: "1.0"\n'
                "settings:\n"
                "  sandbox:\n"
                "    enabled: true\n"
                "    ring: \"1\"\n"
                "rules: []\n"
            )
            path = Path(f.name)
        try:
            self.assertEqual(validate_policy(path), [])
        finally:
            path.unlink(missing_ok=True)


class TestSetEnabled(unittest.TestCase):
    """`prismor sandbox on|off` must flip exactly one field: an operator who
    turns containment off for an afternoon should get the same ring, network
    and limits back when they turn it on again."""

    def _policy(self, ws: Path):
        import yaml
        return yaml.safe_load((ws / ".prismor" / "policy.yaml").read_text())

    def test_off_then_on_preserves_the_rest_of_the_block(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / ".prismor").mkdir()
            (ws / ".prismor" / "policy.yaml").write_text(
                'version: "1.0"\n'
                "settings:\n"
                "  sandbox:\n"
                "    enabled: true\n"
                "    mode: enforce\n"
                "    network: allowlist\n"
                "rules: []\n"
            )
            sandbox.set_enabled(ws, False)
            block = self._policy(ws)["settings"]["sandbox"]
            self.assertFalse(block["enabled"])
            self.assertEqual(block["mode"], "enforce")
            self.assertEqual(block["network"], "allowlist")

            sandbox.set_enabled(ws, True)
            block = self._policy(ws)["settings"]["sandbox"]
            self.assertTrue(block["enabled"])
            self.assertEqual(block["network"], "allowlist")

    def test_writes_into_a_policy_with_no_sandbox_block(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / ".prismor").mkdir()
            (ws / ".prismor" / "policy.yaml").write_text(
                'version: "1.0"\nrules: []\n'
            )
            sandbox.set_enabled(ws, True)
            self.assertTrue(self._policy(ws)["settings"]["sandbox"]["enabled"])

    def test_parser_accepts_on_and_off(self):
        parser = build_parser()
        for sub in ("on", "off"):
            args = parser.parse_args(["sandbox", sub])
            self.assertEqual(args.sandbox_command, sub)


if __name__ == "__main__":
    unittest.main()
