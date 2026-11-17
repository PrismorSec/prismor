"""Linux sandbox engine: bwrap argv, egress proxy, and live bubblewrap runs."""

import http.server
import os
import shutil
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prismor.runtime import sandbox, sandbox_native as sn


class _Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a):
        pass


def _local_server():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Quiet)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _cfg(**kw):
    return {"mode": "enforce", "network": "none", "workspace_mount": "rw", **kw}


class TestBwrapArgv(unittest.TestCase):
    def setUp(self):
        self.ws = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.ws, True)
        self.real_ws = os.path.realpath(self.ws)

    def test_binds_protected_paths_read_only(self):
        (self.ws / ".prismor").mkdir()
        argv = sn.bwrap_argv(self.ws, _cfg(), unshare_net=True)
        i = argv.index(os.path.join(self.real_ws, ".prismor"))
        self.assertEqual(argv[i - 1], "--ro-bind")
        for flag in ("--unshare-net", "--unshare-pid", "--new-session"):
            self.assertIn(flag, argv)

    def test_protected_parents_are_mount_points(self):
        (self.ws / ".git" / "hooks").mkdir(parents=True)
        argv = sn.bwrap_argv(self.ws, _cfg(), unshare_net=False)
        git = os.path.join(self.real_ws, ".git")
        i = argv.index(git)  # bound onto itself: a mount point, so `mv .git` is EBUSY
        self.assertEqual(argv[i - 1], "--bind")
        self.assertLess(i, argv.index(os.path.join(git, "hooks")))
        ro = sn.bwrap_argv(self.ws, _cfg(workspace_mount="ro"), unshare_net=False)
        self.assertEqual(ro[ro.index(git) - 1], "--ro-bind")

    def test_extra_protect_and_deny_read(self):
        (self.ws / ".gemini").mkdir()
        hidden = self.ws / "secret.txt"
        hidden.write_text("s", encoding="utf-8")
        argv = sn.bwrap_argv(self.ws, _cfg(protect=[".gemini"], deny_read=[str(hidden)]), unshare_net=False)
        self.assertEqual(argv[argv.index(os.path.join(self.real_ws, ".gemini")) - 1], "--ro-bind")
        self.assertEqual(argv[argv.index(os.path.realpath(hidden)) - 1], "/dev/null")


class TestPolicyMapping(unittest.TestCase):
    def test_sandbox_config_maps_onto_bwrap(self):
        seen = {}
        with mock.patch.object(sn, "run", lambda cmd, *, workspace, cfg: seen.update(cfg) or 0):
            sandbox._run_bwrap("true", Path("/w"), {"enabled": True, "ring": "2", "writable": ["out"],
                                                    "hide": [".env"]})
        self.assertEqual(seen["network"], "allowlist")
        self.assertIn(os.path.realpath("/w/out"), seen["allow_write"])
        self.assertIn(os.path.realpath("/w/.env"), seen["deny_read"])
        self.assertIn(".claude", seen["protect"])


class TestEgressProxy(unittest.TestCase):
    def test_proxy_forwards_allowed_and_blocks_others(self):
        ok, other = _local_server(), _local_server()
        self.addCleanup(ok.shutdown)
        self.addCleanup(other.shutdown)
        seen = []

        def decide(host, port, scheme):
            seen.append((host, port))
            return port == ok.server_address[1]

        proxy = sn.EgressProxy(decide)
        self.addCleanup(proxy.close)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler(
            {"http": f"http://127.0.0.1:{proxy.address[1]}"}))
        self.assertEqual(opener.open(f"http://127.0.0.1:{ok.server_address[1]}/", timeout=5).status, 200)
        with self.assertRaises(urllib.error.HTTPError) as err:
            opener.open(f"http://127.0.0.1:{other.server_address[1]}/", timeout=5)
        self.assertEqual(err.exception.code, 403)
        self.assertEqual([p for _, p in seen], [ok.server_address[1], other.server_address[1]])

    def test_decider_fails_closed_in_enforce_when_evaluator_breaks(self):
        with mock.patch("prismor.runtime.runtime.evaluate_tool_call", side_effect=RuntimeError("x")):
            d = sn.make_decider(workspace=Path("."), agent="t", session_id="", mode="enforce", command="c")
            self.assertFalse(d("example.com", 443, "https"))
            d = sn.make_decider(workspace=Path("."), agent="t", session_id="", mode="observe", command="c")
            self.assertTrue(d("example.com", 443, "https"))


@unittest.skipUnless(sn.status()["ready"], "no native sandbox on this host")
class TestLiveSandbox(unittest.TestCase):
    """Real kernel enforcement. No external network: every target is loopback or denied locally."""

    def setUp(self):
        self.ws = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.ws, True)
        (self.ws / ".prismor").mkdir()
        # conftest points $HOME at a temp dir (writable in the sandbox), so use
        # the account's real home: a path that is truly outside every allow rule.
        import pwd
        self.outside = Path(pwd.getpwuid(os.getuid()).pw_dir) / f".prismor-sbx-test-{uuid.uuid4().hex[:8]}"
        self.outside.mkdir()
        (self.outside / "secret.txt").write_text("s")
        self.addCleanup(shutil.rmtree, self.outside, True)
        self.seen = []
        allow_port = []
        self.allow_port = allow_port

        def fake_decider(**_):
            def decide(host, port, scheme):
                self.seen.append((host, port))
                return port in allow_port
            return decide

        patcher = mock.patch.object(sn, "make_decider", fake_decider)
        patcher.start()
        self.addCleanup(patcher.stop)

    def run_in(self, cmd, **cfg):
        return sn.run(cmd, workspace=self.ws, cfg=_cfg(**cfg))

    def test_workspace_write_allowed(self):
        self.assertEqual(self.run_in("echo hi > ok.txt"), 0)
        self.assertEqual((self.ws / "ok.txt").read_text().strip(), "hi")

    def test_write_outside_workspace_denied(self):
        self.assertNotEqual(self.run_in(f"echo x > {self.outside}/new.txt"), 0)
        self.assertFalse((self.outside / "new.txt").exists())

    def test_protected_path_denied_even_from_nested_child(self):
        cmd = f"{sys.executable} -c \"import subprocess;raise SystemExit(subprocess.call(['sh','-c','echo x > .prismor/p.yaml']))\""
        self.assertNotEqual(self.run_in(cmd), 0)
        self.assertFalse((self.ws / ".prismor" / "p.yaml").exists())

    def test_denied_read(self):
        self.assertNotEqual(self.run_in(f"cat {self.outside}/secret.txt", deny_read=[str(self.outside)]), 0)
        self.assertEqual(self.run_in(f"cat {self.outside}/secret.txt"), 0)

    def test_allowlist_routes_through_proxy_and_kernel_blocks_bypass(self):
        ok, other = _local_server(), _local_server()
        self.addCleanup(ok.shutdown)
        self.addCleanup(other.shutdown)
        self.allow_port.append(ok.server_address[1])
        via = "curl -sf -m5 --noproxy '' -x \"$http_proxy\" -o /dev/null http://127.0.0.1:{}/"
        self.assertEqual(self.run_in(via.format(ok.server_address[1]), network="allowlist"), 0)
        self.assertNotEqual(self.run_in(via.format(other.server_address[1]), network="allowlist"), 0)
        self.assertIn(("127.0.0.1", other.server_address[1]), self.seen)
        # A tool that ignores the proxy cannot reach a non-loopback address.
        self.assertNotEqual(self.run_in("curl -s -m3 --noproxy '*' -o /dev/null http://192.0.2.1/",
                                        network="allowlist"), 0)

    def test_renaming_a_protected_parent_is_denied(self):
        (self.ws / ".git" / "hooks").mkdir(parents=True)
        cmd = "mv .git .g && echo x > .g/hooks/post-checkout; mv .g .git 2>/dev/null; test ! -e .git/hooks/post-checkout"
        self.run_in(cmd)
        self.assertTrue((self.ws / ".git").is_dir())
        self.assertFalse((self.ws / ".git" / "hooks" / "post-checkout").exists())
        self.assertNotEqual(self.run_in("git config --file .git/config core.hooksPath /tmp/h"), 0)
        self.assertEqual(self.run_in("echo ok > .git/HEAD.test"), 0)  # writes inside .git still work

    def test_bash_is_the_shell(self):
        self.assertEqual(self.run_in("[[ 1 == 1 ]]"), 0)

    def test_observe_mode_applies_no_kernel_limits(self):
        self.assertEqual(self.run_in(f"echo x > {self.outside}/obs.txt", mode="observe"), 0)


if __name__ == "__main__":
    unittest.main()
