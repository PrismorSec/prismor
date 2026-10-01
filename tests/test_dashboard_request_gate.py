"""The dashboard API rewrites the security policy and serves agent transcripts,
so a web page the user has open must not reach it (GHSA-9xjv-g2ch-rfhc,
GHSA-687v-q5f9-cpq6). Every request passes PrismorRequestHandler's gate.
"""
import http.client
import json
import os
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prismor.runtime import server as srv


class TestDashboardRequestGate(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp()
        self.env = mock.patch.dict(os.environ, {"PRISMOR_HOME": self.home})
        self.env.start()
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), srv.PrismorRequestHandler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.port = self.httpd.server_address[1]

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.env.stop()
        srv._SERVER_TOKEN = None

    def req(self, method, path, headers=None, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        data = json.dumps(body).encode() if body is not None else None
        hdrs = {"Content-Type": "application/json", **(headers or {})}
        conn.request(method, path, body=data, headers=hdrs)
        r = conn.getresponse()
        r.read()
        conn.close()
        return r.status, dict(r.getheaders())

    def put_global(self, headers):
        return self.req("PUT", "/api/policy/global", headers, {"yaml": "# cleared\n"})

    def policy_written(self):
        return (Path(self.home) / "policy.yaml").exists()

    def test_cross_origin_policy_overwrite_is_refused(self):
        # The reporter's PoC: a page on another origin PUTs the global policy.
        status, _ = self.put_global({"Origin": "https://evil.example"})
        self.assertEqual(403, status)
        self.assertFalse(self.policy_written())

    def test_cross_site_fetch_without_origin_is_refused(self):
        status, _ = self.put_global({"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "cors"})
        self.assertEqual(403, status)
        self.assertFalse(self.policy_written())

    def test_dns_rebinding_host_is_refused(self):
        status, _ = self.req("GET", "/api/sessions", {"Host": f"evil.example:{self.port}"})
        self.assertEqual(403, status)

    def test_no_wildcard_cors_and_no_preflight(self):
        status, headers = self.req("GET", "/api/docs")
        self.assertEqual(200, status)
        self.assertNotIn("Access-Control-Allow-Origin", headers)
        status, _ = self.req("OPTIONS", "/api/policy/global", {"Origin": "https://evil.example"})
        self.assertNotEqual(204, status)

    def test_same_origin_dashboard_write_still_works(self):
        status, _ = self.put_global({"Origin": f"http://127.0.0.1:{self.port}", "Sec-Fetch-Site": "same-origin"})
        self.assertEqual(200, status)
        self.assertTrue(self.policy_written())

    def test_cross_site_link_to_the_page_still_opens(self):
        status, _ = self.req("GET", "/", {"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate"})
        self.assertNotEqual(403, status)

    def test_token_required_off_loopback(self):
        srv._SERVER_TOKEN = "s3cret"
        self.assertEqual(401, self.req("GET", "/api/sessions")[0])
        self.assertEqual(401, self.req("GET", "/api/sessions", {"Authorization": "Bearer wrong"})[0])
        self.assertEqual(200, self.req("GET", "/api/sessions", {"Authorization": "Bearer s3cret"})[0])
        self.assertEqual(200, self.req("GET", "/api/sessions", {"Cookie": "prismor_dashboard_token=s3cret"})[0])
        status, headers = self.req("GET", "/?token=s3cret")
        self.assertEqual(200, status)
        self.assertIn("HttpOnly", headers.get("Set-Cookie", ""))

    def test_run_server_requires_token_only_off_loopback(self):
        self.assertTrue(srv._is_loopback("127.0.0.1"))
        self.assertTrue(srv._is_loopback("localhost"))
        self.assertTrue(srv._is_loopback("::1"))
        self.assertFalse(srv._is_loopback("0.0.0.0"))
        self.assertFalse(srv._is_loopback("192.168.1.5"))


if __name__ == "__main__":
    unittest.main()
