"""The local dashboard must work with no network: its scripts and logo are
served by the dashboard server, not a CDN. With chart.js on a CDN, initCharts()
threw `Chart is not defined` offline and the page never left its loading screen.
"""
import os
import re
import sys
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prismor.runtime import server as srv


class TestOfflineAssets(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), srv.PrismorRequestHandler)
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()
        cls.base = "http://127.0.0.1:%d" % cls.httpd.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()

    def get(self, path):
        try:
            with urllib.request.urlopen(self.base + path, timeout=10) as r:
                return r.status, r.headers.get("Content-Type", ""), r.read()
        except urllib.error.HTTPError as exc:
            return exc.code, "", b""

    def test_page_loads_no_remote_scripts(self):
        html = srv._DASHBOARD_HTML.read_text(encoding="utf-8")
        remote = re.findall(r'<script[^>]+src="(https?:[^"]+)"', html)
        self.assertEqual([], remote)

    def test_every_local_asset_the_page_uses_is_served(self):
        html = srv._DASHBOARD_HTML.read_text(encoding="utf-8")
        paths = sorted(set(re.findall(r'"(/static/[^"]+)"', html)))
        self.assertIn("/static/chart.umd.min.js", paths)
        for path in paths:
            status, ctype, body = self.get(path)
            self.assertEqual(200, status, path)
            self.assertTrue(body, path)
            self.assertTrue(ctype.startswith(("text/javascript", "image/png")), (path, ctype))

    def test_static_route_does_not_leave_its_directory(self):
        for path in ("/static/../dashboard.html", "/static/..%2Fserver.py",
                     "/static/%2e%2e/server.py", "/static/chart.js.LICENSE.md",
                     "/static/nope.js"):
            status, _, _ = self.get(path)
            self.assertEqual(404, status, path)


if __name__ == "__main__":
    unittest.main()
