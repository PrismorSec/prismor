"""The dashboard's Docs tab: /api/docs lists, reads and searches the shipped
Markdown docs.

The name parameter reaches the filesystem, so the traversal cases are the point
of this file — a docs reader that can be talked into reading ~/.prismor/*.yaml
is a local file disclosure on a server bound to localhost but reachable from any
page the browser has open (CORS is `*` here).
"""
import json
import os
import sys
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prismor.runtime import server as srv


class TestDocsApi(unittest.TestCase):
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
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def test_lists_the_docs_with_their_titles(self):
        status, data = self.get("/api/docs")
        self.assertEqual(200, status)
        by_name = {d["name"]: d["title"] for d in data["docs"]}
        self.assertEqual("MCP Gateway", by_name.get("mcp-gateway.md"))

    def test_reads_one_doc(self):
        status, data = self.get("/api/docs?name=mcp-gateway.md")
        self.assertEqual(200, status)
        self.assertIn("prismor mcp-gateway install", data["markdown"])

    def test_search_returns_matching_pages_with_snippets(self):
        status, data = self.get("/api/docs?q=" + urllib.parse.quote("mcp-gateway install"))
        self.assertEqual(200, status)
        hit = next((r for r in data["results"] if r["name"] == "mcp-gateway.md"), None)
        self.assertIsNotNone(hit)
        self.assertTrue(hit["hits"])

    def test_search_requires_every_word(self):
        status, data = self.get("/api/docs?q=" + urllib.parse.quote("gateway zzzznotaword"))
        self.assertEqual(200, status)
        self.assertEqual([], data["results"])

    def test_name_cannot_escape_the_docs_directory(self):
        for bad in ("../pyproject.toml", "../../etc/passwd", "/etc/passwd",
                    "docs/architecture.md", "pyproject.toml", "architecture.md.bak"):
            status, _ = self.get("/api/docs?name=" + urllib.parse.quote(bad, safe=""))
            self.assertIn(status, (400, 404), bad)


if __name__ == "__main__":
    unittest.main()
