"""Approving one blocked call from the dashboard (approvals_local.py via /api/approvals)."""
import http.client
import json
import os
import sys
import threading
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prismor.runtime import approvals_local, unlock
from prismor.runtime import server as srv


def _serve():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), srv.PrismorRequestHandler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()

    def call(method, path, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", httpd.server_address[1], timeout=10)
        conn.request(method, path, body=json.dumps(body) if body is not None else None,
                     headers={"Content-Type": "application/json"})
        r = conn.getresponse(); data = json.loads(r.read() or b"{}"); conn.close()
        return r.status, data
    return httpd, call


def _pending():
    return approvals_local.request("fp1", agent="claude", session_id="s1",
                                   finding={"ruleId": "destructive-command", "severity": "CRITICAL", "title": "rm -rf"},
                                   summary="rm -rf build/")


def test_list_and_approve_once():
    httpd, call = _serve()
    try:
        rid = _pending()["id"]
        status, data = call("GET", "/api/approvals")
        assert status == 200 and [r["id"] for r in data["requests"]] == [rid]
        assert "fp" not in data["requests"][0]  # the fingerprint stays server-side
        assert call("POST", "/api/approvals", {"id": rid, "approve": True})[0] == 200
        assert call("GET", "/api/approvals")[1]["requests"] == []
        assert call("POST", "/api/approvals", {"id": "nope", "approve": True})[0] == 404
    finally:
        httpd.shutdown(); httpd.server_close()


def test_refused_while_an_unlock_window_is_open():
    httpd, call = _serve()
    try:
        rid = _pending()["id"]
        unlock.set_password("correct horse battery staple")
        unlock.open_window()
        status, data = call("POST", "/api/approvals", {"id": rid, "approve": True})
        assert status == 403 and "terminal" in data["error"]
    finally:
        httpd.shutdown(); httpd.server_close()
