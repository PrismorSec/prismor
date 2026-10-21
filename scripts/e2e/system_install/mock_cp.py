"""Stand-in control plane: enrolls any token starting with "fleet-", accepts
telemetry ingest, and 404s everything else (so policy pulls find nothing)."""
import json, os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG = open(os.environ.get("MOCK_LOG", "mock-cp.log"), "a", buffering=1)


class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _send(self, code, body=None):
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.end_headers()
        if body is not None:
            self.wfile.write(json.dumps(body).encode())

    def do_GET(self):
        LOG.write(f"GET {self.path} auth={bool(self.headers.get('Authorization'))}\n")
        if self.path.startswith("/api/policy/version") and self.headers.get("Authorization"):
            return self._send(200, {"version": 0, "org": "org-test", "device_id": "dev-ci", "deviceKind": "device"})
        self._send(404, {"error": "not_found"})

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("content-length", 0))) or b"{}")
        if self.path.startswith("/api/devices/enroll"):
            ok = str(body.get("token", "")).startswith("fleet-")
            LOG.write(f"ENROLL label={body.get('label')} platform={body.get('platform')} ok={ok}\n")
            if not ok:
                return self._send(401, {"error": "invalid_token"})
            return self._send(200, {"device_id": f"dev-{body.get('label')}", "org_id": "org-test",
                                    "user_id": "user-admin", "device_key": "prism_dev_FAKE_from_enroll",
                                    "org_name": "Test Org"})
        LOG.write(f"POST {self.path} events={len(body.get('events') or [])} "
                  f"auth={self.headers.get('Authorization', '')[:20]}\n")
        self._send(200, {"ok": True})


ThreadingHTTPServer(("127.0.0.1", int(os.environ.get("MOCK_PORT", "8790"))), H).serve_forever()
