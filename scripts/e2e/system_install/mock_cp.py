"""Stand-in control plane: accepts telemetry ingest, 404s everything else."""
import json, os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
LOG = open(os.environ.get("MOCK_LOG", "mock-cp.log"), "a", buffering=1)
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        LOG.write(f"GET {self.path} auth={bool(self.headers.get('Authorization'))}\n"); self.send_response(404); self.end_headers()
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("content-length", 0))) or b"{}")
        LOG.write(f"POST {self.path} events={len(body.get('events') or [])} auth={self.headers.get('Authorization','')[:20]}\n")
        self.send_response(200); self.send_header("content-type", "application/json"); self.end_headers(); self.wfile.write(b'{"ok":true}')
ThreadingHTTPServer(("127.0.0.1", 8790), H).serve_forever()
