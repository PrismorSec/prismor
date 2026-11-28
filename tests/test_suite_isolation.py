"""The suite must never upload with the developer's enrolled identity.

Runs a child pytest, under this repo's conftest, as if launched from an enrolled
machine whose control plane is a local capture server. A child process is the
only way to model that: this process's environment is already sandboxed.
"""
import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# Uploads at import, from a thread that outlives its test, and at unconfigure:
# the three places a per-test sandbox does not cover.
PROBE = '''
import threading, time
from prismor.runtime import sinks

def upload():
    sinks.upload_telemetry([{"event_id": "probe", "verdict": "blocked"}])

upload()

def test_probe():
    def late():
        time.sleep(0.5)  # past this test's teardown
        upload()
    threading.Thread(target=late).start()

import atexit
atexit.register(upload)
'''


def test_enrolled_developer_machine_uploads_nothing(tmp_path):
    hits = []

    class Capture(BaseHTTPRequestHandler):
        def do_POST(self):
            hits.append(self.path)
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            self.send_response(200)
            self.end_headers()

        def log_message(self, *a):
            pass

    server = HTTPServer(("127.0.0.1", 0), Capture)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{server.server_address[1]}"

    home = tmp_path / "enrolled-home"
    (home / ".prismor").mkdir(parents=True)
    (home / ".prismor" / "identity.json").write_text(json.dumps(
        {"device_key": "test-device-key", "device_id": "d", "org_id": "o", "api_base": url}))

    # A throwaway repo layout holding the real conftest and the probe.
    (tmp_path / "adapters").mkdir()
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "conftest.py").write_bytes((REPO / "tests" / "conftest.py").read_bytes())
    (tmp_path / "tests" / "test_probe.py").write_text(PROBE)

    env = {k: v for k, v in os.environ.items()
           if not k.startswith("PRISMOR_") and k != "_PYTEST_REAL_HOMES"}
    env.update(HOME=str(home), USERPROFILE=str(home), NO_PROXY="127.0.0.1",
               # sys.path as resolved here: the fake $HOME hides a user-site pytest.
               PYTHONPATH=os.pathsep.join([str(REPO)] + [p for p in sys.path if "site-packages" in p]))
    try:
        for extra in ({}, {"PRISMOR_AGENT_KEY": "test-agent-key", "PRISMOR_API_BASE": url}):
            run = subprocess.run(
                [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests/test_probe.py"],
                cwd=tmp_path, env={**env, **extra}, capture_output=True, text=True, timeout=120)
            assert run.returncode == 0, run.stdout + run.stderr
            assert hits == [], f"the test run uploaded to the enrolled control plane: {hits}"
    finally:
        server.shutdown()
