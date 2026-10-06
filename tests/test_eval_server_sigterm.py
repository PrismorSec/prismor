"""#543: SIGTERM must stop eval-server cleanly so the atexit heartbeat flush runs."""
import os
import signal
import socket
import subprocess
import sys
import time
import urllib.request


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_sigterm_runs_atexit_handlers(tmp_path):
    port = _free_port()
    marker = tmp_path / "flushed"
    # Stand-in for heartbeat.flush_at_exit: an atexit hook registered in the server process.
    boot = (f"import atexit, pathlib; atexit.register(lambda: pathlib.Path({str(marker)!r}).write_text('ok'));"
            f"from prismor.runtime.eval_server import run_eval_server; run_eval_server(port={port})")
    # The child must import THIS checkout: with cwd=tmp_path and no PYTHONPATH
    # it imported whatever prismor was installed, and tested that instead.
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = dict(os.environ, PRISMOR_HOME=str(tmp_path / "home"),
               PYTHONPATH=os.pathsep.join(filter(None, [repo, os.environ.get("PYTHONPATH")])))
    proc = subprocess.Popen([sys.executable, "-c", boot], cwd=tmp_path, env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        for _ in range(100):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=0.5)
                break
            except OSError:
                time.sleep(0.1)
        proc.send_signal(signal.SIGTERM)
        assert proc.wait(timeout=10) == 0
    finally:
        if proc.poll() is None:
            proc.kill()
    assert marker.read_text() == "ok"
