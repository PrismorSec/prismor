"""POST /v1/redact gives the TypeScript adapters the result-side masking the
Python adapters run in-process (PrismorSec/prismor#507)."""
from __future__ import annotations

import json
import threading
import urllib.request

from prismor.runtime.eval_server import EvalHandler, _ThreadingHTTPServer


def _post(port, path, body, headers=None):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def _serve(tmp_path, monkeypatch, api_key=None):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / "home"))
    handler = type("H", (EvalHandler,), {"workspace": tmp_path, "api_key": api_key})
    srv = _ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_redact_masks_secret_in_tool_result(tmp_path, monkeypatch):
    srv = _serve(tmp_path, monkeypatch)
    try:
        secret = "sk_" + "live_" + "51UxFakeSrv9x8y7z6w5v4"
        status, body = _post(srv.server_address[1], "/v1/redact",
                             {"result": {"stdout": f"STRIPE_KEY={secret}\n"}})
        assert status == 200 and body["redacted"] is True
        assert secret not in json.dumps(body["result"])
        status, body = _post(srv.server_address[1], "/v1/redact", {"result": "hello"})
        assert body == {"result": "hello", "redacted": False}
    finally:
        srv.shutdown()


def test_redact_requires_api_key_when_set(tmp_path, monkeypatch):
    srv = _serve(tmp_path, monkeypatch, api_key="k1")
    try:
        assert _post(srv.server_address[1], "/v1/redact", {"result": "x"})[0] == 401
        assert _post(srv.server_address[1], "/v1/redact", {"result": "x"},
                     {"Authorization": "Bearer k1"})[0] == 200
    finally:
        srv.shutdown()
