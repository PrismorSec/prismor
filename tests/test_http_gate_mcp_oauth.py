"""mcp_oauth (L8): only the redirect carrying this login's state ends the wait.

The callback port is predictable, so any local process or page could GET
/callback and end the login (and its query used to merge into the result).
"""
import threading
import urllib.error
import urllib.request

from prismor.runtime import mcp_oauth


def _get(port, query):
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/callback?{query}", timeout=5) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def test_only_the_expected_state_finishes_the_wait():
    done = threading.Event()
    handler = type("_H", (mcp_oauth._CallbackHandler,), {"result": {}, "done": done})
    httpd = mcp_oauth._bind_callback(0, handler, fixed=False)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    port = httpd.server_address[1]
    try:
        assert _get(port, "code=early") == 400  # before the state exists
        handler.expected_state = "s3cret"
        assert _get(port, "error=access_denied") == 400  # stray GET, no state
        assert _get(port, "code=forged&state=wrong") == 400
        assert not done.is_set() and handler.result == {} and handler.ignored == 3
        assert _get(port, "code=real&state=s3cret") == 200
        assert done.is_set() and handler.result == {"code": "real", "state": "s3cret"}
        assert _get(port, "code=late&state=s3cret") == 400  # no second answer
        assert handler.result["code"] == "real"
    finally:
        httpd.shutdown()
        httpd.server_close()
