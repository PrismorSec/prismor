"""A client hanging up mid-response must not dump a traceback (BrokenPipeError)."""
import io
import sys
from contextlib import redirect_stderr

from prismor.runtime.server import PrismorRequestHandler, _DashboardServer


def _handle_error_output(exc):
    server = _DashboardServer(("127.0.0.1", 0), PrismorRequestHandler)
    try:
        buf = io.StringIO()
        with redirect_stderr(buf):
            try:
                raise exc
            except Exception:
                server.handle_error(None, ("127.0.0.1", 1))
        return buf.getvalue()
    finally:
        server.server_close()


def test_client_disconnect_is_silent():
    assert _handle_error_output(BrokenPipeError(32, "Broken pipe")) == ""
    assert _handle_error_output(ConnectionResetError(54, "reset")) == ""


def test_real_errors_still_reported():
    assert "ValueError" in _handle_error_output(ValueError("boom"))
