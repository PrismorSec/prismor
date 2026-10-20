"""A dead preferred address (broken IPv6) must not stall the live fallback."""
import socket
import threading
import time

from prismor.runtime import happy_eyeballs


def _listener():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen()
    threading.Thread(target=srv.accept, daemon=True).start()
    return srv, srv.getsockname()[1]


def test_dead_ipv6_falls_back_to_ipv4_fast(monkeypatch):
    srv, port = _listener()
    dead = (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("100::1", port, 0, 0))  # RFC 6666 discard prefix
    live = (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [dead, live])
    t = time.monotonic()
    with happy_eyeballs.create_connection(("dual.test", port), timeout=10) as s:
        assert s.getpeername()[1] == port
        assert s.gettimeout() == 10
    assert time.monotonic() - t < 2
    srv.close()


def test_single_family_uses_stdlib(monkeypatch):
    srv, port = _listener()
    with happy_eyeballs.create_connection(("127.0.0.1", port), timeout=5) as s:
        assert s.getpeername()[1] == port
    srv.close()


def test_all_dead_raises_timeout(monkeypatch):
    dead6 = (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("100::1", 9, 0, 0))
    dead4 = (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", 9))  # TEST-NET-1
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [dead6, dead4])
    t = time.monotonic()
    try:
        happy_eyeballs.create_connection(("dual.test", 9), timeout=1)
    except OSError:
        pass
    else:
        raise AssertionError("expected failure")
    assert time.monotonic() - t < 3


def test_dead_host_fails_at_connect_cap_but_reads_keep_full_timeout(monkeypatch):
    """A network that drops packets used to cost the whole request timeout
    (8s per control-plane call on the hook path); connect is now capped."""
    monkeypatch.setattr(happy_eyeballs, "CONNECT_TIMEOUT", 0.5)
    t = time.monotonic()
    try:
        happy_eyeballs.create_connection(("192.0.2.1", 9), timeout=8)  # TEST-NET-1 blackhole
    except OSError:
        pass
    else:
        raise AssertionError("expected failure")
    assert time.monotonic() - t < 2

    srv, port = _listener()
    with happy_eyeballs.create_connection(("127.0.0.1", port), timeout=8) as s:
        assert s.gettimeout() == 8
    srv.close()
