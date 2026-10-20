"""Happy Eyeballs (RFC 8305) for every outbound connection the CLI makes.

``socket.create_connection`` tries each resolved address in turn and gives
each one the *full* timeout. On a network that advertises an IPv6 route but
drops IPv6 traffic (common on home routers, hotel and office Wi-Fi), every
request to a dual-stack host (prismor.dev sits behind Cloudflare) burns its
whole timeout on the dead AAAA address before trying IPv4. A hook makes
several control-plane calls, so a prompt stalled ~30s and Claude Code killed
the hook. Browsers and curl race the families instead; this does the same.

Installed only by the CLI entry point (our own process). The in-process SDK
adapters never call it, so the host application's sockets stay untouched.
"""
from __future__ import annotations

import errno
import selectors
import socket
import sys
import time

# RFC 8305 recommends 250ms before starting the next attempt.
_STAGGER = 0.25
# A handshake to a live host takes well under a second even on poor links. On
# a network that silently drops packets (captive Wi-Fi, a dead VPN route) the
# connect is where the whole request timeout went: 8s per control-plane call.
# The caller's timeout still governs reads, so a slow server keeps its window.
# ponytail: one cap for every host; make it per-call if a >3s handshake is real.
CONNECT_TIMEOUT = 3.0
_stdlib_create_connection = socket.create_connection


def create_connection(address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT,
                      source_address=None, *, all_errors=False):
    if timeout is socket._GLOBAL_DEFAULT_TIMEOUT:
        timeout = socket.getdefaulttimeout()
    connect_timeout = CONNECT_TIMEOUT if timeout is None else min(timeout, CONNECT_TIMEOUT)
    sock = _connect(address, connect_timeout, source_address, all_errors)
    sock.settimeout(timeout)
    return sock


def _connect(address, timeout, source_address, all_errors):
    host, port = address
    try:
        infos = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)
    except OSError:
        infos = []
    if len({i[0] for i in infos}) < 2:
        # Single-family: nothing to race, keep stdlib behaviour exactly.
        # all_errors only exists on 3.11+; pass it only when asked for.
        kw = {"all_errors": True} if all_errors else {}
        return _stdlib_create_connection(address, timeout, source_address, **kw)

    # Interleave families, preferred (first-resolved) family first.
    first = infos[0][0]
    a = [i for i in infos if i[0] == first]
    b = [i for i in infos if i[0] != first]
    queue = [x for pair in zip(a, b) for x in pair] + a[len(b):] + b[len(a):]

    deadline = None if timeout is None else time.monotonic() + timeout
    sel = selectors.DefaultSelector()
    errors: list = []
    next_start = 0.0
    winner = None
    try:
        while winner is None and (queue or sel.get_map()):
            now = time.monotonic()
            if deadline is not None and now >= deadline:
                break
            if queue and (not sel.get_map() or now >= next_start):
                family, type_, proto, _, sa = queue.pop(0)
                sock = socket.socket(family, type_, proto)
                try:
                    sock.setblocking(False)
                    if source_address:
                        sock.bind(source_address)
                    err = sock.connect_ex(sa)
                except OSError as exc:
                    sock.close()
                    errors.append(exc)
                    continue
                if err == 0:
                    winner = sock
                    break
                if err not in (errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EAGAIN):
                    sock.close()
                    errors.append(OSError(err, errno.errorcode.get(err, str(err))))
                    continue
                sel.register(sock, selectors.EVENT_WRITE)
                next_start = now + _STAGGER
                continue

            waits = []
            if queue:
                waits.append(next_start - now)
            if deadline is not None:
                waits.append(deadline - now)
            for key, _ in sel.select(max(0.0, min(waits)) if waits else None):
                sock = key.fileobj
                sel.unregister(sock)
                err = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                if err == 0:
                    winner = sock
                    break
                sock.close()
                errors.append(OSError(err, errno.errorcode.get(err, str(err))))
    finally:
        for key in list(sel.get_map().values()):
            key.fileobj.close()
        sel.close()

    if winner is not None:
        winner.setblocking(True)
        winner.settimeout(timeout)
        return winner
    if not errors or (deadline is not None and time.monotonic() >= deadline):
        raise socket.timeout("timed out")  # == TimeoutError on 3.10+
    if all_errors and sys.version_info >= (3, 11):
        raise ExceptionGroup("create_connection failed", errors)  # noqa: F821 (3.11+ only)
    raise errors[0]


def install() -> None:
    """Route http.client / urllib (and direct callers) through the racer."""
    socket.create_connection = create_connection


if __name__ == "__main__":
    # Self-check: a dead preferred address must not delay a live fallback.
    import threading

    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen()
    port = srv.getsockname()[1]
    threading.Thread(target=lambda: srv.accept(), daemon=True).start()
    blackhole = (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("100::1", port, 0, 0))  # RFC 6666 discard
    live = (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))
    socket.getaddrinfo = lambda *a, **k: [blackhole, live]
    t = time.monotonic()
    s = create_connection(("dual.test", port), timeout=10)
    elapsed = time.monotonic() - t
    assert s.getpeername()[1] == port and elapsed < 2, elapsed
    print(f"ok: fell back to IPv4 in {elapsed:.2f}s")
