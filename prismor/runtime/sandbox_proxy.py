"""Loopback HTTP(S) proxy behind the sandbox's ``proxy`` network mode.

In that mode the OS lets a sandboxed command connect to loopback only, and
``HTTP(S)_PROXY`` point here. Each CONNECT, or absolute-URI HTTP request, is
checked against ``settings.egress`` — the same verdict and the same
observe/enforce resolution the hook uses — before it is forwarded. The proxy
lives inside the ``prismor sandbox run`` process for exactly as long as the
command does, so there is no daemon, port file or state to clean up.
"""
from __future__ import annotations

import socket
import socketserver
import threading
from typing import Any, Callable, Dict, Tuple
from urllib.parse import urlsplit

Decision = Tuple[bool, str]   # (blocked, reason)

_NO_PROXY = "localhost,127.0.0.1,::1"


def egress_decider(engine: Any, log: Callable[[str], None]) -> Callable[[str, int, str], Decision]:
    """``(host, port, scheme) -> (blocked, reason)`` from ``engine.egress``."""
    pol = getattr(engine, "egress", None)
    if pol is None or not getattr(pol, "enabled", False):
        return lambda host, port, scheme: (False, "")
    from prismor.runtime.egress import Destination

    def decide(host: str, port: int, scheme: str) -> Decision:
        dest = Destination(host, port, scheme, origin="sandbox", evidence=f"{host}:{port}")
        action, entry = pol.verdict(dest)
        if action == "allow":
            return False, ""
        reason = (entry.reason if entry is not None and entry.reason else
                  "denied by settings.egress" if entry is not None else "not on the egress allowlist")
        mode = pol.effective_mode(action, entry, default_mode=getattr(engine, "default_mode", "observe"),
                                  device_mode=getattr(engine, "device_mode", None))
        if mode != "enforce":
            log(f"{host}:{port} is {reason} (observe: allowed)")
            return False, ""
        return True, reason

    return decide


class _Handler(socketserver.StreamRequestHandler):
    server: "_Server"

    def _reply(self, code: int, text: str) -> None:
        body = f"Prismor sandbox: {text}\n".encode()
        phrase = {400: "Bad Request", 403: "Forbidden", 502: "Bad Gateway"}[code]
        self.wfile.write(f"HTTP/1.1 {code} {phrase}\r\n"
                         f"Content-Type: text/plain\r\nContent-Length: {len(body)}\r\n"
                         "Connection: close\r\n\r\n".encode() + body)

    def handle(self) -> None:
        try:
            method, target, version = self.rfile.readline(8192).decode("latin-1").split()
        except ValueError:
            return
        headers = []
        while len(headers) < 200:
            line = self.rfile.readline(65536)
            if line in (b"\r\n", b"\n", b""):
                break
            headers.append(line)
        connect = method.upper() == "CONNECT"
        if connect:
            host, _, port_s = target.rpartition(":")
            scheme, path = "https", ""
        else:
            url = urlsplit(target)
            if url.scheme != "http" or not url.hostname:
                return self._reply(400, "send an absolute http:// URL or CONNECT")
            host, port_s, scheme = url.hostname, str(url.port or 80), "http"
            path = (url.path or "/") + (f"?{url.query}" if url.query else "")
        host = host.strip("[]")
        if not host or not port_s.isdigit():
            return self._reply(400, f"bad target {target!r}")
        port = int(port_s)
        blocked, reason = self.server.decide(host, port, scheme)
        if blocked:
            self.server.log(f"blocked {host}:{port} ({reason})")
            return self._reply(403, f"blocked {host}:{port} ({reason}). "
                                    "Add it to settings.egress.allow if it is expected.")
        try:
            upstream = socket.create_connection((host, port), timeout=30)
        except OSError as exc:
            return self._reply(502, f"could not reach {host}:{port} ({exc})")
        upstream.settimeout(None)
        if connect:
            self.wfile.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        else:
            kept = [h for h in headers if not h.lower().startswith((b"proxy-", b"connection:"))]
            upstream.sendall(f"{method} {path} {version}\r\n".encode("latin-1")
                             + b"".join(kept) + b"Connection: close\r\n\r\n")
        self._relay(upstream)

    def _relay(self, upstream: socket.socket) -> None:
        def down() -> None:
            try:
                while True:
                    data = upstream.recv(65536)
                    if not data:
                        break
                    self.connection.sendall(data)
            except OSError:
                pass
            finally:
                _shut(self.connection)

        t = threading.Thread(target=down, daemon=True)
        t.start()
        try:
            while True:
                data = self.rfile.read1(65536)   # includes anything buffered after the headers
                if not data:
                    break
                upstream.sendall(data)
        except OSError:
            pass
        finally:
            _shut(upstream)
        t.join(timeout=60)
        upstream.close()


def _shut(sock: socket.socket) -> None:
    try:
        sock.shutdown(socket.SHUT_WR)
    except OSError:
        pass


class _Server(socketserver.ThreadingTCPServer):
    daemon_threads = True

    def __init__(self, decide: Callable[[str, int, str], Decision], log: Callable[[str], None]):
        super().__init__(("127.0.0.1", 0), _Handler)
        self.decide = decide
        self.log = log


class EgressProxy:
    """A running proxy. ``env()`` points a child process at it; ``close()`` stops it."""

    def __init__(self, decide: Callable[[str, int, str], Decision], log: Callable[[str], None]):
        self._server = _Server(decide, log)
        self.port = self._server.server_address[1]
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

    @classmethod
    def for_engine(cls, engine: Any, log: Callable[[str], None]) -> "EgressProxy":
        return cls(egress_decider(engine, log), log)

    def env(self) -> Dict[str, str]:
        url = f"http://127.0.0.1:{self.port}"
        env = {name: url for name in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy")}
        env.update({"NO_PROXY": _NO_PROXY, "no_proxy": _NO_PROXY,
                    "NODE_USE_ENV_PROXY": "1"})   # Node's built-in fetch ignores the vars otherwise
        return env

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
