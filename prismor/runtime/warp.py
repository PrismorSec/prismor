"""``prismor proxy -- <agent> [args...]``: the LLM lane without a base URL.

Pointing an agent at the proxy with ``ANTHROPIC_BASE_URL`` works, but Claude
Code treats a custom base URL as "not first-party" and turns features off
(``/remote-control``, claude.ai connectors). Some agents have no base-URL knob
at all. Warp runs the agent as a child behind a CONNECT proxy instead:

- The child gets ``HTTPS_PROXY`` pointing at a loopback port and a local CA in
  its own environment only. Nothing is added to the system keychain.
- Only the provider API hosts are decrypted. Every other host is tunnelled
  as raw bytes, never decrypted.
- On a decrypted host, only generation paths (``/v1/messages``,
  ``/v1/responses``, ``:generateContent``…) go to the Prismor proxy. OAuth,
  telemetry, token counting and WebSocket upgrades go to the real host.

The agent still believes it talks to api.anthropic.com, so its first-party
checks pass, and every proposed tool call is screened by the same proxy.

Certificates are made with the ``openssl`` CLI: the stdlib cannot build an
X.509 certificate and the package keeps one runtime dependency.
"""
from __future__ import annotations

import os
import secrets
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import threading
from http.client import HTTPConnection, HTTPSConnection
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Optional, Sequence
from urllib.parse import urlsplit

from prismor.runtime.proxy import (
    DEFAULT_UPSTREAMS,
    MAX_BODY_BYTES,
    _ThreadingHTTPServer,
    build_proxy_server,
    generation_route,
    shutdown_proxy,
)
from prismor.runtime.store import prismor_home

#: Hosts agents call for model traffic. Only these are decrypted, and only
#: their generation paths are diverted; each diverted call goes back to the
#: host it was sent to. Seen live 2026-11-21: Codex with a ChatGPT login calls
#: chatgpt.com, agy calls daily-cloudcode-pa, OpenCode's default model calls
#: opencode.ai.
INTERCEPT_HOSTS = frozenset(
    {urlsplit(u["base_url"]).hostname for u in DEFAULT_UPSTREAMS.values()}
    | {"chatgpt.com", "daily-cloudcode-pa.googleapis.com", "cloudcode-pa.googleapis.com",
       "opencode.ai"})

# RFC 9110 7.6.1: meaningful on one connection only, never copied across.
_HOP = frozenset({"connection", "proxy-connection", "keep-alive", "proxy-authenticate",
                  "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade"})

# Where the OS keeps its public roots, for the env vars that REPLACE a trust store.
_SYSTEM_ROOTS = ("/etc/ssl/cert.pem", "/etc/ssl/certs/ca-certificates.crt",
                 "/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/ca-bundle.pem")

_CA_CNF = """[req]
distinguished_name = dn
[dn]
[v3_ca]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
"""


def _openssl(cwd: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["openssl", *args], cwd=str(cwd), capture_output=True, text=True)


def _system_roots(env: Mapping[str, str], own_dir: Path) -> Optional[Path]:
    """The trust store the child would have had without us.

    A SSL_CERT_FILE that is already our bundle (warp inside warp) is skipped,
    or the bundle would nest on every launch.
    """
    candidates = [env.get("SSL_CERT_FILE") or "", ssl.get_default_verify_paths().cafile or ""]
    for c in candidates + list(_SYSTEM_ROOTS):
        if c and Path(c).is_file() and Path(c).parent != own_dir:
            return Path(c)
    return None


class LocalCA:
    """A P-256 root under $PRISMOR_HOME/warp, trusted only by warp children."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.cert = root / "ca.pem"
        self.key = root / "ca.key"

    @classmethod
    def load_or_create(cls, root: Path) -> "LocalCA":
        ca = cls(root)
        root.mkdir(parents=True, exist_ok=True)
        os.chmod(root, 0o700)
        fresh = (ca.cert.exists() and ca.key.exists()
                 and _openssl(root, "x509", "-checkend", "86400", "-noout",
                              "-in", ca.cert.name).returncode == 0)
        if not fresh:
            # Derived state: an expired or broken root is replaced, not reported.
            (root / "ca.cnf").write_text(_CA_CNF, encoding="utf-8")
            for step in (("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", "ca.key"),
                         ("req", "-x509", "-new", "-key", "ca.key", "-sha256", "-days", "825",
                          "-subj", "/CN=Prismor warp local CA", "-config", "ca.cnf",
                          "-extensions", "v3_ca", "-out", "ca.pem")):
                out = _openssl(root, *step)
                if out.returncode != 0:
                    raise RuntimeError(f"openssl {step[0]} failed: {out.stderr.strip()}")
        os.chmod(ca.key, 0o600)
        return ca

    def server_context(self, hosts: Iterable[str]) -> ssl.SSLContext:
        """One leaf with every intercepted host as a SAN, minted per launch.

        ponytail: one leaf for the fixed host list, no SNI callback; add
        per-host minting if routes ever take arbitrary hosts.
        """
        r = self.root
        san = ",".join(f"DNS:{h}" for h in sorted(hosts))
        (r / "leaf.cnf").write_text(
            "[leaf]\nbasicConstraints = critical,CA:FALSE\n"
            "keyUsage = critical,digitalSignature\nextendedKeyUsage = serverAuth\n"
            f"subjectAltName = {san}\nauthorityKeyIdentifier = keyid\n", encoding="utf-8")
        for step in (("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", "leaf.key"),
                     ("req", "-new", "-key", "leaf.key", "-subj", "/CN=prismor-warp",
                      "-config", "ca.cnf", "-out", "leaf.csr"),
                     ("x509", "-req", "-in", "leaf.csr", "-CA", "ca.pem", "-CAkey", "ca.key",
                      "-set_serial", "0x" + secrets.token_hex(8), "-days", "397", "-sha256",
                      "-extfile", "leaf.cnf", "-extensions", "leaf", "-out", "leaf.pem")):
            out = _openssl(r, *step)
            if out.returncode != 0:
                raise RuntimeError(f"openssl {step[0]} failed: {out.stderr.strip()}")
        os.chmod(r / "leaf.key", 0o600)
        chain = r / "leaf-chain.pem"
        chain.write_text((r / "leaf.pem").read_text(encoding="utf-8")
                         + self.cert.read_text(encoding="utf-8"), encoding="utf-8")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(chain), str(r / "leaf.key"))
        # http/1.1 only: an h2 stream would not parse as BaseHTTPRequestHandler input.
        ctx.set_alpn_protocols(["http/1.1"])
        return ctx

    def write_trust_files(self, env: Mapping[str, str]) -> Dict[str, str]:
        """Trust files for the child. Returns env vars to set.

        NODE_EXTRA_CA_CERTS appends to Node's roots, so it gets our CA plus any
        extra file the user already had. SSL_CERT_FILE, CURL_CA_BUNDLE and
        REQUESTS_CA_BUNDLE REPLACE the trust store, so they get our CA plus the
        system roots; a CA-only file there breaks every other HTTPS client the
        agent runs (pip, gcloud).
        """
        ca = self.cert.read_text(encoding="utf-8")
        extra = self.root / "node-extra.pem"
        prior = env.get("NODE_EXTRA_CA_CERTS") or ""
        prior_text = Path(prior).read_text(encoding="utf-8") if prior and Path(prior).is_file() \
            and Path(prior) != extra else ""
        extra.write_text(ca + prior_text, encoding="utf-8")
        bundle = self.root / "ca-bundle.pem"
        roots = _system_roots(env, self.root)
        bundle.write_text(ca + (roots.read_text(encoding="utf-8") if roots else ""), encoding="utf-8")
        if roots is None:
            sys.stderr.write("[prismor] warp: no system root bundle found; non-provider HTTPS "
                             "in the agent may fail. Set SSL_CERT_FILE before launching.\n")
        out = {"NODE_EXTRA_CA_CERTS": str(extra)}
        out.update({k: str(bundle) for k in ("SSL_CERT_FILE", "CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE")})
        return out


def child_env(base: Mapping[str, str], proxy_url: str, trust: Mapping[str, str]) -> Dict[str, str]:
    env = dict(base)
    # The agent must believe it talks to the real host; a leftover base URL from
    # an earlier `prismor proxy` session would defeat that.
    env.pop("ANTHROPIC_BASE_URL", None)
    env.pop("ANTHROPIC_UNIX_SOCKET", None)
    env["HTTPS_PROXY"] = env["https_proxy"] = proxy_url
    no_proxy = [p for p in (env.get("NO_PROXY") or env.get("no_proxy") or "").split(",") if p]
    for local in ("localhost", "127.0.0.1", "::1"):
        if local not in no_proxy:
            no_proxy.append(local)
    env["NO_PROXY"] = env["no_proxy"] = ",".join(no_proxy)
    env.update(trust)
    return env


def _splice(a: socket.socket, b: socket.socket) -> None:
    """Copy bytes both ways until either side closes. Blocks."""
    def pump(src: socket.socket, dst: socket.socket) -> None:
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                dst.sendall(data)
        except OSError:
            pass
        for s in (dst, src):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    t = threading.Thread(target=pump, args=(b, a), daemon=True)
    t.start()
    pump(a, b)
    t.join()


def _is_loopback(addr: str) -> bool:
    return addr == "::1" or addr.startswith("127.") or addr.startswith("::ffff:127.")


class _Decrypted(BaseHTTPRequestHandler):
    """One decrypted connection to an intercepted host."""

    protocol_version = "HTTP/1.1"
    divert_port = 0
    token = ""

    def __init__(self, request, client_address, server, upstream) -> None:
        self.upstream = upstream
        super().__init__(request, client_address, server)

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        pass

    def _relay(self) -> None:
        host, port = self.upstream
        if "chunked" in (self.headers.get("Transfer-Encoding") or "").lower():
            try:
                body = self._read_chunked()  # agy sends its body this way
            except ValueError:
                self.close_connection = True
                self.send_error(413)
                return
        else:
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else None
        # http.client sets Content-Length from the body we pass.
        headers = {k: v for k, v in self.headers.items()
                   if k.lower() not in _HOP and k.lower() != "content-length"}
        if "upgrade" in (self.headers.get("Connection") or "").lower():
            if generation_route(self.path):
                # Codex opens a WebSocket to /v1/responses first. Spliced to the
                # real host it would skip the screen, so refuse it: the client
                # falls back to HTTPS, which is diverted like any other call.
                self.send_error(403, "prismor warp: model traffic must use HTTPS to be screened")
                self.close_connection = True
                return
            self._upgrade(host, port, body)
            return
        if generation_route(self.path) and self.divert_port:
            conn = HTTPConnection("127.0.0.1", self.divert_port, timeout=600)
            headers = {k: v for k, v in headers.items() if k.lower() != "host"}
            headers["Host"] = f"127.0.0.1:{self.divert_port}"
            headers["X-Prismor-Warp"] = self.token
            headers["X-Prismor-Warp-Origin"] = host
        else:
            # ponytail: a fresh upstream connection per request; pool it if the
            # passthrough paths (telemetry, OAuth) ever show up in latency.
            conn = HTTPSConnection(host, port, timeout=600, context=ssl.create_default_context())
        try:
            conn.request(self.command, self.path, body=body, headers=headers)
            resp = conn.getresponse()
        except OSError as exc:
            self.send_error(502, f"prismor warp: upstream error: {exc}")
            return
        try:
            self._answer(resp)
        finally:
            conn.close()

    def _read_chunked(self) -> bytes:
        parts = []
        while True:
            size = int(self.rfile.readline().split(b";")[0].strip() or b"0", 16)
            if size == 0:
                while self.rfile.readline() not in (b"\r\n", b"\n", b""):
                    pass  # trailers
                return b"".join(parts)
            parts.append(self.rfile.read(size))
            self.rfile.readline()  # CRLF after each chunk
            if sum(map(len, parts)) > MAX_BODY_BYTES:
                raise ValueError("chunked body over the proxy's size cap")

    def _answer(self, resp) -> None:
        no_body = self.command == "HEAD" or resp.status in (204, 304) or resp.status < 200
        length = resp.getheader("Content-Length")
        chunked = not no_body and length is None
        self.send_response_only(resp.status, resp.reason)
        for k, v in resp.getheaders():
            if k.lower() not in _HOP:
                self.send_header(k, v)
        if chunked:
            self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        if no_body:
            return
        try:
            # read1: whatever has arrived, so SSE reaches the agent token by token.
            while True:
                data = resp.read1(65536)
                if not data:
                    break
                self.wfile.write(b"%x\r\n%s\r\n" % (len(data), data) if chunked else data)
                self.wfile.flush()
            if chunked:
                self.wfile.write(b"0\r\n\r\n")
        except OSError:
            self.close_connection = True

    def _upgrade(self, host: str, port: int, body: Optional[bytes]) -> None:
        """WebSocket and friends: raw TLS to the real host, never to the proxy.

        The control plane behind /remote-control is exactly what must stay
        first-party, and an HTTP client cannot produce a 101 anyway.
        """
        try:
            raw = socket.create_connection((host, port), timeout=30)
            up = ssl.create_default_context().wrap_socket(raw, server_hostname=host)
            up.settimeout(None)
        except OSError as exc:
            self.send_error(502, f"prismor warp: upstream error: {exc}")
            return
        lines = [f"{self.command} {self.path} {self.request_version}"]
        lines += [f"{k}: {v}" for k, v in self.headers.items()]
        up.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + (body or b""))
        _splice(self.connection, up)
        self.close_connection = True

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = _relay


class _Tunnel(BaseHTTPRequestHandler):
    """The CONNECT proxy the child's HTTPS_PROXY names."""

    protocol_version = "HTTP/1.1"
    hosts: frozenset = INTERCEPT_HOSTS
    tls: Optional[ssl.SSLContext] = None
    decrypted = _Decrypted

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        pass

    def do_CONNECT(self) -> None:  # noqa: N802
        self.close_connection = True
        if not _is_loopback(self.client_address[0]):
            self.send_error(403, "prismor warp: loopback only")  # never an open relay
            return
        host, _, port_s = self.path.rpartition(":")
        host = host.strip("[]").lower()
        try:
            port = int(port_s or 443)
        except ValueError:
            self.send_error(400)
            return
        if host not in self.hosts:
            try:
                up = socket.create_connection((host, port), timeout=30)
                up.settimeout(None)
            except OSError:
                self.send_error(502)
                return
            self.send_response(200, "Connection established")
            self.end_headers()
            _splice(self.connection, up)
            return
        self.send_response(200, "Connection established")
        self.end_headers()
        try:
            tls_sock = self.tls.wrap_socket(self.connection, server_side=True)
        except (ssl.SSLError, OSError):
            return
        self.decrypted(tls_sock, self.client_address, self.server, (host, port))


def start_tunnel(tls: ssl.SSLContext, divert_port: int,
                 hosts: Iterable[str] = INTERCEPT_HOSTS, token: str = "") -> _ThreadingHTTPServer:
    """Bind the CONNECT proxy on a kernel-picked loopback port and serve it."""
    decrypted = type("_D", (_Decrypted,), {"divert_port": divert_port, "token": token})
    handler = type("_T", (_Tunnel,), {"tls": tls, "hosts": frozenset(hosts),
                                      "decrypted": decrypted})
    server = _ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def run_warp(command: Sequence[str], *, mode: str = "observe",
             workspace: Optional[Path] = None, config_path: Optional[Path] = None,
             session_id: str = "", agent_name: str = "",
             judge: str = "", judge_budget_ms: int = 0) -> int:
    """Run ``command`` behind the proxy. Returns the child's exit status."""
    command: List[str] = list(command)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        sys.stderr.write("usage: prismor proxy [--mode …] -- <agent> [args...]\n")
        return 2
    if shutil.which("openssl") is None:
        sys.stderr.write("[prismor] warp needs the openssl CLI to mint its local CA; "
                         "install it or use ANTHROPIC_BASE_URL with `prismor proxy`.\n")
        return 2
    server, ws, _warm, config = build_proxy_server(
        "127.0.0.1", 0, workspace=workspace, mode=mode, config_path=config_path,
        session_id=session_id, agent_name=agent_name,
        judge_budget_ms=judge_budget_ms, judge=judge)
    # One pass-through upstream per decrypted host, picked by the token below.
    for host in INTERCEPT_HOSTS:
        config.upstreams.setdefault(f"warp:{host}", {"base_url": f"https://{host}"})
    token = secrets.token_urlsafe(24)
    server.RequestHandlerClass.warp_token = token
    threading.Thread(target=server.serve_forever, daemon=True).start()
    ca = LocalCA.load_or_create(prismor_home() / "warp")
    tunnel = start_tunnel(ca.server_context(INTERCEPT_HOSTS), server.server_address[1],
                          token=token)
    url = f"http://127.0.0.1:{tunnel.server_address[1]}"
    env = child_env(os.environ, url, ca.write_trust_files(os.environ))

    # stderr only, and only before the child starts: a TUI agent owns the terminal.
    err = sys.stderr.write
    err(f"[prismor] warp: proxy mode {mode}, workspace {ws}\n")
    err(f"[prismor] warp: decrypting {', '.join(sorted(INTERCEPT_HOSTS))}; "
        "generation paths screened, everything else first-party\n")
    err(f"[prismor] warp: CA {ca.cert} (trusted by this child only)\n")
    err(f"[prismor] warp: exec {' '.join(command)}\n")

    try:
        child = subprocess.Popen(command, env=env)
    except OSError as exc:
        err(f"[prismor] warp: cannot run {command[0]}: {exc}\n")
        return 127
    # Ctrl-C reaches the child through the terminal's process group; we only
    # wait. Signals sent to us alone are passed on, so closing the terminal
    # (SIGHUP) does not orphan an agent pointed at a dead port.
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    for sig in (getattr(signal, "SIGTERM", None), getattr(signal, "SIGHUP", None)):
        if sig is not None:
            signal.signal(sig, lambda s, _f: child.send_signal(s))
    try:
        rc = child.wait()
    finally:
        if child.poll() is None:
            child.terminate()
        tunnel.shutdown()
        server.shutdown()
        shutdown_proxy()
    return 128 - rc if rc < 0 else rc
