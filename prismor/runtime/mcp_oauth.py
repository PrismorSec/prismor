"""OAuth sign-in for remote MCP servers behind the gateway.

Remote MCP servers that follow the MCP authorization spec (Linear, Stripe,
Neon, PostHog, Atlassian, …) answer an unauthenticated request with ``401`` and
a ``WWW-Authenticate: Bearer resource_metadata="…"`` challenge instead of
accepting a static API key. Before this module the gateway could only forward
a token pasted into the server's ``headers``, so those servers either needed a
long-lived shared key or could not be fronted at all.

The flow, all stdlib (the runtime's only dependency is pyyaml):

  1. **Discovery** — protected-resource metadata (RFC 9728) names the
     authorization server; its metadata (RFC 8414, or OpenID discovery) gives
     the authorize / token / registration endpoints.
  2. **Client** — a pre-registered ``client_id`` from the server entry's
     ``"oauth"`` block, else dynamic client registration (RFC 7591).
  3. **Sign-in** — ``prismor mcp-gateway login <server>``: authorization code
     with PKCE (S256) and a loopback redirect, carrying the ``resource``
     indicator (RFC 8707) so the token is minted for this server only.
  4. **Use** — the gateway sends the stored access token, refreshes it before
     it expires or on a 401, and when it cannot (no sign-in yet, refresh
     revoked) tells the model which command the human has to run.

Tokens belong to the person who signed in: they are stored under
``$PRISMOR_HOME/mcp-oauth/`` (0600), keyed by the server URL rather than the
config name, so renaming an entry or pointing a name at another host can never
hand a token to a server it was not issued for.
"""

from __future__ import annotations

import base64
import hashlib
import http.server
import json
import os
import re
import secrets
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

#: Refresh this many seconds before the token's stated expiry, so a call that
#: starts just before expiry does not land just after it. Capped at half the
#: token's lifetime, or a server minting 30s tokens would see a refresh on
#: every call.
EXPIRY_SKEW = 60
HTTP_TIMEOUT = 15.0
LOGIN_TIMEOUT = 300.0
CLIENT_NAME = "Prismor MCP Gateway"
PROTOCOL_VERSION = "2025-06-18"
#: Default loopback callback ports are derived from the server URL inside this
#: range. A stable redirect URI lets a dynamically registered client be reused
#: on the next sign-in instead of registering a new app every time.
CALLBACK_PORT_BASE = 33400
CALLBACK_PORT_SPAN = 500


class OAuthError(RuntimeError):
    def __init__(self, message: str, status: int = 0):
        super().__init__(message)
        self.status = status


def _ua() -> str:
    try:
        from importlib.metadata import version
        return "prismor-gateway/" + version("prismor")
    except Exception:
        return "prismor-gateway/0"


# ── url helpers ──────────────────────────────────────────────────────────────

def _is_loopback(host: str) -> bool:
    return host in ("localhost", "127.0.0.1", "::1") or host.endswith(".localhost")


def _require_secure(url: str, what: str) -> str:
    """Endpoints that receive codes, secrets or tokens must be https.

    Plain http is allowed for loopback only (local development servers and
    tests); anything else would put a bearer token on the wire in the clear.
    """
    parts = urllib.parse.urlsplit(url)
    if parts.scheme == "https" or (parts.scheme == "http" and _is_loopback(parts.hostname or "")):
        return url
    raise OAuthError(f"{what} must be https: {url}")


def canonical_resource(url: str) -> str:
    """The server URL as an RFC 8707 resource: lowercase scheme/host, no
    fragment or query, no trailing slash."""
    p = urllib.parse.urlsplit(url.strip())
    path = p.path.rstrip("/")
    netloc = (p.hostname or "").lower()
    if p.port and not ((p.scheme == "https" and p.port == 443) or (p.scheme == "http" and p.port == 80)):
        netloc += f":{p.port}"
    return urllib.parse.urlunsplit((p.scheme.lower(), netloc, path, "", ""))


def _resource_matches(advertised: str, server_url: str) -> bool:
    """RFC 9728 §3.3: the metadata must be about this server. Accept the exact
    URL or a path prefix of it (a server at /mcp may advertise its origin)."""
    a = canonical_resource(advertised)
    s = canonical_resource(server_url)
    return s == a or s.startswith(a + "/")


def _well_known(base: str, suffix: str) -> List[str]:
    """RFC 8414 / 9728 well-known URLs for ``base``: path-inserted first, then
    the origin root."""
    p = urllib.parse.urlsplit(base)
    origin = f"{p.scheme}://{p.netloc}"
    path = p.path.rstrip("/")
    urls = []
    if path:
        urls.append(f"{origin}/.well-known/{suffix}{path}")
    urls.append(f"{origin}/.well-known/{suffix}")
    return urls


# ── http ─────────────────────────────────────────────────────────────────────

def _http_json(url: str, *, data: Optional[Dict[str, Any]] = None,
               form: Optional[Dict[str, str]] = None,
               headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    hdrs = {"Accept": "application/json", "User-Agent": _ua(),
            "MCP-Protocol-Version": PROTOCOL_VERSION}
    hdrs.update(headers or {})
    body = None
    if data is not None:
        body = json.dumps(data).encode("utf-8")
        hdrs["Content-Type"] = "application/json"
    elif form is not None:
        body = urllib.parse.urlencode(form).encode("utf-8")
        hdrs["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(url, data=body, headers=hdrs,
                                 method="POST" if body is not None else "GET")
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:  # scheme checked by callers  # nosec B310
            raw = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            err = json.loads(exc.read().decode("utf-8", errors="replace"))
            detail = str(err.get("error_description") or err.get("error") or "")
        except Exception:
            pass
        raise OAuthError(f"{url} returned HTTP {exc.code}{': ' + detail if detail else ''}", exc.code)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise OAuthError(f"{url} unreachable: {exc}")
    try:
        out = json.loads(raw)
    except ValueError:
        raise OAuthError(f"{url} did not return JSON")
    if not isinstance(out, dict):
        raise OAuthError(f"{url} did not return a JSON object")
    return out


def _try_json(urls: List[str], *, stop_on_server_error: bool = False) -> Optional[Dict[str, Any]]:
    """First URL that answers with a JSON object. With ``stop_on_server_error``
    a 5xx or 429 aborts the search: it says nothing about whether the metadata
    exists, so it must not send discovery down a fallback path."""
    failed = 0
    for url in urls:
        try:
            return _http_json(url)
        except OAuthError as exc:
            if exc.status >= 500 or exc.status == 429:
                failed = exc.status
            continue
    if stop_on_server_error and failed:
        raise OAuthError(f"metadata discovery failed: HTTP {failed}", failed)
    return None


def issuers_match(a: str, b: str) -> bool:
    """RFC 8414 §3.3 simple string comparison, except that a root issuer with
    and without its trailing slash name the same server."""
    if a == b:
        return True
    shorter, longer = sorted((a, b), key=len)
    p = urllib.parse.urlsplit(shorter)
    return longer == shorter + "/" and shorter == f"{p.scheme}://{p.netloc}"


def _as_metadata_urls(issuer: str) -> List[str]:
    """RFC 8414 / OIDC discovery URLs for an issuer, in the order the MCP SDKs
    use. An issuer with a path never falls back to the origin root: that is
    another tenant's metadata."""
    p = urllib.parse.urlsplit(issuer)
    origin = f"{p.scheme}://{p.netloc}"
    path = p.path.rstrip("/")
    if path:
        return [f"{origin}/.well-known/oauth-authorization-server{path}",
                f"{origin}/.well-known/openid-configuration{path}",
                f"{origin}{path}/.well-known/openid-configuration"]
    return [f"{origin}/.well-known/oauth-authorization-server",
            f"{origin}/.well-known/openid-configuration"]


def union_scopes(*scopes: Optional[str]) -> str:
    out: List[str] = []
    for group in scopes:
        for sc in (group or "").split():
            if sc not in out:
                out.append(sc)
    return " ".join(out)


# ── discovery ────────────────────────────────────────────────────────────────

def parse_www_authenticate(value: str) -> Dict[str, str]:
    """Parameters of a ``Bearer`` challenge (``resource_metadata``, ``scope``,
    ``error``). Other schemes are ignored."""
    value = value or ""
    m = re.search(r"\bBearer\b(.*)", value, re.I | re.S)
    if not m:
        return {}
    out: Dict[str, str] = {}
    for key, quoted, bare in re.findall(r'([A-Za-z_][\w-]*)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^\s,]+))', m.group(1)):
        out[key.lower()] = quoted if quoted else bare
    return out


def discover(server_url: str, challenge: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """Find the authorization server for ``server_url``.

    Returns ``{"resource", "issuer", "authorization_endpoint", "token_endpoint",
    "registration_endpoint", "scopes"}``.
    """
    challenge = challenge or {}
    prm_urls = _well_known(server_url, "oauth-protected-resource")
    if challenge.get("resource_metadata"):
        prm_urls.insert(0, _require_secure(challenge["resource_metadata"], "resource metadata URL"))
    prm = _try_json(prm_urls, stop_on_server_error=True)
    resource = canonical_resource(server_url)
    scopes: List[str] = []
    if prm is not None:
        advertised = str(prm.get("resource") or "")
        if advertised and not _resource_matches(advertised, server_url):
            raise OAuthError(f"resource metadata is for {advertised}, not {server_url}")
        servers = prm.get("authorization_servers") or []
        if not servers:
            raise OAuthError(f"{server_url}: resource metadata names no authorization server")
        issuer = str(servers[0])
        scopes = [str(s) for s in prm.get("scopes_supported") or []]
    else:
        # Servers on the 2025-03-26 spec publish authorization-server metadata
        # at their own origin and no resource metadata.
        p = urllib.parse.urlsplit(server_url)
        issuer = f"{p.scheme}://{p.netloc}"
    _require_secure(issuer, "authorization server")
    asm = _try_json(_as_metadata_urls(issuer))
    if asm is None:
        raise OAuthError(f"no authorization-server metadata found for {issuer}")
    # RFC 8414 §3.3: metadata naming another issuer is not this server's.
    if not issuers_match(str(asm.get("issuer") or ""), issuer):
        raise OAuthError(f"authorization server metadata is for {asm.get('issuer')!r}, expected {issuer}")
    for key in ("authorization_endpoint", "token_endpoint"):
        if not asm.get(key):
            raise OAuthError(f"authorization server {issuer} has no {key}")
        _require_secure(str(asm[key]), key)
    if asm.get("registration_endpoint"):
        _require_secure(str(asm["registration_endpoint"]), "registration_endpoint")
    methods = asm.get("code_challenge_methods_supported")
    if isinstance(methods, list) and methods and "S256" not in methods:
        raise OAuthError(f"authorization server {issuer} does not support PKCE S256")
    # MCP scope selection: the challenge, then the resource's scopes, then the
    # authorization server's. Ask for offline_access where the server knows it,
    # or OIDC servers (Okta, Auth0, Entra) issue no refresh token.
    as_scopes = [str(x) for x in asm.get("scopes_supported") or []]
    if challenge.get("scope"):
        scopes = challenge["scope"].split()
    elif not scopes:
        scopes = as_scopes
    if scopes and "offline_access" in as_scopes and "offline_access" not in scopes:
        scopes.append("offline_access")
    return {
        "iss_required": asm.get("authorization_response_iss_parameter_supported") is True,
        "resource": resource,
        "issuer": str(asm.get("issuer") or issuer),
        "authorization_endpoint": str(asm["authorization_endpoint"]),
        "token_endpoint": str(asm["token_endpoint"]),
        "registration_endpoint": str(asm.get("registration_endpoint") or ""),
        "scopes": scopes,
    }


def register_client(registration_endpoint: str, redirect_uri: str) -> Dict[str, Any]:
    """Dynamic client registration (RFC 7591) as a public native client."""
    reg = _http_json(_require_secure(registration_endpoint, "registration_endpoint"), data={
        "client_name": CLIENT_NAME,
        "redirect_uris": [redirect_uri],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
        "application_type": "native",
    })
    if not reg.get("client_id"):
        raise OAuthError("client registration returned no client_id")
    return reg


# ── token store ──────────────────────────────────────────────────────────────

def _store_dir() -> Path:
    from prismor.runtime.store import prismor_home
    return prismor_home() / "mcp-oauth"


def _store_path(server_url: str) -> Path:
    digest = hashlib.sha256(canonical_resource(server_url).encode("utf-8")).hexdigest()[:32]
    return _store_dir() / f"{digest}.json"


def load_record(server_url: str) -> Optional[Dict[str, Any]]:
    path = _store_path(server_url)
    try:
        rec = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, ValueError, OSError):
        return None
    # The file name is a hash; the record names the server it belongs to. A
    # record copied in for another URL is not used.
    if not isinstance(rec, dict) or rec.get("resource") != canonical_resource(server_url):
        return None
    return rec


def save_record(server_url: str, rec: Dict[str, Any]) -> Path:
    path = _store_path(server_url)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    rec = dict(rec, resource=canonical_resource(server_url))
    tmp = path.with_suffix(".tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(rec, fh, indent=2)
    os.replace(tmp, path)
    return path


def delete_record(server_url: str) -> bool:
    try:
        _store_path(server_url).unlink()
        return True
    except FileNotFoundError:
        return False


def _apply_token_response(rec: Dict[str, Any], tok: Dict[str, Any]) -> Dict[str, Any]:
    if not tok.get("access_token"):
        raise OAuthError("token endpoint returned no access_token")
    if str(tok.get("token_type") or "bearer").lower() != "bearer":
        raise OAuthError(f"unsupported token_type {tok.get('token_type')!r}")
    rec = dict(rec)
    rec["access_token"] = str(tok["access_token"])
    # A refresh response may omit the refresh token: keep the one we have.
    if tok.get("refresh_token"):
        rec["refresh_token"] = str(tok["refresh_token"])
    try:
        lifetime = int(tok["expires_in"]) if tok.get("expires_in") else 0
    except (TypeError, ValueError):
        lifetime = 0
    now = int(time.time())
    rec["expires_at"] = now + lifetime if lifetime > 0 else None
    rec["refresh_at"] = now + max(lifetime - EXPIRY_SKEW, lifetime // 2) if lifetime > 0 else None
    if tok.get("scope"):
        rec["scope"] = str(tok["scope"])
    return rec


def _client_auth(rec: Dict[str, Any], form: Dict[str, str]) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    form["client_id"] = rec["client_id"]
    if rec.get("client_secret"):
        if rec.get("token_endpoint_auth_method") == "client_secret_post":
            form["client_secret"] = rec["client_secret"]
        else:
            basic = f"{urllib.parse.quote(rec['client_id'], safe='')}:{urllib.parse.quote(rec['client_secret'], safe='')}"
            headers["Authorization"] = "Basic " + base64.b64encode(basic.encode()).decode()
    return headers


def refresh_record(rec: Dict[str, Any]) -> Dict[str, Any]:
    if not rec.get("refresh_token"):
        raise OAuthError("no refresh token")
    form = {"grant_type": "refresh_token", "refresh_token": rec["refresh_token"],
            "resource": rec["resource"]}
    headers = _client_auth(rec, form)
    tok = _http_json(_require_secure(rec["token_endpoint"], "token_endpoint"),
                     form=form, headers=headers)
    return _apply_token_response(rec, tok)


# ── gateway side ─────────────────────────────────────────────────────────────

def login_hint(name: str) -> str:
    return (f"MCP server '{name}' needs sign-in (OAuth). Ask the user to run "
            f"`prismor mcp-gateway login {name}` on this machine, then retry.")


class OAuthSession:
    """The token side of one remote upstream. Thread-safe; never interactive."""

    def __init__(self, name: str, server_url: str):
        self.name = name
        self.server_url = server_url
        self._lock = threading.Lock()
        self._rec: Optional[Dict[str, Any]] = None

    def _record(self) -> Optional[Dict[str, Any]]:
        # Re-read when nothing is cached so a `login` run while the gateway is
        # up takes effect on the next call, without a restart.
        if self._rec is None:
            self._rec = load_record(self.server_url)
        return self._rec

    def authorization(self) -> Optional[str]:
        """The ``Authorization`` header value to send, refreshing a token that
        is about to expire. None when the user has not signed in."""
        with self._lock:
            rec = self._record()
            if rec is None:
                return None
            due = rec.get("refresh_at") or rec.get("expires_at")
            if due and time.time() >= due and rec.get("refresh_token"):
                try:
                    self._rec = rec = refresh_record(rec)
                    save_record(self.server_url, rec)
                except OAuthError as exc:
                    sys.stderr.write(f"[prismor-gateway] {self.name}: token refresh failed: {exc}\n")
            return "Bearer " + rec["access_token"]

    def insufficient_scope(self, scope: str) -> None:
        """A 403 ``insufficient_scope``: remember what the server asked for so
        the next ``login`` requests it on top of what was already granted."""
        with self._lock:
            rec = load_record(self.server_url)
            if rec is not None and scope:
                rec["step_up_scope"] = union_scopes(rec.get("step_up_scope"), scope)
                save_record(self.server_url, rec)
                self._rec = rec

    def unauthorized(self, sent: Optional[str]) -> bool:
        """The server rejected ``sent``. Returns True when a different token is
        now available (refreshed, or a newer sign-in on disk) and the request
        should be retried once."""
        with self._lock:
            disk = load_record(self.server_url)
            if disk is not None and sent != "Bearer " + disk.get("access_token", ""):
                self._rec = disk
                return True
            rec = disk or self._rec
            if rec is None or not rec.get("refresh_token"):
                self._rec = None
                return False
            try:
                self._rec = refresh_record(rec)
                save_record(self.server_url, self._rec)
                return True
            except OAuthError as exc:
                sys.stderr.write(f"[prismor-gateway] {self.name}: token refresh failed: {exc}\n")
                self._rec = None
                return False


# ── login (interactive, CLI) ─────────────────────────────────────────────────

def _pkce() -> Dict[str, str]:
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return {"verifier": verifier, "challenge": challenge}


def _probe_challenge(server_url: str, headers: Dict[str, str]) -> Dict[str, str]:
    """POST an ``initialize`` without credentials to read the 401 challenge."""
    hdrs = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
            "User-Agent": _ua()}
    hdrs.update({k: v for k, v in headers.items() if k.lower() != "authorization"})
    body = json.dumps({"jsonrpc": "2.0", "id": "prismor-oauth-probe", "method": "initialize",
                       "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                                  "clientInfo": {"name": "prismor-gateway", "version": "0"}}})
    req = urllib.request.Request(server_url, data=body.encode(), headers=hdrs, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT):  # http(s) enforced by the gateway config  # nosec B310
            return {}
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            return parse_www_authenticate(exc.headers.get("WWW-Authenticate") or "")
        return {}
    except (urllib.error.URLError, OSError, ValueError):
        return {}


class _CallbackHandler(http.server.BaseHTTPRequestHandler):
    result: Dict[str, str] = {}
    done: Optional[threading.Event] = None

    def do_GET(self):  # noqa: N802
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path != "/callback":
            self.send_response(404)
            self.end_headers()
            return
        q = dict(urllib.parse.parse_qsl(parsed.query))
        type(self).result.update(q)
        ok = "code" in q
        body = ("<h3>Signed in. You can close this tab and return to the terminal.</h3>" if ok
                else "<h3>Sign-in failed: " + _html_escape(q.get("error_description") or q.get("error") or "no code")
                + "</h3>")
        self.send_response(200 if ok else 400)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))
        if type(self).done is not None:
            type(self).done.set()

    def log_message(self, *args):  # silence the default access log
        pass


def default_callback_port(server_url: str) -> int:
    digest = hashlib.sha256(canonical_resource(server_url).encode("utf-8")).digest()
    return CALLBACK_PORT_BASE + int.from_bytes(digest[:4], "big") % CALLBACK_PORT_SPAN


def _bind_callback(port: int, handler, fixed: bool) -> http.server.HTTPServer:
    try:
        return http.server.HTTPServer(("127.0.0.1", port), handler)
    except OSError:
        if fixed:
            raise OAuthError(f"callback port {port} is in use")
        # The derived port is taken: any free port works, at the cost of
        # registering a new client for the new redirect URI.
        return http.server.HTTPServer(("127.0.0.1", 0), handler)


def _html_escape(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def login(name: str, server_url: str, *, headers: Optional[Dict[str, str]] = None,
          oauth_cfg: Optional[Dict[str, Any]] = None, open_browser: bool = True,
          timeout: float = LOGIN_TIMEOUT, port: int = 0,
          on_authorize_url: Optional[Callable[[str], None]] = None) -> Dict[str, Any]:
    """Run the browser sign-in for one server and store its tokens.

    ``on_authorize_url`` receives the URL the human must open (printed by the
    CLI; tests follow it programmatically).
    """
    oauth_cfg = oauth_cfg or {}
    challenge = _probe_challenge(server_url, headers or {})
    meta = discover(server_url, challenge)
    prev = load_record(server_url) or {}

    done = threading.Event()
    handler = type("_Handler", (_CallbackHandler,), {"result": {}, "done": done})
    httpd = _bind_callback(port or default_callback_port(server_url), handler, fixed=bool(port))
    redirect_uri = f"http://127.0.0.1:{httpd.server_address[1]}/callback"
    thread = threading.Thread(target=httpd.serve_forever, name="prismor-oauth-cb", daemon=True)
    thread.start()
    try:
        if oauth_cfg.get("client_id"):
            client = {"client_id": str(oauth_cfg["client_id"])}
            if oauth_cfg.get("client_secret"):
                client["client_secret"] = str(oauth_cfg["client_secret"])
        elif (prev.get("registered") and prev.get("redirect_uri") == redirect_uri
              and issuers_match(str(prev.get("issuer") or ""), meta["issuer"])):
            # Same issuer, same redirect: reuse the client registered last time
            # rather than adding another app to the user's account.
            client = {k: prev[k] for k in ("client_id", "client_secret", "token_endpoint_auth_method")
                      if prev.get(k)}
        elif meta["registration_endpoint"]:
            client = register_client(meta["registration_endpoint"], redirect_uri)
            client["registered"] = True
        else:
            raise OAuthError(
                f"{meta['issuer']} does not support dynamic client registration; add "
                f'"oauth": {{"client_id": "…"}} to the \'{name}\' server entry')
        scopes = oauth_cfg.get("scopes")
        if isinstance(scopes, list):
            scopes = " ".join(str(x) for x in scopes)
        if not scopes:
            # Keep what was granted before and add what a 403 asked for since,
            # so stepping up for one tool does not drop another's access.
            same_as = issuers_match(str(prev.get("issuer") or ""), meta["issuer"])
            scopes = union_scopes(prev.get("scope") if same_as else "",
                                  prev.get("step_up_scope") if same_as else "",
                                  " ".join(meta["scopes"]))
        scopes = scopes.split()
        pkce = _pkce()
        state = secrets.token_urlsafe(24)
        params = {"response_type": "code", "client_id": client["client_id"],
                  "redirect_uri": redirect_uri, "state": state,
                  "code_challenge": pkce["challenge"], "code_challenge_method": "S256",
                  "resource": meta["resource"]}
        if scopes:
            params["scope"] = " ".join(scopes)
        sep = "&" if "?" in meta["authorization_endpoint"] else "?"
        url = meta["authorization_endpoint"] + sep + urllib.parse.urlencode(params)
        if on_authorize_url is not None:
            on_authorize_url(url)
        if open_browser:
            try:
                import webbrowser
                webbrowser.open(url)
            except Exception:
                pass
        if not done.wait(timeout):
            raise OAuthError(f"no sign-in within {int(timeout)}s")
        result = handler.result
    finally:
        httpd.shutdown()
        httpd.server_close()

    if result.get("state") != state:
        raise OAuthError("sign-in response had the wrong state (possible CSRF); try again")
    if "code" not in result:
        raise OAuthError("sign-in refused: " + (result.get("error_description") or result.get("error") or "no code"))
    # RFC 9207: a present iss must name the server we sent the user to, and
    # one the server promised to send must not be missing (mix-up defence).
    if result.get("iss") is not None:
        if not issuers_match(result["iss"], meta["issuer"]):
            raise OAuthError(f"sign-in response came from {result['iss']}, expected {meta['issuer']}")
    elif meta.get("iss_required"):
        raise OAuthError(f"sign-in response from {meta['issuer']} is missing its iss parameter")

    rec: Dict[str, Any] = {
        "server": name, "issuer": meta["issuer"], "token_endpoint": meta["token_endpoint"],
        "client_id": client["client_id"], "resource": meta["resource"],
    }
    if client.get("client_secret"):
        rec["client_secret"] = client["client_secret"]
    if client.get("token_endpoint_auth_method"):
        rec["token_endpoint_auth_method"] = client["token_endpoint_auth_method"]
    if client.get("registered"):
        rec["registered"] = True
        rec["redirect_uri"] = redirect_uri
    form = {"grant_type": "authorization_code", "code": result["code"],
            "redirect_uri": redirect_uri, "code_verifier": pkce["verifier"],
            "resource": meta["resource"]}
    tok_headers = _client_auth(rec, form)
    tok = _http_json(meta["token_endpoint"], form=form, headers=tok_headers)
    rec = _apply_token_response(rec, tok)
    save_record(server_url, rec)
    return rec


def status(server_url: str) -> str:
    rec = load_record(server_url)
    if rec is None:
        return "not signed in"
    exp = rec.get("expires_at")
    if not exp:
        left = "no expiry"
    elif exp > time.time():
        left = f"expires in {int((exp - time.time()) // 60)}m"
    else:
        left = "expired" + (", will refresh" if rec.get("refresh_token") else "")
    return f"signed in via {rec.get('issuer')} ({left})"
