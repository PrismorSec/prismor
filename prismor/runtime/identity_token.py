"""Verified end-user identity: check an IdP-issued JWT before trusting a subject.

Without this, the end user a tool call is attributed to is whatever the caller
asserts (``subject: "user:alice"``). That is fine for attribution and useless
for authorization: any caller can claim to be anyone. With ``settings.identity``
configured, a caller presents the user's token from the org's IdP (Okta,
Auth0, Entra, Cognito, WorkOS, ...) and the subject — including its roles —
comes from the verified claims instead.

Config (``settings.identity``, honored only from the signed org policy, or from
eval-server flags on an unmanaged host)::

    identity:
      mode: observe            # off | observe | require
      issuer: https://acme.okta.com/oauth2/default
      audience: [api://support-bot]
      jwks_uri: https://acme.okta.com/oauth2/default/v1/keys
      user_claim: sub          # default sub; e.g. preferred_username, email
      team_claim: team         # optional
      roles_claim: groups      # optional; list or space/comma-separated string

Claim names match exactly first, then as a dotted path into nested claims, so
both ``https://acme.com/roles`` (Auth0) and ``realm_access.roles`` (Keycloak)
work.

Modes:
  observe  verify a token when one is sent; otherwise keep the asserted subject
           (``verified=false``) and tag the event ``identity: missing|invalid``.
  require  a call without a valid token is blocked — except a coding agent's
           hook on an enrolled device, whose identity the enrollment proves.

Verification is PyJWT (``pip install 'prismor[identity]'``). Only asymmetric
algorithms are accepted, so a token signed with ``none`` or with the public key
as an HMAC secret is rejected before any claim is read.
"""
from __future__ import annotations

import sys
from typing import Any, Dict, List, Optional, Tuple

from prismor.runtime.principal import Subject, trusted_device_surface

ALGORITHMS = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"]
MODES = ("off", "observe", "require")
LEEWAY_SECONDS = 60

# Set by `prismor eval-server --identity-*` for hosts without a signed org policy.
_server_config: Optional[Dict[str, Any]] = None
_jwks_clients: Dict[str, Any] = {}


class IdentityError(Exception):
    """The token could not be verified. ``reason`` is safe to log."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def set_server_config(cfg: Optional[Dict[str, Any]]) -> None:
    global _server_config
    _server_config = cfg


def effective_config(policy_cfg: Any) -> Optional[Dict[str, Any]]:
    """The identity config in force, or None when off. The signed policy wins."""
    cfg = policy_cfg if isinstance(policy_cfg, dict) and policy_cfg else _server_config
    if not cfg or str(cfg.get("mode") or "off").lower() == "off":
        return None
    return cfg


def _http_url(value: str) -> bool:
    """Only http(s): urllib would otherwise open file:// (or a custom scheme)
    for an issuer or JWKS URL, turning identity config into a local file read."""
    from urllib.parse import urlparse

    return urlparse(str(value)).scheme in ("http", "https")


def config_errors(cfg: Dict[str, Any]) -> List[str]:
    errs = []
    if str(cfg.get("mode") or "off").lower() not in MODES:
        errs.append(f"identity.mode must be one of {', '.join(MODES)}")
    for key in ("issuer", "jwks_uri", "audience"):
        if not cfg.get(key):
            errs.append(f"identity.{key} is required")
    for key in ("issuer", "jwks_uri"):
        if cfg.get(key) and not _http_url(cfg[key]):
            errs.append(f"identity.{key} must be an http(s) URL")
    return errs


def discover_jwks_uri(issuer: str) -> str:
    """The issuer's ``jwks_uri`` from its OIDC discovery document."""
    import json
    import urllib.request

    url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    if not _http_url(url):
        raise IdentityError(f"issuer must be an http(s) URL, got {issuer!r}")
    try:
        # Scheme checked just above, so this cannot open file:// or custom schemes.
        with urllib.request.urlopen(url, timeout=5) as r:  # nosec B310
            uri = json.load(r).get("jwks_uri")
    except Exception as exc:
        raise IdentityError(f"discovery failed for {url}: {exc}") from None
    if not isinstance(uri, str) or not uri:
        raise IdentityError(f"{url} has no jwks_uri")
    if not _http_url(uri):
        raise IdentityError(f"{url} returned a non-http(s) jwks_uri {uri!r}")
    return uri


def add_cli_args(parser) -> None:
    """The --identity-* flags, shared by eval-server and mcp-gateway."""
    parser.add_argument("--identity-issuer", default=None, help="Verify end-user JWTs from this issuer (turns identity on)")
    parser.add_argument("--identity-audience", action="append", default=None, help="Accepted audience; repeatable")
    parser.add_argument("--identity-jwks", default=None, help="JWKS URL of the issuer's signing keys (default: discovered from the issuer)")
    parser.add_argument("--identity-mode", default="observe", choices=["observe", "require"], help="observe: verify when sent; require: block calls without a valid token (default: observe)")
    parser.add_argument("--identity-user-claim", default="sub", help="Claim holding the user id (default: sub; often preferred_username or email). Nested: a.b")
    parser.add_argument("--identity-team-claim", default=None, help="Claim holding the team id")
    parser.add_argument("--identity-roles-claim", default=None, help="Claim holding roles/groups")


def config_from_args(args) -> Optional[Dict[str, Any]]:
    """--identity-* flags -> a validated config with the JWKS URL discovered,
    or None when no issuer was given. Raises IdentityError when unusable."""
    if not getattr(args, "identity_issuer", None):
        return None
    cfg = {
        "mode": args.identity_mode, "issuer": args.identity_issuer,
        "audience": args.identity_audience, "jwks_uri": args.identity_jwks,
        "user_claim": args.identity_user_claim, "team_claim": args.identity_team_claim,
        "roles_claim": args.identity_roles_claim,
    }
    if not cfg["jwks_uri"]:
        cfg["jwks_uri"] = discover_jwks_uri(cfg["issuer"])
    problems = config_errors(cfg)
    if problems:
        raise IdentityError("; ".join(problems))
    return cfg


def _jwks_client(uri: str):
    import jwt

    client = _jwks_clients.get(uri)
    if client is None:
        client = _jwks_clients[uri] = jwt.PyJWKClient(uri, cache_keys=True, lifespan=600, timeout=5)
    return client


def _roles(value: Any) -> Tuple[str, ...]:
    if isinstance(value, str):
        value = value.replace(",", " ").split()
    if isinstance(value, (list, tuple)):
        return tuple(str(v) for v in value if v not in (None, ""))
    return ()


def claim(claims: Dict[str, Any], name: Optional[str]) -> Any:
    """A claim by exact name, else by dotted path into nested objects.

    Exact first, because namespaced claims contain dots
    (``https://acme.com/roles``, Auth0); the path covers nesting
    (``realm_access.roles``, Keycloak).
    """
    if not name:
        return None
    if name in claims:
        return claims[name]
    value: Any = claims
    for part in name.split("."):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


def verify(token: str, cfg: Dict[str, Any]) -> Subject:
    """Verify ``token`` against ``cfg`` and return the subject it proves."""
    problems = config_errors(cfg)
    if problems:
        raise IdentityError("misconfigured: " + "; ".join(problems))
    try:
        import jwt
    except ImportError:
        raise IdentityError("PyJWT not installed (pip install 'prismor[identity]')") from None
    aud = cfg["audience"]
    try:
        key = _jwks_client(str(cfg["jwks_uri"])).get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token, key.key, algorithms=ALGORITHMS,
            audience=list(aud) if isinstance(aud, (list, tuple)) else str(aud),
            issuer=str(cfg["issuer"]), leeway=LEEWAY_SECONDS,
            options={"require": ["exp", "iss", "aud"]},
        )
    except jwt.PyJWKClientError as exc:
        raise IdentityError(f"signing key: {exc}") from None
    except jwt.InvalidTokenError as exc:
        raise IdentityError(f"{type(exc).__name__}: {exc}") from None
    user = claim(claims, str(cfg.get("user_claim") or "sub"))
    if not user:
        raise IdentityError(f"token has no '{cfg.get('user_claim') or 'sub'}' claim")
    team = claim(claims, cfg.get("team_claim"))
    return Subject(
        user_id=str(user),
        team_id=str(team) if team else None,
        org_id=None,
        source="jwt",
        roles=_roles(claim(claims, cfg.get("roles_claim"))),
        claims=claims,
        verified=True,
    )


def apply(
    subject: Subject, token: Optional[str], cfg: Dict[str, Any], *, surface: str, session_id: str = "",
) -> Tuple[Subject, str, Optional[Dict[str, Any]]]:
    """Resolve the subject under ``cfg``: (subject, status, blocking finding or None).

    status is ``verified``, ``device``, ``missing`` or ``invalid: <reason>``.
    """
    status = "missing"
    if token:
        try:
            return verify(token, cfg), "verified", None
        except IdentityError as exc:
            status = f"invalid: {exc.reason}"
            sys.stderr.write(f"[prismor] identity token rejected: {exc.reason}\n")
    elif subject.source == "device" and trusted_device_surface(surface):
        return subject, "device", None

    if str(cfg.get("mode")).lower() != "require":
        return subject, status, None
    return subject, status, {
        "id": f"{session_id}:identity-unverified",
        "ruleId": "identity-unverified",
        "severity": "high",
        # agent-control: blocks in observe mode and cannot be exempted.
        "category": "agent-control",
        "mode": "enforce",
        "title": "End-user identity required — no valid identity token",
        "evidence": status,
        "eventIndex": 0,
        "remediation": (
            "Send the user's IdP token: header X-Prismor-Identity on the eval-server, "
            "or use_subject(token=...) in an SDK adapter. See docs/identity-verification.md."
        ),
    }
