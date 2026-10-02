"""End-user principal (subject) resolution for Prismor.

A coding agent on a laptop maps one-to-one to a device, so device identity was a
fine proxy for "who is acting." A framework agent deployed in production serves
*many* end-users from one process, so each tool call must be attributed to the
calling user for per-user policy and telemetry.

A :class:`Subject` is resolved, in priority order, from:

1. an explicit value passed by the adapter (``resolve_subject("user:alice")`` or
   a pre-built ``Subject``) — the production multi-tenant path;
2. a context-managed subject set via :func:`use_subject` — the per-request path
   for a single deployed agent serving many users (set it in your request
   handler; every tool call in that context is attributed to that user);
3. the ``PRISMOR_SUBJECT`` environment variable — the single-tenant / CI path;
4. the enrolled device identity (``prismor.runtime.enterprise.identity``) — preserves the
   existing per-device behavior when no per-user context is supplied;
5. an anonymous local subject — unenrolled local use.

``PRISMOR_SUBJECT`` accepts:
    "alice"                          → user_id=alice
    "user:alice"                     → user_id=alice
    "user=alice;team=data;org=acme"  → user/team/org (``;`` or ``,`` separated)
"""
from __future__ import annotations

import os
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, Optional, Tuple, Union


@dataclass(frozen=True)
class Subject:
    """The principal a tool call is attributed to."""

    user_id: Optional[str] = None
    team_id: Optional[str] = None
    org_id: Optional[str] = None
    source: str = "anonymous"  # explicit | context | env | device | jwt | anonymous
    # Roles and claims come only from a verified identity token: a
    # caller-asserted string can name a user, never grant itself a role.
    roles: Tuple[str, ...] = ()
    claims: Dict[str, Any] = field(default_factory=dict, hash=False, compare=False)
    verified: bool = False

    def as_dict(self) -> Dict[str, Any]:
        """Compact dict for event metadata / telemetry (omits empty fields)."""
        out: Dict[str, Any] = {"source": self.source}
        if self.user_id:
            out["user_id"] = self.user_id
        if self.team_id:
            out["team_id"] = self.team_id
        if self.org_id:
            out["org_id"] = self.org_id
        if self.roles:
            out["roles"] = list(self.roles)
        if self.verified:
            out["verified"] = True
        return out

    @property
    def is_identified(self) -> bool:
        return bool(self.user_id)


def _parse_subject_string(value: str, source: str) -> Optional[Subject]:
    value = value.strip()
    if not value:
        return None
    # key=value pairs
    if "=" in value:
        fields: Dict[str, str] = {}
        for part in value.replace(",", ";").split(";"):
            part = part.strip()
            if not part or "=" not in part:
                continue
            k, v = part.split("=", 1)
            fields[k.strip().lower()] = v.strip()
        return Subject(
            user_id=fields.get("user") or fields.get("user_id"),
            team_id=fields.get("team") or fields.get("team_id"),
            org_id=fields.get("org") or fields.get("org_id"),
            source=source,
        )
    # "user:alice"
    if ":" in value:
        prefix, rest = value.split(":", 1)
        if prefix.strip().lower() in {"user", "user_id"}:
            return Subject(user_id=rest.strip(), source=source)
    # bare token → user id
    return Subject(user_id=value, source=source)


# Per-request subject override (multi-tenant production agents). Thread/async-safe.
_CURRENT_SUBJECT: ContextVar[Optional[Subject]] = ContextVar("prismor_subject", default=None)
# The end user's IdP token for the same request, verified against
# settings.identity at evaluation time (see identity_token.py).
_CURRENT_TOKEN: ContextVar[Optional[str]] = ContextVar("prismor_identity_token", default=None)

# Surfaces where the enrolled device IS the actor: a developer's coding agent.
# An SDK adapter or eval-server on an enrolled host serves other people, so
# there the device fallback proves nothing about the end user.
_DEVICE_SURFACES = frozenset({"hook", "mirror"})


def trusted_device_surface(surface: Optional[str]) -> bool:
    return str(surface or "") in _DEVICE_SURFACES


def is_verified(subject: Optional[Subject], surface: Optional[str]) -> bool:
    """Whether ``subject`` is proven rather than asserted, on this surface."""
    if subject is None:
        return False
    return subject.verified or (subject.source == "device" and trusted_device_surface(surface))


def current_token() -> Optional[str]:
    """The end user's IdP token for this call.

    Per-request ``use_subject(token=...)`` wins. A long-lived single-user
    process (an MCP gateway the host starts for one person) can instead point
    ``PRISMOR_IDENTITY_TOKEN_FILE`` at a file an external refresher rewrites:
    it is re-read on every call, because tokens expire long before the process
    does. ``PRISMOR_IDENTITY_TOKEN`` is the static fallback.
    """
    token = _CURRENT_TOKEN.get()
    if token:
        return token
    path = os.environ.get("PRISMOR_IDENTITY_TOKEN_FILE")
    if path:
        try:
            with open(path, encoding="utf-8") as fh:
                value = fh.read().strip()
            if value:
                return value[7:].strip() if value.lower().startswith("bearer ") else value
        except OSError:
            pass
    return os.environ.get("PRISMOR_IDENTITY_TOKEN") or None


@contextmanager
def use_subject(
    value: Optional[Union[str, Subject]] = None, *, token: Optional[str] = None,
) -> Iterator[Subject]:
    """Attribute all tool calls inside this block to ``value``.

    Use in a request handler so one deployed agent serving many users tags each
    user's calls correctly without re-guarding tools per request::

        with use_subject("user:alice"):
            Runner.run_sync(agent, prompt)

    Pass the user's IdP token as ``token=`` when the org verifies identity
    (``settings.identity``); the verified claims then replace ``value``::

        with use_subject(token=request.headers["Authorization"].removeprefix("Bearer ")):
            Runner.run_sync(agent, prompt)
    """
    subject = value if isinstance(value, Subject) else (
        _parse_subject_string(value, source="context") if isinstance(value, str) else None
    )
    reset_subject = _CURRENT_SUBJECT.set(subject)
    reset_token = _CURRENT_TOKEN.set(token)
    try:
        yield subject or Subject(source="anonymous")
    finally:
        _CURRENT_SUBJECT.reset(reset_subject)
        _CURRENT_TOKEN.reset(reset_token)


def _from_device() -> Optional[Subject]:
    try:
        from prismor.runtime.enterprise import identity as _identity
        ident = _identity.load_identity()
        if not ident:
            return None
        return Subject(
            user_id=ident.get("user_id"),
            org_id=ident.get("org_id"),
            source="device",
        )
    except Exception:
        return None


def resolve_subject(value: Optional[Union[str, Subject]] = None) -> Subject:
    """Resolve the active principal. See module docstring for the priority order."""
    if isinstance(value, Subject):
        return value
    if isinstance(value, str):
        parsed = _parse_subject_string(value, source="explicit")
        if parsed:
            return parsed

    ctx = _CURRENT_SUBJECT.get()
    if ctx is not None and ctx.is_identified:
        return ctx

    env = os.environ.get("PRISMOR_SUBJECT")
    if env:
        parsed = _parse_subject_string(env, source="env")
        if parsed:
            return parsed

    device = _from_device()
    if device:
        return device

    return Subject(source="anonymous")
