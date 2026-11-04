"""Agent connections: which agent may hand work to which.

Agents hand each other work over many channels — an orchestrator's handoff
(OpenAI Agents, ADK, BeeAI, LangGraph's ``transfer_to_*``, CrewAI's delegate
tools), one coding agent shelling out to another (``claude -p``, ``codex
exec``), an agent served as an MCP server, and A2A. :func:`agent_message`
normalizes each to one shape, ``{from, to, channel}``, and one table decides
them all (``settings.agent_connections``, from the signed org policy)::

    agent_connections:
      mode: enforce              # observe | enforce; absent = off
      agents:                    # registry: one id per agent, every name it goes by
        agt_deploy:
          name: deploy-bot
          aliases: [crewai:Deploy Engineer, a2a:https://deploy.internal, mcp:deploy-server]
          public_key: <base64 raw Ed25519 public key>
      allow:
        - {from: planner, to: deploy-bot}
        - {from: support-triage, to: billing-assistant, action: ask, channels: [a2a]}

Names, ids and aliases are interchangeable everywhere: each is resolved to the
agent's id before matching, case- and separator-insensitively, so ``Deploy
Bot``, ``deploy_bot`` and ``transfer_to_deploy_bot``'s target all meet. An
alias may carry the channel it is known on (``a2a:<url>``, ``mcp:<server>``,
``<framework>:<name>``). A pair with no entry is denied (enforce) or flagged
(observe); ``action: ask`` routes it to human approval; ``*`` matches anyone.

The sender's check can be skipped by an agent without Prismor, so the receiver
checks too. The sender attaches a short-lived JWT (RFC 7519, EdDSA per RFC
8037) signed with its agent key — the Ed25519 key that signs its telemetry
receipts — with ``sub`` = caller, ``aud`` = target and, when it acts for a
user, ``act`` (RFC 8693). Any JWT library verifies it; :func:`asgi_guard`
verifies it against ``public_key`` and the same ``allow`` table before the
message reaches its agent. Legacy ``peers: {name: key}`` is still read.
"""
from __future__ import annotations

import base64
import json
import re
import time
import uuid
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

HEADER = "x-prismor-caller"
RULE_ID = "agent-connection"
TOKEN_TTL = 60  # seconds a signed caller header stays valid
ISSUER = "prismor"

_SEP = re.compile(r"[\s_\-]+")


def norm(name: Any) -> str:
    return _SEP.sub("-", str(name or "").strip().lower()).strip("-")


class ConnectionPolicy:
    def __init__(self) -> None:
        self.mode: Optional[str] = None  # None = feature off
        self.allow: List[Dict[str, Any]] = []
        self.names: Dict[str, str] = {}   # id -> display name
        self.keys: Dict[str, str] = {}    # id -> base64 Ed25519 public key
        self._alias: Dict[str, str] = {}  # normalized name/alias -> id
        self.source = ""

    @classmethod
    def from_settings(cls, settings: Dict[str, Any], *, source: str = "") -> "ConnectionPolicy":
        pol = cls()
        pol.source = source
        raw = settings.get("agent_connections")
        if not isinstance(raw, dict):
            return pol
        mode = str(raw.get("mode") or "").lower()
        pol.mode = mode if mode in ("observe", "enforce") else None
        agents = raw.get("agents")
        for aid, spec in (agents.items() if isinstance(agents, dict) else []):
            spec = spec if isinstance(spec, dict) else {}
            aid = str(aid)
            pol.names[aid] = str(spec.get("name") or aid)
            for alias in [aid, spec.get("name"), *(spec.get("aliases") or [])]:
                if alias:
                    pol._alias.setdefault(norm(alias), aid)
            # ponytail: "crewai:Deploy Engineer" also answers to the bare name, so an
            # adapter that does not say which framework it is still resolves; the
            # first agent to claim a bare name keeps it.
            for alias in spec.get("aliases") or []:
                if ":" in str(alias) and not str(alias).startswith(("a2a:", "mcp:")):
                    pol._alias.setdefault(norm(str(alias).split(":", 1)[1]), aid)
            if spec.get("public_key"):
                pol.keys[aid] = str(spec["public_key"])
        peers = raw.get("peers")
        for name, key in (peers.items() if isinstance(peers, dict) else []):
            if key:
                pol.keys.setdefault(pol.resolve(name), str(key))
        for entry in raw.get("allow") or []:
            if isinstance(entry, dict) and entry.get("from") and entry.get("to"):
                action = str(entry.get("action") or "allow").lower()
                channels = entry.get("channels")
                pol.allow.append({
                    "from": "*" if entry["from"] == "*" else pol.resolve(entry["from"]),
                    "to": "*" if entry["to"] == "*" else pol.resolve(entry["to"]),
                    "action": action if action in ("allow", "ask") else "allow",
                    "channels": {str(c) for c in channels} if isinstance(channels, list) else None,
                })
        return pol

    @property
    def enabled(self) -> bool:
        return self.mode is not None

    def resolve(self, name: Any, kind: str = "") -> str:
        """The agent id ``name`` stands for; an unregistered name resolves to itself."""
        if kind and norm(f"{kind}:{name}") in self._alias:
            return self._alias[norm(f"{kind}:{name}")]
        return self._alias.get(norm(name), norm(name))

    def known(self, name: Any, kind: str = "") -> bool:
        return bool(kind) and norm(f"{kind}:{name}") in self._alias or norm(name) in self._alias

    def label(self, aid: str) -> str:
        return self.names.get(aid, aid)

    def decide(self, src: str, dst: str, channel: str = "") -> str:
        """``allow`` | ``ask`` | ``deny`` for agent ``src`` handing work to ``dst``."""
        src, dst = self.resolve(src), self.resolve(dst)
        for e in self.allow:
            if (e["from"] in (src, "*") and e["to"] in (dst, "*")
                    and (e["channels"] is None or channel in e["channels"])):
                return e["action"]
        return "deny"

    def finding(self, msg: Dict[str, str], index: int, session_id: str) -> Optional[Dict[str, Any]]:
        """The finding for one agent message, or None when the connection allows it."""
        verdict = self.decide(msg["from"], msg["to"], msg.get("channel", ""))
        if verdict == "allow":
            return None
        src, dst = self.label(self.resolve(msg["from"])), self.label(self.resolve(msg["to"]))
        fid = f"{RULE_ID}-{index}"
        f: Dict[str, Any] = {
            "id": f"{session_id}:{fid}" if session_id else fid,
            "severity": "HIGH",
            "category": "agent-connection",
            "ruleId": RULE_ID,
            "eventIndex": index,
            "fromAgent": src,
            "toAgent": dst,
            "channel": msg.get("channel", ""),
            "evidence": f"{src} → {dst} ({msg.get('channel') or 'handoff'})",
            "mode": self.mode,
        }
        if verdict == "ask":
            f.update(action="step_up", mode="enforce", title=f"{src} → {dst} needs approval",
                     remediation="Approve it, or change the connection to allow in Agent flows.")
        else:
            # Connected, just not over this channel: say so, or the admin goes
            # looking for an edge that is already there.
            rs, rd = self.resolve(msg["from"]), self.resolve(msg["to"])
            over = sorted({c for e in self.allow if e["from"] in (rs, "*") and e["to"] in (rd, "*")
                           for c in (e["channels"] or ())})
            if over:
                f.update(action="block", title=f"{src} may hand work to {dst} only over {', '.join(over)}, not {msg.get('channel') or 'handoff'}",
                         remediation=f"Tick {msg.get('channel') or 'handoff'} on the {src} → {dst} connection in Agent flows if this is intended.")
            else:
                f.update(action="block", title=f"No connection policy lets {src} hand work to {dst}",
                         remediation=f"Add a connection from {src} to {dst} in Agent flows if this is intended.")
        f["message"] = f["title"]
        if f["mode"] == "enforce" and self.source == "remote":
            f["authoritative"] = True
        return f


# -- one shape for every channel ------------------------------------------------

# A coding agent run headless by another: the prompt it is handed is the message.
_CLI = [(re.compile(rf"(?:^|[;&|(]|\$\()\s*(?:\S+=\S+\s+)*(?:\S*/)?{pat}"), name) for pat, name in (
    (r"claude\s+(?:\S+\s+)*?(?:-p|--print)\b", "claude"),
    (r"codex\s+exec\b", "codex"),
    (r"gemini\s+(?:\S+\s+)*?(?:-p|--prompt)\b", "gemini"),
    (r"opencode\s+run\b", "opencode"),
    (r"copilot\s+(?:\S+\s+)*?(?:-p|--prompt)\b", "copilot"),
    (r"cursor-agent\s+(?:\S+\s+)*?(?:-p|--print)\b", "cursor"),
)]
_CREW_DELEGATE = {"delegate-work", "delegate-work-to-coworker", "ask-question", "ask-question-to-coworker"}


def _arg(meta: Dict[str, Any], key: str) -> Any:
    """``key`` from wherever an adapter put the tool's arguments."""
    pools: Iterable[Any] = [meta.get("kwargs"), meta.get("args"), meta.get("tool_input")]
    for pool in pools:
        for p in (pool if isinstance(pool, list) else [pool]):
            if isinstance(p, dict) and p.get(key):
                return p[key]
    return None


def agent_message(event: Dict[str, Any], policy: ConnectionPolicy) -> Optional[Dict[str, str]]:
    """``{from, to, channel}`` when this event hands work to another agent, else None."""
    meta = event.get("metadata") if isinstance(event.get("metadata"), dict) else {}
    src = str(meta.get("from_agent") or meta.get("agent_name") or event.get("agent") or "")
    tool = str(meta.get("tool_name") or "")
    to, channel = None, "handoff"
    if meta.get("handoff_to"):  # OpenAI Agents, ADK, BeeAI, Vercel AI, the proxy's A2A lane
        to = str(meta["handoff_to"])
        if meta.get("provider") == "a2a":
            channel = "a2a"
            if meta.get("a2a_url") and policy.known(meta["a2a_url"], "a2a"):
                to = policy.resolve(meta["a2a_url"], "a2a")
    elif tool.startswith("transfer_to_"):  # LangGraph supervisor / swarm handoff tools
        to = tool[len("transfer_to_"):]
    elif norm(tool) in _CREW_DELEGATE and _arg(meta, "coworker"):  # CrewAI delegation
        to = str(_arg(meta, "coworker"))
    elif tool.startswith("mcp__") and tool.count("__") >= 2:  # an agent served over MCP
        server = tool.split("__")[1]
        if policy.known(server, "mcp"):
            to, channel = policy.resolve(server, "mcp"), "tool"
    elif event.get("type") == "shell" and event.get("command"):
        cmd = str(event["command"])
        to = next((name for rx, name in _CLI if rx.search(cmd)), None)
        channel = "cli"
    if not to or norm(to) == norm(src):
        return None
    return {"from": src, "to": to, "channel": channel}


# -- signed caller header (a standard JWT) ---------------------------------------

def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def sign_caller(src: str, dst: str, key: Any = None, *, now: Optional[float] = None,
                act: Optional[str] = None) -> Optional[str]:
    """A compact EdDSA JWT proving ``src`` sent this to ``dst``; None without a key."""
    from prismor.runtime.enterprise import receipt_signing as rs

    if key is None:
        if not rs.available():
            return None
        key = rs._load_or_create_key()
        if key is None:
            return None
    iat = int(now if now is not None else time.time())
    claims: Dict[str, Any] = {"iss": ISSUER, "sub": src, "aud": dst, "iat": iat,
                              "exp": iat + TOKEN_TTL, "jti": uuid.uuid4().hex}
    if act:
        claims["act"] = {"sub": act}
    head = _b64(json.dumps({"alg": "EdDSA", "typ": "JWT"}, separators=(",", ":")).encode())
    body = _b64(json.dumps(claims, separators=(",", ":")).encode())
    return f"{head}.{body}.{_b64(key.sign(f'{head}.{body}'.encode()))}"


# ponytail: replay cache is per receiver process and only holds unexpired ids;
# a fleet of receiver replicas behind a load balancer would need a shared one.
_seen: Dict[str, int] = {}


def verify_caller(token: str, dst: str, policy: ConnectionPolicy, *,
                  now: Optional[float] = None) -> str:
    """The verified caller's agent id for a message to ``dst``. Raises ValueError otherwise."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        head, body, sig = token.split(".")
        header, claims = json.loads(_unb64(head)), json.loads(_unb64(body))
    except Exception:
        raise ValueError("malformed caller header")
    if header.get("alg") != "EdDSA":  # never "none", never a key reused as an HMAC secret
        raise ValueError("caller header must be signed with EdDSA")
    src = policy.resolve(claims.get("sub"))
    pub = policy.keys.get(src)
    if not pub:
        raise ValueError(f"{claims.get('sub') or 'caller'} is not a registered agent")
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(pub)).verify(
            _unb64(sig), f"{head}.{body}".encode())
    except (InvalidSignature, ValueError):
        raise ValueError("caller signature does not verify")
    t = int(now if now is not None else time.time())
    if policy.resolve(claims.get("aud")) != policy.resolve(dst):
        raise ValueError("caller header was issued for another agent")
    if not (claims.get("iat", 0) - 5 <= t <= claims.get("exp", 0)):
        raise ValueError("caller header expired")
    for jti, exp in list(_seen.items()):
        if exp < t:
            del _seen[jti]
    jti = str(claims.get("jti") or "")
    if jti in _seen:
        raise ValueError("caller header replayed")
    _seen[jti] = int(claims["exp"])
    return src


def check_inbound(policy: ConnectionPolicy, token: Optional[str], dst: str,
                  *, now: Optional[float] = None) -> Tuple[bool, str]:
    """Receiver side: (allowed, reason) for an A2A message arriving at ``dst``."""
    if not policy.enabled:
        return True, ""
    try:
        if not token:
            raise ValueError("no signed caller header")
        src = verify_caller(token, dst, policy, now=now)
    except ValueError as exc:
        return policy.mode != "enforce", str(exc)
    # ponytail: an `ask` pair is held at the sender; the receiver has no
    # approval queue, so it lets through what the sender's approval released.
    if policy.decide(src, dst, "a2a") in ("allow", "ask"):
        return True, ""
    return (policy.mode != "enforce",
            f"no connection policy lets {policy.label(src)} call {policy.label(policy.resolve(dst))}")


def asgi_guard(app: Callable, *, agent: str, policy: Optional[ConnectionPolicy] = None) -> Callable:
    """Wrap an A2A server's ASGI app so only allowed, signed callers reach ``agent``.

    ``policy`` defaults to the workspace's active policy (the signed org bundle
    this agent pulls), re-read every few seconds so a console change applies
    without a restart.
    """
    cache: Dict[str, Any] = {"at": 0.0, "policy": None}

    def _active() -> ConnectionPolicy:
        if policy is not None:
            return policy
        if time.monotonic() - cache["at"] > 5:  # building the engine costs ~20ms
            from pathlib import Path
            from prismor.runtime.policy_engine import PolicyEngine
            cache.update(at=time.monotonic(), policy=PolicyEngine(Path.cwd()).agent_connections)
        return cache["policy"]

    async def guarded(scope: Dict[str, Any], receive: Callable, send: Callable) -> None:
        if scope.get("type") != "http":
            return await app(scope, receive, send)
        token = dict(scope.get("headers") or []).get(HEADER.encode(), b"").decode() or None
        ok, reason = check_inbound(_active(), token, agent)
        if not ok:
            body = json.dumps({"jsonrpc": "2.0", "id": None,
                               "error": {"code": -32001, "message": f"Blocked by Prismor: {reason}",
                                         "data": {"prismor": "agent_connection"}}}).encode()
            await send({"type": "http.response.start", "status": 403,
                        "headers": [(b"content-type", b"application/json")]})
            await send({"type": "http.response.body", "body": body})
            return
        await app(scope, receive, send)

    return guarded
