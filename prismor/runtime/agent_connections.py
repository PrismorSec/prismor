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
import shlex
import sys
import threading
import time
import uuid
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

HEADER = "x-prismor-caller"
RULE_ID = "agent-connection"
TOKEN_TTL = 60  # seconds a signed caller header stays valid
MAX_TTL = 300   # the longest lifetime a receiver accepts from any signer
ISSUER = "prismor"

_SEP = re.compile(r"[\s_\-]+")


def norm(name: Any) -> str:
    # A trailing "/" is dropped so a2a:https://host and a2a:https://host/ meet.
    return _SEP.sub("-", str(name or "").strip().lower()).strip("-/")


class ConnectionPolicy:
    def __init__(self) -> None:
        self.mode: Optional[str] = None  # None = feature off
        self.allow: List[Dict[str, Any]] = []
        self.names: Dict[str, str] = {}   # id -> display name
        self.keys: Dict[str, str] = {}    # id -> base64 Ed25519 public key
        self._alias: Dict[str, str] = {}  # normalized name/alias -> id
        self._bare: set = set()           # keys only a "kind:" alias's bare form gave
        self._ambiguous: set = set()      # keys more than one agent claimed
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
        specs = [(str(aid), spec if isinstance(spec, dict) else {})
                 for aid, spec in (agents.items() if isinstance(agents, dict) else [])]
        # Every explicit id, name and alias first, so a bare form below never
        # takes a name another agent registered outright.
        for aid, spec in specs:
            pol.names[aid] = str(spec.get("name") or aid)
            for alias in [aid, spec.get("name"), *(spec.get("aliases") or [])]:
                owner = pol._claim(alias, aid)
                if owner and owner != aid:
                    sys.stderr.write(f"[prismor] agent_connections: {alias!r} names both {owner} and {aid}; "
                                     f"it resolves to {owner}. Give {aid} a distinct name or alias.\n")
            if spec.get("public_key"):
                pol.keys[aid] = str(spec["public_key"])
        # ponytail: "crewai:Deploy Engineer" also answers to the bare name, so an
        # adapter that does not say which framework it is still resolves; the
        # first agent to claim a bare name keeps it.
        for aid, spec in specs:
            for alias in spec.get("aliases") or []:
                if ":" in str(alias) and not str(alias).startswith(("a2a:", "mcp:")):
                    key = norm(str(alias).split(":", 1)[1])
                    if key and (key not in pol._alias or key in pol._bare):
                        pol._bare.add(key)
                        pol._claim(key, aid)
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

    def _claim(self, alias: Any, aid: str) -> Optional[str]:
        """Register ``alias`` for ``aid``; the agent that holds it (first wins)."""
        key = norm(alias)
        if not alias or not key:  # "-" or "/" normalizes to nothing: it would match an unnamed sender
            return None
        owner = self._alias.setdefault(key, aid)
        if owner != aid:
            self._ambiguous.add(key)
        return owner

    def ambiguous(self, name: Any) -> bool:
        """``name`` is claimed by more than one agent, so it can't say which."""
        return norm(name) in self._ambiguous

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
            f.update(action="step_up", title=f"{src} → {dst} needs approval",
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
# The command is parsed, not pattern-matched: quoted text and heredoc bodies
# (commit messages, docs) are data, and a wrapper's own arguments are skipped.
_HEADLESS = {  # binary -> (agent, what makes the run headless: a flag or a subcommand)
    "claude": ("claude", {"-p", "--print"}), "claude-code": ("claude", {"-p", "--print"}),
    "codex": ("codex", {"exec", "e"}), "gemini": ("gemini", {"-p", "--prompt"}),
    "opencode": ("opencode", {"run"}), "copilot": ("copilot", {"-p", "--prompt"}),
    "cursor-agent": ("cursor", {"-p", "--print"}),
}
_NAMED = re.compile("|".join(map(re.escape, _HEADLESS)))
# Commands that run the command after them, and which of their options take a value.
_WRAPPERS = {
    "env": {"-u", "--unset", "-C", "--chdir"}, "doas": {"-u", "-C"},
    "sudo": {"-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U", "-T", "--user", "--group",
             "--chdir", "--host", "--prompt", "--role", "--type", "--other-user", "--close-from"},
    "timeout": {"-s", "--signal", "-k", "--kill-after"}, "nice": {"-n", "--adjustment"},
    "ionice": {"-c", "-n", "-p", "-P", "-u", "--class", "--classdata"}, "stdbuf": {"-i", "-o", "-e"},
    "xargs": {"-I", "-n", "-P", "-d", "-L", "-s", "-E", "-a", "--max-args", "--max-procs",
              "--delimiter", "--arg-file", "--replace"},
    "npx": {"-p", "--package"}, "bunx": {"-p", "--package"}, "pnpx": {"-p", "--package"},
    "exec": {"-a"}, "nohup": set(), "time": set(), "setsid": set(), "command": set(), "builtin": set(),
}
_LINE_FLAGS = {"env": {"-S", "--split-string"}, "npx": {"-c", "--call"}}  # the value is a command line
_RUNNERS = {"npm": {"exec", "x"}, "pnpm": {"exec", "dlx"}, "yarn": {"exec", "dlx"}, "bun": {"x"}}
_KEYWORDS = {"{", "}", "!", "if", "then", "else", "elif", "do", "while", "until"}
_SHELLS = {"sh", "bash", "zsh", "ksh", "dash", "mksh", "fish"}
_PUNCT = "();<>|&\n"


def _substitutions(text: str) -> List[str]:
    """The body of every ``$( )`` and backtick the shell runs (not in single quotes)."""
    out, i, n, dq = [], 0, len(text), False
    while i < n:
        c = text[i]
        if c == "\\":
            i += 2
        elif c == "'" and not dq:
            j = text.find("'", i + 1)
            i = n if j < 0 else j + 1
        elif c == '"':
            dq, i = not dq, i + 1
        elif c == "`":
            j = i + 1
            while j < n and text[j] != "`":
                j += 2 if text[j] == "\\" else 1
            out.append(text[i + 1:j])
            i = j + 1
        elif text.startswith("$(", i):
            depth, j = 1, i + 2
            while j < n and depth:
                d = text[j]
                if d == "\\":
                    j += 2
                    continue
                if d == "'":
                    k = text.find("'", j + 1)
                    j = n if k < 0 else k + 1
                    continue
                depth += (d == "(") - (d == ")")
                j += 1
            out.append(text[i + 2:j - 1])
            i = j
        else:
            i += 1
    return out


def _headless(argv: List[str], depth: int) -> Optional[str]:
    """The agent one simple command runs headless, past env assignments and wrappers."""
    i = 0
    while i < len(argv):
        word = argv[i]
        base = word.rsplit("/", 1)[-1]
        if word in _KEYWORDS or re.match(r"[A-Za-z_][A-Za-z0-9_]*=", word):
            i += 1
            continue
        if base in _RUNNERS and i + 1 < len(argv) and argv[i + 1] in _RUNNERS[base]:
            i, base = i + 1, "npx"  # npm exec / pnpm dlx run a package's binary, as npx does
        if base not in _WRAPPERS:
            break
        i += 1
        while i < len(argv) and argv[i].startswith("-"):
            flag = argv[i]
            i += 1
            if flag == "--":
                break
            if base == "command" and flag in ("-v", "-V"):
                return None  # only looks the name up
            if flag in _LINE_FLAGS.get(base, ()) and i < len(argv):
                return _cli_agent(argv[i], depth + 1)
            if flag in _WRAPPERS[base]:
                i += 1
        if base == "timeout":
            i += 1  # its duration
    if i >= len(argv):
        return None
    base, args = argv[i].rsplit("/", 1)[-1], argv[i + 1:]
    if base == "eval":
        return _cli_agent(" ".join(args), depth + 1)
    if base in _SHELLS:  # sh -c 'script': the script is a command line
        j = 0
        while j < len(args) and args[j][:1] in ("-", "+"):
            flag = args[j]
            j += 1
            if flag in ("-o", "+o", "-O", "+O"):
                j += 1
            elif flag.startswith("-") and not flag.startswith("--") and "c" in flag[1:]:
                return _cli_agent(args[j], depth + 1) if j < len(args) else None
        return None
    hit = _HEADLESS.get(base)
    if hit and hit[1] & {a.split("=", 1)[0] for a in args}:
        return hit[0]
    return None


def _cli_agent(command: str, depth: int = 0) -> Optional[str]:
    """The coding agent ``command`` runs headless (``claude -p``, ``codex exec``, …), else None."""
    if depth > 3 or not _NAMED.search(re.sub(r"[\\'\"]", "", command)):
        return None
    from prismor.runtime.shell_context import heredocs

    # A heredoc body is data (a commit message, a file being written) unless a
    # shell is reading it as its script.
    text, parts, last = command, [], 0
    for h in heredocs(command):
        opener = re.split(r"[;&|(`\n]", command[:h.start])[-1].split()
        if any(w.rsplit("/", 1)[-1] in _SHELLS for w in opener):
            hit = _cli_agent(command[h.body_start:h.body_end], depth + 1)
            if hit:
                return hit
        parts.append(command[last:h.body_start])
        last = h.end
    if parts:
        text = "".join(parts) + command[last:]
    for inner in _substitutions(text):
        hit = _cli_agent(inner, depth + 1)
        if hit:
            return hit
    lex = shlex.shlex(text.replace("\\\n", " "), posix=True, punctuation_chars=_PUNCT)
    lex.whitespace, lex.commenters, lex.whitespace_split = " \t\r", "", True
    try:
        tokens = list(lex)
    except ValueError:  # an unclosed quote: the shell would not run it either
        return None
    argv: List[str] = []
    skip = False
    for tok in tokens + [";"]:
        if skip:
            skip = False
        elif tok and all(c in _PUNCT for c in tok) and not ("(" in tok or ")" in tok) and ("<" in tok or ">" in tok):
            skip = True  # a redirect: its target is not an argument
        elif tok and all(c in _PUNCT for c in tok):
            hit = _headless(argv, depth) if argv else None
            if hit:
                return hit
            argv = []
        else:
            argv.append(tok)
    return None


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
    elif tool == "transfer_to_agent" and _arg(meta, "agent_name"):  # Google ADK: the target is an argument
        to = str(_arg(meta, "agent_name"))
    elif tool.startswith("transfer_to_"):  # LangGraph supervisor / swarm, OpenAI Agents handoffs
        to = tool[len("transfer_to_"):]
    elif norm(tool) in _CREW_DELEGATE and _arg(meta, "coworker"):  # CrewAI delegation
        to = str(_arg(meta, "coworker"))
    elif meta.get("mcp_server") or (tool.startswith("mcp__") and tool.count("__") >= 2):  # an agent served over MCP
        # Hooks name the server inside the tool name; SDK adapters, whose MCP
        # tools keep the server's bare tool name, pass it as mcp_server.
        server = str(meta.get("mcp_server") or tool.split("__")[1])
        if policy.known(server, "mcp"):
            to, channel = policy.resolve(server, "mcp"), "tool"
    elif event.get("type") == "shell" and event.get("command"):
        to, channel = _cli_agent(str(event["command"])), "cli"
    if not to:
        return None
    # The same agent under another of its names is not a message; a name two
    # agents share can't say that, so it is checked (and the clash shown).
    if norm(to) == norm(src) or (policy.resolve(to) == policy.resolve(src)
                                 and not policy.ambiguous(to) and not policy.ambiguous(src)):
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
_seen_lock = threading.Lock()


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
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise ValueError("malformed caller header")
    if header.get("alg") != "EdDSA":  # never "none", never a key reused as an HMAC secret
        raise ValueError("caller header must be signed with EdDSA")
    src = policy.resolve(claims.get("sub"))
    pub = policy.keys.get(src)
    if not pub:
        raise ValueError(f"{str(claims.get('sub') or 'caller')[:80]} is not a registered agent")
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(pub)).verify(
            _unb64(sig), f"{head}.{body}".encode())
    except (InvalidSignature, ValueError):
        raise ValueError("caller signature does not verify")
    t = int(now if now is not None else time.time())
    aud = claims.get("aud")
    auds = aud if isinstance(aud, list) else [aud]
    # Every audience must be this agent: a header issued to several receivers
    # could be replayed at each, since the replay cache is per receiver.
    if not auds or any(policy.resolve(a) != policy.resolve(dst) for a in auds):
        raise ValueError("caller header was issued for another agent")
    iat, exp = claims.get("iat"), claims.get("exp")
    if not all(isinstance(v, (int, float)) and not isinstance(v, bool) for v in (iat, exp)):
        raise ValueError("caller header needs numeric iat and exp")
    if exp - iat > MAX_TTL:  # a long-lived header is a replayable credential
        raise ValueError(f"caller header lives longer than {MAX_TTL}s")
    if not (iat - 5 <= t <= exp):
        raise ValueError("caller header expired")
    jti = str(claims.get("jti") or "")
    if not jti:
        raise ValueError("caller header has no jti, so a replay can't be told apart")
    with _seen_lock:  # a threaded server checks two copies of one header at once
        for seen, until in list(_seen.items()):
            if until < t:
                _seen.pop(seen, None)
        if jti in _seen:
            raise ValueError("caller header replayed")
        _seen[jti] = int(exp)
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
    except Exception:  # whatever a forged header trips over, it is not a valid caller
        return policy.mode != "enforce", "malformed caller header"
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

    def _active() -> Optional[ConnectionPolicy]:
        if policy is not None:
            return policy
        if time.monotonic() - cache["at"] > 5:  # building the engine costs ~20ms
            cache["at"] = time.monotonic()
            try:
                from pathlib import Path
                from prismor.runtime.policy_engine import PolicyEngine
                cache["policy"] = PolicyEngine(Path.cwd()).agent_connections
            except Exception as exc:  # keep the last policy that loaded
                sys.stderr.write(f"[prismor] agent_connections: policy reload failed: {exc!r}\n")
        return cache["policy"]

    async def guarded(scope: Dict[str, Any], receive: Callable, send: Callable) -> None:
        if scope.get("type") != "http":
            return await app(scope, receive, send)
        # Discovery (the Agent Card at /.well-known/agent-card.json) is public:
        # a client fetches it, unsigned, before it can send anything. Only a
        # read, and only under this app's own root (it may be mounted).
        path, root = str(scope.get("path") or ""), str(scope.get("root_path") or "")
        if root and path.startswith(root):
            path = path[len(root):]
        if scope.get("method") in ("GET", "HEAD") and path.startswith("/.well-known/"):
            return await app(scope, receive, send)
        pol = _active()
        if pol is None:  # fail closed: no policy has ever loaded
            ok, reason, status = False, "agent connection policy could not be loaded", 503
        else:
            # Headers are latin-1 bytes (ASGI); a decode that can't fail.
            token = dict(scope.get("headers") or []).get(HEADER.encode(), b"").decode("latin-1") or None
            (ok, reason), status = check_inbound(pol, token, agent), 403
        if ok and reason:  # observe: let it through, but say what enforce would refuse
            # repr: the reason can quote the caller's unverified sub, newlines and all.
            sys.stderr.write(f"[prismor] agent_connections (observe) would refuse a call to {agent}: {reason!r}\n")
        if not ok:
            body = json.dumps({"jsonrpc": "2.0", "id": None,
                               "error": {"code": -32001, "message": f"Blocked by Prismor: {reason}",
                                         "data": {"prismor": "agent_connection"}}}).encode()
            await send({"type": "http.response.start", "status": status,
                        "headers": [(b"content-type", b"application/json")]})
            await send({"type": "http.response.body", "body": body})
            return
        await app(scope, receive, send)

    return guarded
