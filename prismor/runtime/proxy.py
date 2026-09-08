"""prismor/runtime/proxy.py — the LLM lane: a policy proxy for model traffic.

Prismor already screens agents at the places where a tool call *executes* —
coding-agent hooks, the MCP gateway, the mirrored built-ins, in-process SDK
adapters. All of those require the agent to cooperate: something has to be
hooked, wired, or imported. This surface requires only that the agent's model
traffic pass through a URL we control::

    ANTHROPIC_BASE_URL=http://127.0.0.1:7080  claude
    OPENAI_BASE_URL=http://127.0.0.1:7080/v1  codex

That is the one lever that works on an agent Prismor cannot hook, which is
most of them.

What makes this different from an AI gateway
--------------------------------------------
Every gateway in this category screens *text*: prompt in, completion out, regex
or a classifier over both. That is the weakest thing you can do with the
position, because the dangerous part of an agent turn is not the prose — it is
the ``tool_use`` block at the end of it, the one the harness is about to
execute.

This proxy screens the tool call. A ``tool_use`` in the model's response is
reshaped into the same canonical event a Bash hook produces
(:func:`prismor.runtime.mirror.shape_call_event`) and run through the same
:func:`~prismor.runtime.runtime.evaluate_tool_call`, so the rule that stops
``rm -rf /`` at the hook layer stops the model from *proposing* it here — one
policy, whether the call arrives through a hook, an MCP server, or a raw HTTPS
request to api.anthropic.com.

Streaming, and why tool blocks are held
---------------------------------------
Refusing after the client has already read the bytes is theatre. Text deltas
stream through untouched (minus cloak masking); a ``tool_use`` content block is
*buffered* from its ``content_block_start`` until its ``content_block_stop``,
evaluated whole, and then either released verbatim or replaced with a refusal.
The client never sees a complete tool call that policy would deny. Cost: the
tool block lands in one burst instead of streaming in. Nobody watches JSON
arguments type themselves out, so this is free in practice.

Fail-closed
-----------
In ``enforce`` mode an engine error refuses the request; in ``observe`` it logs
and forwards. Same rule as the MCP gateway — a broken engine must not become a
silent allow.

Dependencies
------------
Stdlib only (``http.server`` + ``http.client``), like the rest of the runtime.
The package has exactly one runtime dependency and this surface does not add a
second: a proxy that drags in a web framework is a proxy nobody deploys next to
the agent it is supposed to be governing.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import signal
import ssl
import sys
import threading
import time
from datetime import datetime, timezone
from http.client import HTTPConnection, HTTPSConnection
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from socketserver import ThreadingMixIn
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple
from urllib.parse import urlsplit

PROXY_AGENT = "prismor-proxy"
SURFACE_ID = "llm-proxy"

#: Path → provider. The client points its SDK at us with no other change, so
#: the route has to be inferred from the request the SDK would have sent
#: anyway. Unknown paths are forwarded to the default upstream unscreened but
#: logged (auth handshakes, /v1/models, health checks).
PROVIDER_ROUTES: Tuple[Tuple[str, str], ...] = (
    ("/v1/messages", "anthropic"),
    ("/v1/complete", "anthropic"),
    ("/v1/chat/completions", "openai"),
    ("/v1/responses", "openai"),
)

DEFAULT_UPSTREAMS: Dict[str, Dict[str, str]] = {
    "anthropic": {"base_url": "https://api.anthropic.com",
                  "api_key_env": "ANTHROPIC_API_KEY",
                  "auth_header": "x-api-key"},
    "openai": {"base_url": "https://api.openai.com",
               "api_key_env": "OPENAI_API_KEY",
               "auth_header": "authorization"},
}

#: Headers we must not relay: hop-by-hop, or ones the upstream will recompute.
_STRIP_REQUEST_HEADERS = frozenset({
    "host", "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "content-length",
    "accept-encoding",  # we do not decompress, so do not let the upstream compress
})
_STRIP_RESPONSE_HEADERS = frozenset({
    "connection", "keep-alive", "transfer-encoding", "content-encoding",
    "content-length", "upgrade",
})

CONNECT_TIMEOUT = 30
READ_TIMEOUT = 600

#: Rebuild the derived session snapshot once every this many events. See
#: ``Screen.evaluate`` for why it is not once per event.
SNAPSHOT_EVERY = 25


# ── config ───────────────────────────────────────────────────────────────────

class ProxyConfigError(ValueError):
    """Malformed proxy config."""


class ProxyConfig:
    """Upstreams, virtual keys and fallback order.

    Virtual keys are the point of the thing: a client presents a Prismor key,
    the proxy swaps in the real provider credential on the way out. The agent
    never holds the provider key, so revoking its access is a line in this file
    rather than a rotation across every machine that ever ran it.

    With no keys configured the proxy runs in pass-through auth: whatever
    credential the client sent is relayed. That is the local-developer mode —
    it governs behavior without asking anyone to re-plumb their credentials
    first, which is the only way this gets switched on.
    """

    def __init__(self, raw: Optional[Dict[str, Any]] = None) -> None:
        raw = raw or {}
        self.upstreams: Dict[str, Dict[str, Any]] = {
            name: dict(spec) for name, spec in DEFAULT_UPSTREAMS.items()
        }
        for name, spec in (raw.get("upstreams") or {}).items():
            if not isinstance(spec, dict):
                raise ProxyConfigError(f"upstream {name!r} must be an object")
            self.upstreams.setdefault(name, {}).update(spec)
        self.keys: Dict[str, Dict[str, Any]] = raw.get("keys") or {}
        if not isinstance(self.keys, dict):
            raise ProxyConfigError("`keys` must be an object of key → {subject, upstream}")
        self.default_upstream: str = raw.get("default_upstream") or "anthropic"

    @classmethod
    def load(cls, path: Optional[Path]) -> "ProxyConfig":
        if path is None or not path.exists():
            return cls()
        try:
            return cls(json.loads(path.read_text(encoding="utf-8")))
        except ProxyConfigError:
            raise
        except Exception as exc:
            raise ProxyConfigError(f"cannot read proxy config {path}: {exc}") from exc

    def upstream(self, name: str) -> Dict[str, Any]:
        spec = self.upstreams.get(name)
        if spec is None:
            raise ProxyConfigError(f"no upstream configured named {name!r}")
        return spec

    def resolve_key(self, presented: str) -> Optional[Dict[str, Any]]:
        """Virtual key → {subject, upstream, ...}. Constant-time compare."""
        for key, meta in self.keys.items():
            if hmac.compare_digest(presented, str(key)):
                return dict(meta or {})
        return None

    def chain(self, name: str) -> List[str]:
        """Primary upstream then its declared fallbacks, deduplicated.

        Fallback is the one feature every AI gateway has that is genuinely
        about availability rather than security, and it costs ten lines here
        because the forward path already loops.
        """
        out = [name]
        for alt in (self.upstream(name).get("fallback") or []):
            if alt not in out and alt in self.upstreams:
                out.append(str(alt))
        return out


# ── payload normalizers ──────────────────────────────────────────────────────

def _text_of(content: Any) -> str:
    """Flatten a message ``content`` (string, or list of typed blocks) to text."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for block in content:
            if isinstance(block, str):
                parts.append(block)
            elif isinstance(block, dict):
                if isinstance(block.get("text"), str):
                    parts.append(block["text"])
                elif block.get("type") == "tool_result":
                    parts.append(_text_of(block.get("content")))
        return "\n".join(p for p in parts if p)
    return "" if content is None else str(content)


def extract_prompt(body: Dict[str, Any]) -> str:
    """The text going to the model: system prompt plus every message.

    Both provider shapes put the system prompt somewhere different and OpenAI
    folds it into ``messages``; flattening both to one blob is enough, because
    the rules that matter here (secret material, data-boundary values, injected
    instructions riding in a tool_result) are category rules over combined text.
    """
    parts: List[str] = []
    system = body.get("system") or body.get("instructions")
    if system:
        parts.append(_text_of(system))
    for msg in body.get("messages") or []:
        if isinstance(msg, dict):
            parts.append(_text_of(msg.get("content")))
    if isinstance(body.get("input"), (str, list)):
        parts.append(_text_of(body["input"]))
    return "\n".join(p for p in parts if p)


def prompt_parts(body: Dict[str, Any]) -> Dict[str, str]:
    """The prompt broken back into the pieces a person recognises.

    ``extract_prompt`` flattens system and messages into one blob because the
    rules are category rules over combined text. That blob is the right thing
    to evaluate and the wrong thing to *show*: a reader looking at a session
    wants the sentence they typed, not their sentence welded to the workflow's
    system prompt.
    """
    system = body.get("system") or body.get("instructions")
    out: Dict[str, str] = {}
    if system:
        out["system"] = _text_of(system)
    last_user = ""
    for msg in body.get("messages") or []:
        if not isinstance(msg, dict):
            continue
        role = str(msg.get("role") or "")
        if role == "system" and "system" not in out:
            out["system"] = _text_of(msg.get("content"))
        elif role == "user":
            last_user = _text_of(msg.get("content"))
    if not last_user and isinstance(body.get("input"), (str, list)):
        last_user = _text_of(body["input"])
    if last_user:
        out["user_message"] = last_user
    return out


def conversation_key(body: Dict[str, Any]) -> str:
    """A stable id for the conversation this request belongs to.

    A chat UI sends its whole history every turn, so the opening exchange is
    the one thing that stays constant across a conversation and differs
    between conversations. Hashing it threads a chatbot's turns into one
    session instead of dumping every conversation the process ever proxied
    into a single one keyed on the proxy's pid.
    """
    system = ""
    first_user = ""
    raw_system = body.get("system") or body.get("instructions")
    if raw_system:
        system = _text_of(raw_system)
    for msg in body.get("messages") or []:
        if isinstance(msg, dict) and str(msg.get("role") or "") == "user":
            first_user = _text_of(msg.get("content"))
            break
    if not (system or first_user):
        return ""
    seed = (system[:2000] + "\x00" + first_user[:2000]).encode("utf-8", "replace")
    return hashlib.sha256(seed).hexdigest()[:12]


def response_tool_calls(provider: str, body: Dict[str, Any]) -> List[Tuple[str, Any]]:
    """``(tool_name, arguments)`` for every tool call in a completed response."""
    calls: List[Tuple[str, Any]] = []
    if provider == "anthropic":
        for block in body.get("content") or []:
            if isinstance(block, dict) and block.get("type") == "tool_use":
                calls.append((str(block.get("name") or ""), block.get("input")))
        return calls
    for choice in body.get("choices") or []:
        message = (choice or {}).get("message") or {}
        for call in message.get("tool_calls") or []:
            fn = (call or {}).get("function") or {}
            calls.append((str(fn.get("name") or ""), _loads(fn.get("arguments"))))
    # Responses API
    for item in body.get("output") or []:
        if isinstance(item, dict) and item.get("type") in ("function_call", "tool_call"):
            calls.append((str(item.get("name") or ""), _loads(item.get("arguments"))))
    return calls


def _loads(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except Exception:
            return {"_raw": value}
    return value if value is not None else {}


# ── the screen ───────────────────────────────────────────────────────────────

class Screen:
    """Policy decisions for one proxy, over the shared runtime pipeline.

    Kept separate from the HTTP handler so the streaming reframer and the
    buffered path share exactly one implementation of "is this tool call
    allowed", and so tests can drive it without a socket.
    """

    def __init__(self, workspace: Path, mode: str, session_id: str,
                 agent_name: str = "") -> None:
        self.workspace = workspace
        self.mode = mode
        self.session_id = session_id
        self.agent_name = agent_name
        # session id -> [events, unsnapshotted]. A proxy outlives any one
        # conversation, so counting per process would snapshot on a boundary
        # that means nothing.
        self._counts: Dict[str, List[int]] = {}
        self._conversations: Dict[str, str] = {}
        # Serialized for the same reason the MCP gateway serializes: the
        # trifecta TagLedger is order-dependent, and concurrent evaluations
        # could let the completing half of a forbidden tag pair through.
        self._lock = threading.Lock()

    # -- events ----------------------------------------------------------

    def session_for(self, body: Dict[str, Any], explicit: str = "") -> str:
        """The session this request belongs to.

        An explicit ``X-Prismor-Session`` header wins -- a caller that knows
        its own conversation id should say so. Otherwise the conversation is
        recognised from its opening exchange, so a chatbot's turns land in one
        session and two chats do not merge into the proxy's lifetime.
        """
        if explicit:
            token = re.sub(r"[^A-Za-z0-9_.:-]", "-", explicit)[:64]
            return f"{self.session_id}-{token}"
        key = conversation_key(body)
        if not key:
            return self.session_id
        with self._lock:
            sid = self._conversations.get(key)
            if not sid:
                sid = f"{self.session_id}-{key}"
                self._conversations[key] = sid
        return sid

    def _base(self, agent_event: str, subject: Optional[str],
              session_id: str = "") -> Dict[str, Any]:
        return {
            "ts": datetime.now(timezone.utc).isoformat(),
            "session_id": session_id or self.session_id,
            "agent": PROXY_AGENT,
            "agent_event": agent_event,
            "metadata": {
                "cwd": str(self.workspace),
                "surface": SURFACE_ID,
                "subject": subject,
            },
        }

    def prompt_event(self, provider: str, model: str, prompt: str,
                     subject: Optional[str], session_id: str = "",
                     parts: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        event = self._base("prompt", subject, session_id)
        event["metadata"].update({"provider": provider, "model": model,
                                  "tool_name": "llm_request"})
        # The flattened blob is what policy reads; the parts are what a person
        # reads in the session view.
        for key, value in (parts or {}).items():
            if value:
                event["metadata"][key] = value
        event.update({"type": "prompt", "prompt": prompt})
        return event

    def tool_event(self, tool_name: str, arguments: Any, provider: str,
                   model: str, subject: Optional[str],
                   session_id: str = "") -> Dict[str, Any]:
        """Shape a model-proposed tool call as the event a hook would produce.

        This is the whole reason the surface earns its place. ``shape_call_event``
        is what the mirror uses to make a mirrored ``Bash`` look like a hooked
        ``Bash``; reusing it here makes a *model-proposed* Bash look like both.
        One rule table covers all three, and a tool this proxy has never heard
        of still lands on the generic payload path rather than being waved
        through.
        """
        event = self._base("PreToolUse", subject, session_id)
        event["metadata"].update({"provider": provider, "model": model,
                                  "tool_name": tool_name, "proposed": True})
        try:
            from prismor.runtime import mirror
            shaped = mirror.shape_call_event(tool_name, arguments)
        except Exception:
            shaped = None
        if shaped:
            event.update(shaped)
            return event
        try:
            args_text = json.dumps(arguments, default=str)
        except Exception:
            args_text = str(arguments)
        event.update({"type": "tool_result", "response": args_text})
        return event

    # -- evaluation ------------------------------------------------------

    def evaluate(self, event: Dict[str, Any], subject: Optional[str] = None):
        """One event → Decision, or None when the engine is unavailable in observe.

        Persistence is handled here rather than by ``evaluate_tool_call``'s
        ``persist=True``. That path re-reads and re-analyses the *entire*
        session log on every event and rewrites the snapshot, which is right
        for a hook (one short-lived process per call) and quadratic for a
        surface that stays up. Measured on a fresh PRISMOR_HOME: 48ms at event
        10, 89ms at event 40, still climbing; with the rebuild removed it is
        flat at ~38ms. The event log itself is an O(1) append and still gets
        every event, so the audit trail is unchanged — only the derived
        snapshot is amortized.

        ponytail: rebuild every SNAPSHOT_EVERY events, so the console lags a
        live proxy session by at most that many calls. The same defect is in
        every long-lived surface (the MCP gateway has it too) and the real fix
        is an incremental snapshot in runtime.py; this keeps the blast radius
        to one file until that lands.
        """
        try:
            from prismor.runtime.principal import resolve_subject
            from prismor.runtime.runtime import evaluate_tool_call
            with self._lock:
                self._persist(event)
                return evaluate_tool_call(
                    event=event,
                    workspace=self.workspace,
                    agent=PROXY_AGENT,
                    mode=self.mode,
                    session_id=str(event.get("session_id") or self.session_id),
                    agent_name=self.agent_name,
                    subject=resolve_subject(subject),
                    persist=False,
                )
        except Exception as exc:
            sys.stderr.write(f"[prismor-proxy] evaluation error: {exc}\n")
            if self.mode == "enforce":
                raise
            return None

    def _persist(self, event: Dict[str, Any]) -> None:
        """Append the event; rebuild that session's snapshot every N events."""
        sid = str(event.get("session_id") or self.session_id)
        try:
            from prismor.runtime.store import append_session_event
            append_session_event(self.workspace, sid, event)
        except Exception as exc:
            sys.stderr.write(f"[prismor-proxy] session log error: {exc}\n")
            return
        counts = self._counts.setdefault(sid, [0, 0])
        counts[0] += 1
        counts[1] += 1
        if counts[0] % SNAPSHOT_EVERY:
            return
        self.snapshot(sid)

    def snapshot(self, session_id: str = "") -> None:
        """Rebuild the session snapshot the console and `prismor sessions` read.

        Called every SNAPSHOT_EVERY events for one session, and for every
        session the process touched when the surface stops. A conversation is
        often a handful of events -- the n8n agent that produced a blocked
        install command logged five -- so a purely periodic rebuild left short
        sessions with a log on disk and no session anywhere an operator looks.
        """
        targets = [session_id] if session_id else list(self._counts)
        for sid in targets:
            counts = self._counts.get(sid)
            if not counts or not counts[1]:
                continue
            counts[1] = 0
            self._snapshot_one(sid)

    def _snapshot_one(self, sid: str) -> None:
        try:
            from prismor.runtime.cli import analyze_events
            from prismor.runtime.store import read_session_events, save_session_snapshot
            events = read_session_events(self.workspace, sid)
            save_session_snapshot(
                workspace=self.workspace,
                session_id=sid,
                agent=PROXY_AGENT,
                agent_name=self.agent_name or PROXY_AGENT,
                source="proxy",
                repo_url=None,
                events=events,
                analysis=analyze_events(events, repo_root=self.workspace,
                                        workspace=self.workspace,
                                        session_id=sid),
            )
        except Exception as exc:  # best-effort, exactly as the runtime path is
            sys.stderr.write(f"[prismor-proxy] snapshot error: {exc}\n")

    def log(self, decision: Any, tool_name: str) -> None:
        if decision is None:
            return
        try:
            from prismor.runtime.runtime import log_observe_findings
            log_observe_findings(decision, tool_name=tool_name, mode=self.mode)
        except Exception:
            pass

    def blocking(self, decision: Any) -> Optional[Dict[str, Any]]:
        """The finding that should stop this call, or None.

        ``observe`` never blocks — it is the mode people switch the proxy on
        in, and a proxy that blocks in observe mode gets switched off again.
        """
        if decision is None or self.mode != "enforce":
            return None
        return getattr(decision, "blocking", None)

    def redact(self, text: str) -> str:
        """Mask cloak secrets and data-boundary values in model-bound text.

        Cloak masking runs in both modes for the same reason the gateway does
        it while paused: `pause` suspends *policy*, and a suspended policy must
        still not push a live credential into a third party's logs.
        """
        try:
            from prismor.runtime.redaction import redact_text
            out, _ = redact_text(text, workspace=self.workspace,
                                 data_boundary=self.mode == "enforce")
            return out
        except Exception:
            return text


# ── refusals, in each provider's own error shape ─────────────────────────────

def refusal_reason(blocking: Dict[str, Any]) -> str:
    rule = blocking.get("ruleId") or blocking.get("rule_id") or "policy"
    detail = blocking.get("message") or blocking.get("reason") or "blocked by policy"
    return f"Blocked by Prismor [{rule}]: {detail}"


def error_body(provider: str, message: str) -> bytes:
    """A refusal the client's own SDK will parse and surface, not choke on."""
    if provider == "anthropic":
        payload = {"type": "error",
                   "error": {"type": "permission_error", "message": message}}
    else:
        payload = {"error": {"message": message, "type": "permission_error",
                             "code": "prismor_policy_block"}}
    return json.dumps(payload).encode()


def _refused_tool_block(provider: str, block: Dict[str, Any], message: str) -> Dict[str, Any]:
    """Replace a denied tool call with a text block explaining the refusal.

    Deleting the block outright would leave the model's turn structurally
    invalid (Anthropic requires a ``tool_result`` for every ``tool_use``), and
    an agent that gets a silent no-op will simply try again. Telling it why
    ends the loop.
    """
    if provider == "anthropic":
        return {"type": "text", "text": message}
    return {"type": "text", "text": message}


# ── streaming reframer ───────────────────────────────────────────────────────

class StreamScreen:
    """Rewrites an SSE stream in flight, holding tool calls until they can be judged.

    Text deltas pass straight through (redacted). Tool-call deltas accumulate
    in ``_pending`` and are released only once the block closes and policy has
    seen the whole thing. Both provider dialects are folded into that one rule.

    ponytail: redaction runs per text delta, so a secret split across two
    deltas can slip through. The PostToolUse scrubber has the same ceiling and
    the same fix — carry a tail buffer of the longest cloak value — which is
    worth doing when a real value survives a stream, not before.
    """

    def __init__(self, screen: Screen, provider: str, model: str,
                 subject: Optional[str], session_id: str = "") -> None:
        self.screen = screen
        self.provider = provider
        self.model = model
        self.subject = subject
        # The request's conversation, so a streamed tool call lands in the
        # same session as the prompt that produced it.
        self.session_id = session_id or screen.session_id
        self.blocked: List[str] = []
        self._pending: List[bytes] = []      # raw SSE lines held back
        self._tool_name: str = ""
        self._tool_json: List[str] = []
        self._tool_index: int = 0
        self._holding = False

    def feed(self, chunk: bytes) -> bytes:
        """One SSE frame in, zero-or-more frames out."""
        try:
            return self._feed(chunk)
        except Exception as exc:  # never break the stream over a parse failure
            sys.stderr.write(f"[prismor-proxy] stream screen error: {exc}\n")
            return chunk

    def flush(self) -> bytes:
        """Anything still held when the upstream closes mid-block."""
        out, self._pending = b"".join(self._pending), []
        self._holding = False
        return out

    # -- internals -------------------------------------------------------

    def _feed(self, chunk: bytes) -> bytes:
        event = _sse_payload(chunk)
        if event is None:
            return b"" if self._holding else chunk

        if self.provider == "anthropic":
            return self._feed_anthropic(chunk, event)
        return self._feed_openai(chunk, event)

    def _feed_anthropic(self, chunk: bytes, event: Dict[str, Any]) -> bytes:
        etype = event.get("type")
        if etype == "content_block_start":
            block = event.get("content_block") or {}
            if block.get("type") == "tool_use":
                self._holding = True
                self._tool_name = str(block.get("name") or "")
                self._tool_json = []
                # The refusal has to be emitted at the SAME index as the block
                # it replaces: a client tracking content blocks by index will
                # mis-assemble the turn if a second block opens at index 0.
                self._tool_index = int(event.get("index") or 0)
                self._pending = [chunk]
                return b""
            return chunk

        if not self._holding:
            if etype == "content_block_delta":
                return _rewrite_text_delta(chunk, event, self.screen.redact)
            return chunk

        self._pending.append(chunk)
        if etype == "content_block_delta":
            delta = event.get("delta") or {}
            if delta.get("type") == "input_json_delta":
                self._tool_json.append(str(delta.get("partial_json") or ""))
            return b""
        if etype == "content_block_stop":
            return self._judge()
        return b""

    def _feed_openai(self, chunk: bytes, event: Dict[str, Any]) -> bytes:
        choices = event.get("choices") or []
        delta = (choices[0] if choices else {}).get("delta") or {}
        finish = (choices[0] if choices else {}).get("finish_reason")

        if delta.get("tool_calls"):
            self._holding = True
            self._pending.append(chunk)
            for call in delta["tool_calls"]:
                fn = (call or {}).get("function") or {}
                if fn.get("name"):
                    self._tool_name = str(fn["name"])
                if fn.get("arguments"):
                    self._tool_json.append(str(fn["arguments"]))
            return b""
        if self._holding and finish:
            self._pending.append(chunk)
            return self._judge()
        if self._holding:
            self._pending.append(chunk)
            return b""
        if delta.get("content"):
            return _rewrite_text_delta(chunk, event, self.screen.redact)
        return chunk

    def _judge(self) -> bytes:
        """Evaluate the completed tool call; release it or replace it."""
        arguments = _loads("".join(self._tool_json) or "{}")
        event = self.screen.tool_event(self._tool_name, arguments,
                                       self.provider, self.model, self.subject,
                                       session_id=self.session_id)
        try:
            decision = self.screen.evaluate(event, self.subject)
        except Exception:
            # enforce-mode engine failure: the held block never ships.
            self._pending = []
            self._holding = False
            reason = "Blocked by Prismor: policy evaluation failed (fail-closed)"
            self.blocked.append(reason)
            return _sse_text_frames(self.provider, reason, self._tool_index)

        self.screen.log(decision, self._tool_name)
        blocking = self.screen.blocking(decision)
        held, self._pending = b"".join(self._pending), []
        self._holding = False
        if blocking is None:
            return held
        reason = refusal_reason(blocking)
        self.blocked.append(reason)
        sys.stderr.write(f"[prismor-proxy] {reason} (tool={self._tool_name})\n")
        return _sse_text_frames(self.provider, reason, self._tool_index)


def _sse_payload(chunk: bytes) -> Optional[Dict[str, Any]]:
    """The JSON object on a ``data:`` line, or None for anything else."""
    for line in chunk.split(b"\n"):
        if line.startswith(b"data:"):
            raw = line[5:].strip()
            if not raw or raw == b"[DONE]":
                return None
            try:
                parsed = json.loads(raw)
            except Exception:
                return None
            return parsed if isinstance(parsed, dict) else None
    return None


def _rewrite_text_delta(chunk: bytes, event: Dict[str, Any],
                        redact: Callable[[str], str]) -> bytes:
    """Re-emit a text delta with its text redacted, or unchanged if nothing changed."""
    if "delta" in event and isinstance(event["delta"], dict) and "text" in event["delta"]:
        original = str(event["delta"].get("text") or "")
        masked = redact(original)
        if masked == original:
            return chunk
        event["delta"]["text"] = masked
    elif event.get("choices"):
        delta = (event["choices"][0] or {}).get("delta") or {}
        original = str(delta.get("content") or "")
        masked = redact(original)
        if masked == original:
            return chunk
        delta["content"] = masked
    else:
        return chunk
    name = b""
    for line in chunk.split(b"\n"):
        if line.startswith(b"event:"):
            name = line + b"\n"
            break
    return name + b"data: " + json.dumps(event).encode() + b"\n\n"


def _sse_text_frames(provider: str, message: str, index: int = 0) -> bytes:
    """A refusal rendered as stream events the client already knows how to read.

    ``index`` is the content-block index of the tool call being replaced, not a
    fresh one: the client assembles the turn by index, so opening a second
    block at 0 after 0 has already closed corrupts it.
    """
    if provider == "anthropic":
        frames = [
            ("content_block_start", {"type": "content_block_start", "index": index,
                                     "content_block": {"type": "text", "text": ""}}),
            ("content_block_delta", {"type": "content_block_delta", "index": index,
                                     "delta": {"type": "text_delta", "text": message}}),
            ("content_block_stop", {"type": "content_block_stop", "index": index}),
        ]
        return b"".join(
            f"event: {name}\ndata: {json.dumps(payload)}\n\n".encode()
            for name, payload in frames)
    payload = {"choices": [{"index": 0, "delta": {"content": message},
                            "finish_reason": "stop"}]}
    return f"data: {json.dumps(payload)}\n\n".encode()


# ── HTTP surface ─────────────────────────────────────────────────────────────

class _ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


class ProxyHandler(BaseHTTPRequestHandler):
    config: ProxyConfig = ProxyConfig()
    screen: Optional[Screen] = None
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        pass

    # -- entry points ----------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/health":
            self._json({"status": "ok", "surface": SURFACE_ID,
                        "mode": self.screen.mode if self.screen else "observe"})
            return
        self._forward(b"")

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        self._forward(self.rfile.read(length) if length else b"")

    do_PUT = do_POST
    do_DELETE = do_GET

    # -- plumbing --------------------------------------------------------

    def _json(self, payload: Any, status: int = 200) -> None:
        body = json.dumps(payload, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _refuse(self, provider: str, message: str, status: int = 403) -> None:
        body = error_body(provider, message)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _provider(self) -> str:
        path = urlsplit(self.path).path
        for prefix, provider in PROVIDER_ROUTES:
            if path.endswith(prefix) or path == prefix:
                return provider
        # An unrouted path is one both APIs define -- /v1/models above all,
        # which is what an SDK calls to verify a credential. Sending it to the
        # default upstream answers an OpenAI client with Anthropic's 401
        # ("invalid x-api-key"), so n8n's Test button says the settings are
        # broken while every actual completion works. The client already told
        # us who it thinks it is talking to: Anthropic SDKs stamp
        # anthropic-version (or send x-api-key), OpenAI SDKs send a bearer.
        if self.headers.get("anthropic-version") or self.headers.get("x-api-key"):
            return "anthropic"
        auth = (self.headers.get("authorization") or "").strip().lower()
        if auth.startswith("bearer "):
            return "openai"
        return self.config.default_upstream

    def _auth(self) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """``(subject, upstream_override, error)`` from the presented credential.

        With virtual keys configured an unknown key is refused outright — that
        is the revocation story, and it is worthless if an unrecognized key
        falls back to pass-through.
        """
        if not self.config.keys:
            return None, None, None
        presented = (self.headers.get("x-api-key")
                     or (self.headers.get("Authorization") or "").removeprefix("Bearer ").strip())
        meta = self.config.resolve_key(presented) if presented else None
        if meta is None:
            return None, None, "unknown or revoked Prismor key"
        return meta.get("subject"), meta.get("upstream"), None

    # -- the request path ------------------------------------------------

    def _forward(self, raw_body: bytes) -> None:
        provider = self._provider()
        subject, upstream_override, auth_error = self._auth()
        if auth_error:
            self._refuse(provider, f"Blocked by Prismor: {auth_error}", status=401)
            return

        body = _loads_object(raw_body)
        screened = body is not None and any(
            urlsplit(self.path).path.endswith(p) for p, _ in PROVIDER_ROUTES)
        model = str((body or {}).get("model") or "")
        streaming = bool((body or {}).get("stream"))

        if screened and self.screen is not None:
            refusal = self._screen_request(provider, model, body, subject)
            if refusal:
                self._refuse(provider, refusal)
                return
            raw_body = json.dumps(body).encode()

        name = upstream_override or provider
        try:
            chain = self.config.chain(name)
        except ProxyConfigError as exc:
            self._refuse(provider, f"prismor-proxy: {exc}", status=502)
            return

        last_error: Optional[str] = None
        for attempt, upstream_name in enumerate(chain):
            try:
                self._relay(upstream_name, provider, raw_body, model,
                            streaming and screened, screened, subject)
                return
            except _Retryable as exc:
                last_error = str(exc)
                if attempt + 1 < len(chain):
                    sys.stderr.write(
                        f"[prismor-proxy] {upstream_name} failed ({exc}); "
                        f"falling back to {chain[attempt + 1]}\n")
                continue
            except Exception as exc:
                self._refuse(provider, f"prismor-proxy: upstream error: {exc}", status=502)
                return
        self._refuse(provider, f"prismor-proxy: all upstreams failed: {last_error}",
                     status=502)

    def _screen_request(self, provider: str, model: str, body: Dict[str, Any],
                        subject: Optional[str]) -> Optional[str]:
        """Screen and mask the outbound prompt. Returns a refusal, or None.

        Masking happens on the way *out*: whatever the agent stuffed into its
        context, the provider's logs should not receive a live credential.
        """
        assert self.screen is not None
        prompt = extract_prompt(body)
        # Resolved once per request and reused for the tool calls the response
        # proposes, so a turn's prompt and its consequences share a session.
        self._session_id = self.screen.session_for(
            body, self.headers.get("x-prismor-session") or "")
        event = self.screen.prompt_event(provider, model, prompt, subject,
                                         session_id=self._session_id,
                                         parts=prompt_parts(body))
        try:
            decision = self.screen.evaluate(event, subject)
        except Exception:
            return "Blocked by Prismor: policy evaluation failed (fail-closed)"
        self.screen.log(decision, "llm_request")
        blocking = self.screen.blocking(decision)
        if blocking is not None:
            reason = refusal_reason(blocking)
            sys.stderr.write(f"[prismor-proxy] {reason}\n")
            return reason
        _mask_in_place(body, self.screen.redact)
        return None

    def _relay(self, upstream_name: str, provider: str, raw_body: bytes,
               model: str, streaming: bool, screened: bool,
               subject: Optional[str]) -> None:
        spec = self.config.upstream(upstream_name)
        base = urlsplit(str(spec.get("base_url") or ""))
        if not base.hostname:
            raise ProxyConfigError(f"upstream {upstream_name!r} has no base_url")

        conn_cls = HTTPSConnection if base.scheme != "http" else HTTPConnection
        kwargs: Dict[str, Any] = {"timeout": CONNECT_TIMEOUT}
        if conn_cls is HTTPSConnection:
            kwargs["context"] = ssl.create_default_context()
        conn = conn_cls(base.hostname, base.port, **kwargs)

        path = urlsplit(self.path).path
        if base.path and base.path != "/":
            path = base.path.rstrip("/") + path
        query = urlsplit(self.path).query
        try:
            conn.request(self.command, path + (f"?{query}" if query else ""),
                         body=raw_body or None,
                         headers=self._upstream_headers(spec, raw_body))
            conn.sock.settimeout(READ_TIMEOUT)  # type: ignore[union-attr]
            resp = conn.getresponse()
        except Exception as exc:
            conn.close()
            raise _Retryable(f"{upstream_name}: {exc}") from exc

        if resp.status >= 500 and self.config.chain(upstream_name)[1:]:
            conn.close()
            raise _Retryable(f"{upstream_name}: HTTP {resp.status}")

        try:
            if streaming:
                self._relay_stream(resp, provider, model, subject)
            else:
                self._relay_buffered(resp, provider, model, screened, subject)
        finally:
            conn.close()

    def _upstream_headers(self, spec: Dict[str, Any], raw_body: bytes) -> Dict[str, str]:
        headers = {k: v for k, v in self.headers.items()
                   if k.lower() not in _STRIP_REQUEST_HEADERS}
        env_name = str(spec.get("api_key_env") or "")
        real_key = os.environ.get(env_name) if env_name else None
        if real_key and self.config.keys:
            # Virtual-key mode: swap the client's Prismor key for the real one.
            header = str(spec.get("auth_header") or "authorization").lower()
            for existing in ("authorization", "x-api-key"):
                headers.pop(existing, None)
                headers.pop(existing.title(), None)
                headers.pop("X-Api-Key", None)
            headers[header] = real_key if header == "x-api-key" else f"Bearer {real_key}"
        headers["Content-Length"] = str(len(raw_body))
        headers["Accept-Encoding"] = "identity"
        return headers

    def _relay_buffered(self, resp: Any, provider: str, model: str,
                        screened: bool, subject: Optional[str]) -> None:
        payload = resp.read()
        if screened and self.screen is not None and resp.status < 400:
            payload = self._screen_response(provider, model, payload, subject)
        self.send_response(resp.status)
        for key, value in resp.getheaders():
            if key.lower() not in _STRIP_RESPONSE_HEADERS:
                self.send_header(key, value)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _screen_response(self, provider: str, model: str, payload: bytes,
                         subject: Optional[str]) -> bytes:
        """Evaluate every tool call the model proposed; redact the prose."""
        assert self.screen is not None
        body = _loads_object(payload)
        if body is None:
            return payload
        blocked: Dict[str, str] = {}
        for tool_name, arguments in response_tool_calls(provider, body):
            event = self.screen.tool_event(tool_name, arguments, provider, model, subject,
                                           session_id=getattr(self, "_session_id", ""))
            try:
                decision = self.screen.evaluate(event, subject)
            except Exception:
                blocked[tool_name] = ("Blocked by Prismor: policy evaluation failed "
                                      "(fail-closed)")
                continue
            self.screen.log(decision, tool_name)
            blocking = self.screen.blocking(decision)
            if blocking is not None:
                blocked[tool_name] = refusal_reason(blocking)
                sys.stderr.write(
                    f"[prismor-proxy] {blocked[tool_name]} (tool={tool_name})\n")
        if blocked:
            body = _strip_blocked_calls(provider, body, blocked)
        _mask_in_place(body, self.screen.redact)
        _meter(self.screen, body, model)
        return json.dumps(body).encode()

    def _relay_stream(self, resp: Any, provider: str, model: str,
                      subject: Optional[str]) -> None:
        assert self.screen is not None
        self.send_response(resp.status)
        for key, value in resp.getheaders():
            if key.lower() not in _STRIP_RESPONSE_HEADERS:
                self.send_header(key, value)
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()

        stream = StreamScreen(self.screen, provider, model, subject,
                              getattr(self, "_session_id", ""))
        try:
            for frame in _sse_frames(resp):
                out = stream.feed(frame)
                if out:
                    self._write_chunk(out)
            tail = stream.flush()
            if tail:
                self._write_chunk(tail)
        finally:
            try:
                self.wfile.write(b"0\r\n\r\n")
            except Exception:
                pass

    def _write_chunk(self, data: bytes) -> None:
        self.wfile.write(f"{len(data):x}\r\n".encode() + data + b"\r\n")
        self.wfile.flush()


class _Retryable(RuntimeError):
    """Upstream failure worth trying the next upstream for."""


def _sse_frames(resp: Any) -> Iterator[bytes]:
    """Split an SSE body into whole ``\\n\\n``-terminated frames."""
    buffer = b""
    while True:
        chunk = resp.read(1024)
        if not chunk:
            break
        buffer += chunk
        while b"\n\n" in buffer:
            frame, buffer = buffer.split(b"\n\n", 1)
            yield frame + b"\n\n"
    if buffer:
        yield buffer


def _loads_object(raw: bytes) -> Optional[Dict[str, Any]]:
    if not raw:
        return None
    try:
        parsed = json.loads(raw)
    except Exception:
        return None
    return parsed if isinstance(parsed, dict) else None


def _mask_in_place(node: Any, redact: Callable[[str], str]) -> None:
    """Walk a decoded payload and mask every string in it."""
    if isinstance(node, dict):
        for key, value in node.items():
            if isinstance(value, str):
                node[key] = redact(value)
            else:
                _mask_in_place(value, redact)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            if isinstance(value, str):
                node[index] = redact(value)
            else:
                _mask_in_place(value, redact)


def _strip_blocked_calls(provider: str, body: Dict[str, Any],
                         blocked: Dict[str, str]) -> Dict[str, Any]:
    """Replace denied tool calls with the refusal text, in place."""
    if provider == "anthropic":
        content = []
        for block in body.get("content") or []:
            name = block.get("name") if isinstance(block, dict) else None
            if isinstance(block, dict) and block.get("type") == "tool_use" and name in blocked:
                content.append(_refused_tool_block(provider, block, blocked[name]))
            else:
                content.append(block)
        body["content"] = content
        if any(isinstance(b, dict) and b.get("type") == "text" for b in content):
            body["stop_reason"] = "end_turn"
        return body
    for choice in body.get("choices") or []:
        message = (choice or {}).get("message") or {}
        kept, refusals = [], []
        for call in message.get("tool_calls") or []:
            name = ((call or {}).get("function") or {}).get("name")
            if name in blocked:
                refusals.append(blocked[name])
            else:
                kept.append(call)
        if refusals:
            message["tool_calls"] = kept
            message["content"] = "\n".join(
                filter(None, [message.get("content") or ""] + refusals))
            if not kept:
                message.pop("tool_calls", None)
                choice["finish_reason"] = "stop"
    return body


def _meter(screen: Screen, body: Dict[str, Any], model: str) -> None:
    """Record token usage against the session. Best-effort, never fatal."""
    usage = body.get("usage")
    if not isinstance(usage, dict):
        return
    try:
        from prismor.runtime.token_usage import record_from_event
        record_from_event(
            workspace=screen.workspace,
            session_id=screen.session_id,
            agent=PROXY_AGENT,
            event={"type": "llm_usage", "metadata": {"model": model, "usage": usage}},
        )
    except Exception:
        pass


# ── entry point ──────────────────────────────────────────────────────────────

def default_config_path() -> Path:
    home = os.environ.get("PRISMOR_HOME") or str(Path.home() / ".prismor")
    return Path(home) / "proxy.json"


def default_workspace() -> Path:
    """Where the proxy reads policy and stores sessions when none is given.

    Deliberately *not* ``Path.cwd()``. The proxy is a long-lived server
    governing some other agent's traffic, so the directory it happens to be
    launched from has nothing to do with what it screens - but the
    instruction-file scan reads that directory's CLAUDE.md / AGENTS.md and
    attributes what it finds to every event. Start it from a security repo
    whose own docs quote the attack strings its rules match and every request
    is refused with ``source: project_memory``, which reads as a false
    positive on the agent and is not one. A neutral home-owned directory keeps
    the surface judging only the traffic; ``--workspace`` opts into a repo's
    policy on purpose.
    """
    home = os.environ.get("PRISMOR_HOME") or str(Path.home() / ".prismor")
    ws = Path(home) / "surfaces" / "proxy"
    ws.mkdir(parents=True, exist_ok=True)
    return ws


def run_proxy(host: str = "127.0.0.1", port: int = 7080,
              workspace: Optional[Path] = None, mode: str = "observe",
              config_path: Optional[Path] = None,
              session_id: str = "", agent_name: str = "") -> None:
    """Start the LLM proxy (blocking)."""
    ws = workspace or default_workspace()
    config = ProxyConfig.load(config_path if config_path is not None
                              else default_config_path())
    ProxyHandler.config = config
    ProxyHandler.screen = Screen(
        workspace=ws, mode=mode,
        session_id=session_id or os.environ.get("PRISMOR_SESSION_ID")
        or f"proxy-{int(time.time())}-{os.getpid()}",
        agent_name=agent_name,
    )

    server = _ThreadingHTTPServer((host, port), ProxyHandler)
    base = f"http://{host}:{port}"
    print(f"[prismor] proxy listening on {base}  (mode: {mode})")
    print(f"[prismor] workspace: {ws}")
    if config.keys:
        print(f"[prismor] virtual keys: {len(config.keys)} "
              "(client keys swapped for provider credentials)")
    else:
        print("[prismor] auth pass-through (no virtual keys configured)")
    print(f"[prismor] point an agent at it:  ANTHROPIC_BASE_URL={base} claude")
    print(f"[prismor]                        OPENAI_BASE_URL={base}/v1 codex")
    def _stop(signum, _frame):
        # SIGTERM is how a container stops, so the flush has to hang off the
        # signal rather than only off KeyboardInterrupt.
        raise KeyboardInterrupt

    for _sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(_sig, _stop)
        except (ValueError, OSError):
            pass  # not the main thread, or the platform lacks the signal

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[prismor] proxy stopped.")
    finally:
        # Sessions here are often a single chat turn, well under the periodic
        # rebuild, so without this the console never sees them at all.
        ProxyHandler.screen.snapshot()


if __name__ == "__main__":
    import argparse as _ap
    _p = _ap.ArgumentParser(description="Prismor LLM policy proxy")
    _p.add_argument("--host", default="127.0.0.1")
    _p.add_argument("--port", type=int, default=7080)
    _p.add_argument("--mode", choices=["observe", "enforce"], default="observe")
    _p.add_argument("--workspace", default=None)
    _p.add_argument("--config", default=None)
    _a = _p.parse_args()
    run_proxy(host=_a.host, port=_a.port, mode=_a.mode,
              workspace=Path(_a.workspace) if _a.workspace else None,
              config_path=Path(_a.config) if _a.config else None)
