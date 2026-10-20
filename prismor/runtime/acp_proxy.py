"""Prismor ACP proxy — govern Agent Client Protocol agents (Zed, JetBrains, …).

An ACP editor launches its coding agent as a subprocess and speaks
newline-delimited JSON-RPC to it over stdio. The agent does its file and
terminal work by calling *client* methods (``fs/write_text_file``,
``terminal/create``, …) that the editor carries out for it, and asks the human
through ``session/request_permission``. ``prismor acp -- <agent…>`` sits on that
pipe in place of the agent::

    editor  <-- stdio -->  prismor acp  <-- stdio -->  claude-agent-acp

and runs the normal policy pipeline on what crosses it:

  ===========================  ===============================  ===========================
  ACP message                  Prismor event                    on a block
  ===========================  ===============================  ===========================
  session/prompt  (c→a)        UserPromptSubmit / prompt        recorded only
  terminal/create (a→c)        PreToolUse / shell               JSON-RPC error to the agent
  fs/write_text_file (a→c)     PreToolUse / file_write          JSON-RPC error to the agent
  fs/read_text_file (a→c)      PreToolUse / file_read           JSON-RPC error to the agent
  session/request_permission   PermissionRequest / native shape answered ``reject`` for the
                                                                human; step-up passes it on
  fs/read_text_file result     PostToolUse / tool_result        cloak-masked; withheld as an
                                                                error on injection
  terminal/output result       PostToolUse / tool_result        redacted; output withheld
  ===========================  ===============================  ===========================

A ``step_up`` verdict on a terminal or write is put to the human through the
editor's own permission dialog (a ``session/request_permission`` the proxy
originates), so ACP is an inline-approval surface like Claude Code's ``ask``.

Coverage limit: anything the agent does *inside its own process* — a built-in
web fetch, a shell it spawns itself because the editor did not advertise the
``terminal`` capability — never crosses this pipe. Those calls still need the
agent's native Prismor hooks. The proxy says on stderr which capabilities the
editor offered, so a gap is visible rather than assumed away.

Cloaking: ``@@SECRET:name@@`` in a ``terminal/create`` (command, args, env) or
``fs/write_text_file`` content is resolved just before the editor runs it, and
raw secret values in what comes back (terminal output, file reads) are masked to
placeholders before the agent sees them. File reads get cloak masking only —
the agent writes edited files back whole, and only a cloak placeholder can be
reversed on that write; a data-boundary mask could not, and would be written
over the user's file.

Transport is stdlib only: two reader threads, one per direction, each line
handled in order. Policy work happens inline; only a step-up (which waits on a
human) moves to a worker so it never stalls the rest of the session.
"""

from __future__ import annotations

import itertools
import json
import os
import shlex
import signal
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ACP_AGENT = "acp"
#: JSON-RPC error code for a policy refusal (implementation-defined server
#: error range). ``-32603`` would read as an editor bug.
POLICY_ERROR = -32000
#: Prefix of ids the proxy itself sends to the editor; never collides with an
#: agent id in practice and lets the client→agent reader claim its replies.
_OWN_ID_PREFIX = "prismor-acp:"
#: Methods the proxy acts on, agent → client.
_GUARDED_AGENT_REQUESTS = frozenset({
    "terminal/create", "fs/write_text_file", "fs/read_text_file",
    "session/request_permission",
})
#: Client capability each guarded client method needs.
_CAPABILITY_OF = {"terminal/create": "terminal", "fs/write_text_file": "fs.writeTextFile",
                  "fs/read_text_file": "fs.readTextFile"}
#: Agent → client requests whose *result* (client → agent) is scanned.
_SCANNED_RESULTS = frozenset({"fs/read_text_file", "terminal/output"})


def _log(msg: str) -> None:
    try:
        sys.stderr.write(f"[prismor-acp] {msg}\n")
        sys.stderr.flush()
    except Exception:
        pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def agent_label(argv: List[str]) -> str:
    """Short name for the wrapped agent (``claude-agent-acp``, ``gemini``…)."""
    for tok in argv:
        base = os.path.basename(tok)
        if not base or base.startswith("-") or base in _LAUNCHERS or base.startswith("python"):
            continue
        # @scope/pkg@version -> pkg
        if tok.startswith("@") and "/" in tok:
            base = tok.split("/", 1)[1]
        base = base.split("@", 1)[0] or base
        return base[:-3] if base.endswith((".py", ".js")) else base
    return "agent"


#: Runners in front of the real agent in an ``agent_servers`` command line.
_LAUNCHERS = frozenset({"npx", "node", "bun", "bunx", "deno", "uv", "uvx", "pipx", "pnpm",
                        "yarn", "dlx", "run", "exec", "env"})


# ── event shaping ────────────────────────────────────────────────────────────

def terminal_command_text(params: Dict[str, Any]) -> str:
    """The shell text a ``terminal/create`` will run.

    ACP carries ``command`` + ``args`` separately; editors typically run
    ``command`` through a shell when ``args`` is empty. ``sh -c "<script>"``
    is screened as the script itself so the command rules see the real work
    rather than an opaque ``sh`` invocation.
    """
    cmd = str(params.get("command") or "")
    args = [str(a) for a in (params.get("args") or []) if a is not None]
    if not args:
        return cmd
    if os.path.basename(cmd) in ("sh", "bash", "zsh", "dash", "fish") and len(args) >= 2 \
            and args[0] in ("-c", "-lc", "-ic", "-cl"):
        return args[1]
    return shlex.join([cmd, *args])


def client_call_event(method: str, params: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    """(native tool, event body) for a client method the agent asked the editor
    to carry out. Same shapes the hooks give Bash/Write/Read."""
    if method == "terminal/create":
        return "Bash", {"type": "shell", "command": terminal_command_text(params)}
    if method == "fs/write_text_file":
        return "Write", {"type": "file_write", "path": str(params.get("path") or ""),
                         "content": str(params.get("content") or "")}
    if method == "fs/read_text_file":
        return "Read", {"type": "file_read", "path": str(params.get("path") or "")}
    raise ValueError(f"not a guarded client call: {method}")


def permission_event(params: Dict[str, Any]) -> Dict[str, Any]:
    """Native-shaped body for a ``session/request_permission`` tool call.

    ACP's ``toolCall.kind`` says what the call is (execute / edit / read /
    fetch / …) and ``rawInput`` carries the agent's own tool arguments, so the
    same command, path and egress rules apply as to a hooked call. Unknown
    kinds fall back to the agent's tool name where it reports one (Claude's
    adapter sends ``_meta.claudeCode.toolName``) and then to a generic
    payload scan.
    """
    from prismor.runtime import mirror

    call = params.get("toolCall") or {}
    raw = call.get("rawInput")
    raw = raw if isinstance(raw, dict) else ({} if raw is None else {"raw": raw})
    kind = str(call.get("kind") or "").lower()
    title = str(call.get("title") or "")
    meta = call.get("_meta") if isinstance(call.get("_meta"), dict) else {}
    tool_name = ""
    for v in meta.values():
        if isinstance(v, dict) and v.get("toolName"):
            tool_name = str(v["toolName"])
            break
    locations = call.get("locations") or []
    loc_path = ""
    if isinstance(locations, list) and locations and isinstance(locations[0], dict):
        loc_path = str(locations[0].get("path") or "")

    native_by_kind = {"execute": "Bash", "edit": "Edit", "delete": "Write",
                      "move": "Write", "read": "Read", "search": "Grep",
                      "fetch": "WebFetch"}
    native = mirror.native_tool(tool_name, raw) if tool_name else None
    native = native or native_by_kind.get(kind)
    if native:
        _, args = mirror.native_call(native, dict(raw))
        if isinstance(args, dict):
            if native in ("Read", "Write", "Edit") and not args.get("file_path"):
                args["file_path"] = loc_path
            if native == "Bash" and not args.get("command"):
                args["command"] = title.strip("` ")
        shaped = mirror.shape_call_event(native, args)
        if shaped is not None:
            return {**shaped, "tool_name": tool_name or native}
    try:
        text = json.dumps(raw, default=str)
    except Exception:
        text = str(raw)
    return {"type": "tool_result", "response": f"{title}\n{text}".strip(),
            "tool_name": tool_name or title or kind or "tool"}


def _resolve_known(text: str, secrets: Dict[str, str]) -> str:
    """Resolve the placeholders named in ``secrets``; leave every other one literal."""
    from prismor.runtime.cloaking.runtime import _PLACEHOLDER_RE
    return _PLACEHOLDER_RE.sub(lambda m: secrets.get(m.group(1), m.group(0)), text)


def _reject_option(options: Any) -> Optional[str]:
    """optionId the agent should receive for a refusal: reject_once first."""
    if not isinstance(options, list):
        return None
    for want in ("reject_once", "reject_always"):
        for opt in options:
            if isinstance(opt, dict) and opt.get("kind") == want and opt.get("optionId") is not None:
                return opt["optionId"]
    return None


def _block_text(prefix: str, blocking: Dict[str, Any], *, evidence: bool = True,
                unblock: str = "") -> str:
    head = f"{prefix}: [{blocking.get('severity', 'HIGH')}] {blocking.get('title', 'policy violation')}"
    if blocking.get("ruleId"):
        head += f" (rule: {blocking['ruleId']})"
    parts = [head]
    if evidence and blocking.get("evidence"):
        parts.append(str(blocking["evidence"])[:500])
    if blocking.get("remediation"):
        parts.append(f"Recommended fix: {blocking['remediation']}")
    if unblock:
        parts += ["", unblock]
    return "\n".join(parts)


# ── the proxy ────────────────────────────────────────────────────────────────

class _Waiter:
    def __init__(self) -> None:
        self.event = threading.Event()
        self.msg: Optional[Dict[str, Any]] = None


class AcpProxy:
    """Relay one editor ⇄ agent ACP connection and govern what crosses it."""

    def __init__(self, argv: List[str], *, workspace: Path, mode: str = "enforce",
                 client_in=None, client_out=None, env: Optional[Dict[str, str]] = None,
                 pin_workspace: bool = False, audit: bool = True):
        if not argv:
            raise ValueError("no agent command given (usage: prismor acp -- <agent command…>)")
        self.argv = list(argv)
        self.workspace = Path(workspace)
        #: An explicit --workspace wins over each session's own cwd.
        self.pin_workspace = pin_workspace
        #: Screen tool calls the agent runs in-process (see _track_tool_update).
        #: Off when the agent's own Prismor hooks already record them.
        self.audit = audit
        self.mode = mode
        self.label = agent_label(self.argv)
        self.agent_name = f"acp:{self.label}"
        self._client_in = client_in if client_in is not None else sys.stdin.buffer
        self._client_out = client_out if client_out is not None else sys.stdout.buffer
        self._env = env
        self._child: Optional[subprocess.Popen] = None
        self._to_client_lock = threading.Lock()
        self._to_agent_lock = threading.Lock()
        self._eval_lock = threading.Lock()
        self._state_lock = threading.Lock()
        self._seq = itertools.count(1)
        #: agent→client request id -> (method, params), awaiting the client's reply.
        self._agent_reqs: Dict[Any, Tuple[str, Dict[str, Any]]] = {}
        #: client→agent request id -> (method, params), awaiting the agent's reply.
        self._client_reqs: Dict[Any, Tuple[str, Dict[str, Any]]] = {}
        #: ids of requests the proxy sent to the client itself.
        self._own: Dict[str, _Waiter] = {}
        #: ACP sessionId -> workspace cwd (from session/new, session/load).
        self._session_cwd: Dict[str, str] = {}
        #: terminalId -> the command text it runs (provenance for output scans),
        #: and the same keyed by the terminal/create request id until it answers.
        self._terminals: Dict[str, str] = {}
        self._terminal_cmds: Dict[Any, str] = {}
        #: path -> cloak placeholder names this proxy masked into a read of it;
        #: the only ones a later write of that path may resolve.
        self._masked_reads: Dict[str, set] = {}
        #: (sessionId, toolCallId) -> what the agent has reported about a tool
        #: call it is running itself (session/update), until it completes.
        self._observed: Dict[Tuple[str, str], Dict[str, Any]] = {}
        #: Audits of in-process calls run off the relay thread, one at a time
        #: so the session ledger sees them in order.
        self._audit = ThreadPoolExecutor(max_workers=1, thread_name_prefix="acp-audit")
        #: Client capabilities from `initialize`; None until the editor says.
        self._offered: Optional[set] = None
        self._closed = threading.Event()

    # ── lifecycle ────────────────────────────────────────────────────────

    def start(self) -> None:
        self._child = subprocess.Popen(
            self.argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=None, env=self._env, bufsize=0)

    def serve(self) -> int:
        if self._child is None:
            self.start()
        child = self._child
        assert child is not None and child.stdout is not None
        t_agent = threading.Thread(target=self._pump, name="acp-agent",
                                   args=(child.stdout, self._from_agent), daemon=True)
        t_client = threading.Thread(target=self._pump_client, name="acp-client", daemon=True)
        t_agent.start()
        t_client.start()
        code = child.wait()
        # Let the agent→client reader drain whatever the agent wrote last.
        t_agent.join(timeout=5)
        self._audit.shutdown(wait=True)
        self._closed.set()
        self._release_waiters()
        return code if code is not None and code >= 0 else 128 + (-code if code else 0)

    def close(self) -> None:
        self._closed.set()
        self._release_waiters()
        self._audit.shutdown(wait=False)
        child = self._child
        if child is None or child.poll() is not None:
            return
        try:
            if child.stdin:
                child.stdin.close()
        except Exception:
            pass
        try:
            child.terminate()
            child.wait(timeout=5)
        except Exception:
            try:
                child.kill()
            except Exception:
                pass

    def _release_waiters(self) -> None:
        with self._state_lock:
            waiters = list(self._own.values())
            self._own.clear()
        for w in waiters:
            w.event.set()

    def _pump(self, stream, handler) -> None:
        try:
            for raw in iter(stream.readline, b""):
                if not raw.strip():
                    continue
                try:
                    msg = json.loads(raw)
                except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
                    msg = None
                try:
                    handler(msg, raw)
                except Exception as exc:  # one bad message must not end the session
                    _log(f"internal error handling message: {exc}")
        except (OSError, ValueError):
            pass

    def _pump_client(self) -> None:
        self._pump(self._client_in, self._from_client)
        # Editor closed its end: let the agent see EOF and shut down cleanly.
        child = self._child
        try:
            if child is not None and child.stdin:
                with self._to_agent_lock:
                    child.stdin.close()
        except Exception:
            pass
        if child is not None:
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                child.terminate()

    # ── wire ─────────────────────────────────────────────────────────────

    def _write_client(self, msg: Any = None, raw: Optional[bytes] = None) -> None:
        data = raw if raw is not None else (json.dumps(msg, ensure_ascii=False) + "\n").encode("utf-8")
        if not data.endswith(b"\n"):
            data += b"\n"
        with self._to_client_lock:
            try:
                self._client_out.write(data)
                self._client_out.flush()
            except (OSError, ValueError):
                pass

    def _write_agent(self, msg: Any = None, raw: Optional[bytes] = None) -> None:
        child = self._child
        if child is None or child.stdin is None:
            return
        data = raw if raw is not None else (json.dumps(msg, ensure_ascii=False) + "\n").encode("utf-8")
        if not data.endswith(b"\n"):
            data += b"\n"
        with self._to_agent_lock:
            try:
                child.stdin.write(data)
                child.stdin.flush()
            except (OSError, ValueError):
                pass

    def _error_to_agent(self, req_id: Any, message: str, code: int = POLICY_ERROR) -> None:
        self._write_agent({"jsonrpc": "2.0", "id": req_id,
                           "error": {"code": code, "message": message}})

    def _notice(self, session_id: Optional[str], text: str) -> None:
        """Tell the human in the editor's own thread view.

        A refused permission reaches the agent as a bare "rejected" — it never
        learns why, so it cannot relay the reason. The editor renders an
        ``agent_message_chunk`` like any agent text, which is the one place the
        person at the keyboard will see it.
        """
        if not session_id:
            return
        # First line is the headline; the rest (evidence, unblock commands) goes
        # in a fenced block so editors neither render it as the agent's own text
        # nor "smart-punctuate" `--pattern` into something that won't paste.
        # Every line is quoted so the whole notice reads as one aside.
        head, _, rest = text.partition("\n")
        body = f"**Prismor:** {head}"
        if rest.strip():
            body += "\n```\n" + rest.strip("\n").replace("```", "'''") + "\n```"
        quoted = "\n".join(f"> {line}" if line else ">" for line in body.splitlines())
        self._write_client({"jsonrpc": "2.0", "method": "session/update", "params": {
            "sessionId": session_id,
            "update": {"sessionUpdate": "agent_message_chunk",
                       "content": {"type": "text", "text": f"\n\n{quoted}\n\n"}},
        }})

    def _ask_client(self, method: str, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Send a request of our own to the editor and wait for its reply."""
        req_id = f"{_OWN_ID_PREFIX}{next(self._seq)}"
        waiter = _Waiter()
        with self._state_lock:
            if self._closed.is_set():
                return None
            self._own[req_id] = waiter
        self._write_client({"jsonrpc": "2.0", "id": req_id, "method": method, "params": params})
        waiter.event.wait()
        return waiter.msg

    # ── agent → client ───────────────────────────────────────────────────

    def _from_agent(self, msg: Any, raw: bytes) -> None:
        if isinstance(msg, list):
            # A batch would carry a terminal/create past inspection if relayed
            # whole; ACP does not use batches, so unbundle and treat each alone.
            for item in msg:
                self._from_agent(item, (json.dumps(item) + "\n").encode("utf-8"))
            return
        if not isinstance(msg, dict):
            self._write_client(raw=raw)
            return
        method = msg.get("method")
        req_id = msg.get("id")
        if method is None and req_id is not None:
            # Response to a client request.
            with self._state_lock:
                pending = self._client_reqs.pop(req_id, None)
            # Relay first: anything the result triggers (a session-start notice)
            # must reach the editor after the session it names.
            self._write_client(raw=raw)
            if pending is not None:
                self._on_agent_result(pending[0], pending[1], msg)
            return
        if method is not None and req_id is not None and method in _GUARDED_AGENT_REQUESTS:
            params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
            self._guard_agent_request(msg, method, params)
            return
        if method is not None and req_id is not None:
            params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
            with self._state_lock:
                self._agent_reqs[req_id] = (method, params)
        self._write_client(raw=raw)
        if method == "session/update" and req_id is None and isinstance(msg.get("params"), dict):
            self._track_tool_update(msg["params"])

    def _forward_agent_request(self, msg: Dict[str, Any], params: Dict[str, Any]) -> None:
        """Relay ``msg`` to the editor, remembering ``params`` (the agent's own,
        placeholder form) for the reply."""
        with self._state_lock:
            self._agent_reqs[msg["id"]] = (str(msg["method"]), params)
        self._write_client(msg)

    def _guard_agent_request(self, msg: Dict[str, Any], method: str, params: Dict[str, Any]) -> None:
        self._mark_covered(params.get("sessionId"),
                           (params.get("toolCall") or {}).get("toolCallId")
                           if method == "session/request_permission" else None)
        if method == "session/request_permission":
            self._guard_permission(msg, params)
            return
        needs = _CAPABILITY_OF.get(method)
        with self._state_lock:
            offered = self._offered
        if needs and offered is not None and needs not in offered:
            # The editor never offered this. Some (CodeCompanion) leave an
            # unadvertised call unanswered, which hangs the agent's turn;
            # answer the way a compliant editor would.
            self._error_to_agent(msg["id"], f"the editor did not advertise {needs}: {method} "
                                 "is not available", code=-32601)
            return
        session_id = params.get("sessionId")
        tool, body = client_call_event(method, params)
        event = self._event(session_id, "PreToolUse", tool, method, body)
        decision, err = self._evaluate(event, session_id)
        if err is not None:
            self._error_to_agent(msg["id"], err)
            return
        passthrough = self._passthrough()
        blocking = decision.blocking if decision is not None else None
        if blocking is not None and passthrough:
            _log(f"would have blocked {method} ({blocking.get('ruleId') or blocking.get('title')}) — "
                 "passing through: prismor is paused")
            blocking = None
        if blocking is None:
            self._release(msg, method, params)
            return

        from prismor.runtime.contract import verdict_of
        verdict = verdict_of(blocking)
        if verdict == "defer":
            try:
                from prismor.runtime.enterprise import deferred as _deferred
                cleared = _deferred.resolve_defer(
                    blocking, event, session_id=self._sid(session_id),
                    workspace=self._workspace_for(session_id))
            except Exception:
                cleared = False
            if cleared:
                self._release(msg, method, params)
                return
            verdict = "block"
        if verdict == "modify" and str(blocking.get("transform") or "") == "pii_redact" \
                and method != "fs/read_text_file":
            try:
                from prismor.runtime.enterprise.approvals import redact_approved_payload
                key = "content" if method == "fs/write_text_file" else "args"
                redacted = dict(params)
                if method == "terminal/create" and not params.get("args"):
                    key = "command"
                redacted[key] = redact_approved_payload(params.get(key),
                                                        workspace=self._workspace_for(session_id))
                _log(f"redacted sensitive values from {method} ({blocking.get('ruleId')})")
                self._release(msg, method, redacted)
                return
            except Exception:
                pass  # fall through to a refusal: never forward what policy said to strip
        if verdict == "step_up":
            threading.Thread(target=self._step_up, name="acp-step-up",
                             args=(msg, method, params, blocking, tool), daemon=True).start()
            return
        self._refuse(msg, method, session_id, blocking)

    def _refuse(self, msg: Dict[str, Any], method: str, session_id: Optional[str],
                blocking: Dict[str, Any], prefix: str = "Blocked by Prismor") -> None:
        text = _block_text(prefix, blocking, unblock=self._unblock_text(blocking, session_id))
        _log(f"blocked {method}: {blocking.get('ruleId') or blocking.get('title')}")
        self._error_to_agent(msg["id"], text)

    def _step_up(self, msg: Dict[str, Any], method: str, params: Dict[str, Any],
                 blocking: Dict[str, Any], tool: str) -> None:
        """Put a step-up verdict to the human through the editor's dialog."""
        session_id = params.get("sessionId")
        if method == "terminal/create":
            what, kind = terminal_command_text(params), "execute"
            raw_input: Dict[str, Any] = {"command": what}
            locations: List[Dict[str, Any]] = []
        else:
            what, kind = str(params.get("path") or ""), "edit" if tool == "Write" else "read"
            raw_input = {"file_path": what}
            locations = [{"path": what}] if what else []
        reason = f"{blocking.get('title') or 'policy'}"
        if blocking.get("ruleId"):
            reason += f" (rule: {blocking['ruleId']})"
        reply = self._ask_client("session/request_permission", {
            "sessionId": session_id,
            "toolCall": {
                "toolCallId": f"prismor-{next(self._seq)}",
                "title": f"Prismor needs your OK — {reason}: {what[:200]}",
                "kind": kind, "status": "pending",
                "rawInput": raw_input, "locations": locations,
            },
            "options": [
                {"optionId": "prismor-allow", "name": "Allow once", "kind": "allow_once"},
                {"optionId": "prismor-reject", "name": "Reject", "kind": "reject_once"},
            ],
        })
        outcome = ((reply or {}).get("result") or {}).get("outcome") or {}
        if outcome.get("outcome") == "selected" and outcome.get("optionId") == "prismor-allow":
            _log(f"approved by the user: {method} ({blocking.get('ruleId')})")
            self._release(msg, method, params)
            return
        self._refuse(msg, method, session_id, blocking, prefix="Rejected by the user (Prismor step-up)")

    def _release(self, msg: Dict[str, Any], method: str, params: Dict[str, Any]) -> None:
        """Forward an allowed request, resolving cloak placeholders on the way."""
        try:
            out = self._decloak(method, params)
        except KeyError as exc:
            self._error_to_agent(msg["id"], (
                f"Blocked by Prismor: unknown secret placeholder @@SECRET:{exc.args[0]}@@ — "
                "register it with `prismor cloak add` (refusing to run the literal placeholder)."))
            return
        if method == "terminal/create":
            # Command text for provenance on the output scan; stored with the
            # placeholder form, never the resolved value.
            with self._state_lock:
                self._terminal_cmds[msg["id"]] = terminal_command_text(params)
        self._forward_agent_request({**msg, "params": out}, params)

    def _decloak(self, method: str, params: Dict[str, Any]) -> Dict[str, Any]:
        from prismor.runtime.cloaking.runtime import decloak_text, placeholder_names
        if method == "terminal/create":
            fields = [params.get("command")] + list(params.get("args") or []) + [
                e.get("value") for e in (params.get("env") or []) if isinstance(e, dict)]
            if not any(isinstance(f, str) and placeholder_names(f) for f in fields):
                return params
            out = dict(params)
            out["command"] = decloak_text(str(params.get("command") or ""))
            if params.get("args"):
                out["args"] = [decloak_text(a) if isinstance(a, str) else a for a in params["args"]]
            if params.get("env"):
                out["env"] = [({**e, "value": decloak_text(e["value"])}
                               if isinstance(e, dict) and isinstance(e.get("value"), str) else e)
                              for e in params["env"]]
            _log("resolved cloaked secret placeholder(s) for terminal/create")
            return out
        if method == "fs/write_text_file":
            content = params.get("content")
            if not isinstance(content, str) or not placeholder_names(content):
                return params
            # A file read masks secrets to placeholders; an edit writes the file
            # back whole. Resolving here keeps that round trip from replacing
            # the user's real values with placeholders. Only the names this
            # proxy masked out of THIS file are resolved: otherwise a write
            # would be a way to drop any registered secret into any file.
            with self._state_lock:
                allowed = set(self._masked_reads.get(str(params.get("path") or ""), ()))
            if not allowed:
                return params
            from prismor.runtime.cloaking.runtime import _read_secret_map
            secrets = {k: v for k, v in _read_secret_map().items() if k in allowed}
            return {**params, "content": _resolve_known(content, secrets)}
        return params

    def _guard_permission(self, msg: Dict[str, Any], params: Dict[str, Any]) -> None:
        session_id = params.get("sessionId")
        shaped = permission_event(params)
        tool_name = shaped.pop("tool_name", "tool")
        event = self._event(session_id, "PermissionRequest", tool_name,
                            "session/request_permission", shaped)
        decision, err = self._evaluate(event, session_id)
        if err is not None:
            # The human is about to be asked anyway, so a broken engine falls
            # back to their judgment rather than to a silent allow or a refusal.
            _log(err)
            self._forward_agent_request(msg, params)
            return
        blocking = decision.blocking if decision is not None else None
        if blocking is not None and self._passthrough():
            _log(f"would have refused permission ({blocking.get('ruleId')}) — prismor is paused")
            blocking = None
        if blocking is None:
            self._forward_agent_request(msg, params)
            return
        from prismor.runtime.contract import verdict_of
        verdict = verdict_of(blocking)
        if verdict in ("step_up", "modify", "defer", "warn"):
            # Step-up is exactly what this request is: let the human decide —
            # but only this once. "Always allow" would let every later call of
            # the kind skip both the human and the policy.
            opts = params.get("options")
            if verdict == "step_up" and isinstance(opts, list):
                narrowed = [o for o in opts if not (isinstance(o, dict) and o.get("kind") == "allow_always")]
                if narrowed and any(isinstance(o, dict) and str(o.get("kind", "")).startswith("allow")
                                    for o in narrowed):
                    params = {**params, "options": narrowed}
                    msg = {**msg, "params": params}
            self._forward_agent_request(msg, params)
            return
        option = _reject_option(params.get("options"))
        outcome = ({"outcome": "selected", "optionId": option} if option is not None
                   else {"outcome": "cancelled"})
        _log(f"refused permission for {tool_name}: {blocking.get('ruleId') or blocking.get('title')}")
        # Notice first: the agent reports the refusal as the user's ("User
        # refused permission"), and the reader should already know it wasn't.
        title = str((params.get("toolCall") or {}).get("title") or tool_name)
        self._notice(session_id, _block_text(
            f"blocked `{title[:120]}` (you were not asked; the agent will report it as refused)",
            blocking, unblock=self._unblock_text(blocking, session_id)))
        self._write_agent({"jsonrpc": "2.0", "id": msg["id"], "result": {"outcome": outcome}})

    # ── tools the agent runs itself ──────────────────────────────────────

    def _track_tool_update(self, params: Dict[str, Any]) -> None:
        """Follow a tool call the agent reports but may never route through us.

        Most agents run their own Bash/Write in-process and only *describe* the
        call to the editor (``tool_call`` / ``tool_call_update``). Nothing can
        be refused there — the call is already under way — but it can still be
        screened and recorded once it completes, so the session ledger is whole
        and a call policy would have refused is surfaced rather than unseen.
        """
        update = params.get("update")
        if not isinstance(update, dict) or update.get("sessionUpdate") not in ("tool_call", "tool_call_update"):
            return
        sid, tcid = str(params.get("sessionId") or ""), str(update.get("toolCallId") or "")
        if not tcid:
            return
        key = (sid, tcid)
        with self._state_lock:
            rec = self._observed.get(key)
            if rec is None:
                if len(self._observed) > 2000:  # an agent that never completes calls
                    self._observed.clear()
                rec = self._observed[key] = {"covered": False}
            for name in ("kind", "title", "locations"):
                if update.get(name):
                    rec[name] = update[name]
            if isinstance(update.get("rawInput"), dict) and update["rawInput"]:
                rec["rawInput"] = update["rawInput"]
            if isinstance(update.get("_meta"), dict):
                rec["_meta"] = update["_meta"]
            if update.get("rawOutput") is not None:
                rec["rawOutput"] = update["rawOutput"]
            done = update.get("status") in ("completed", "failed")
            if done:
                rec["status"] = update["status"]
                self._observed.pop(key, None)
        if done and self.audit and not rec.get("covered") and not self._closed.is_set():
            try:
                self._audit.submit(self._audit_call, sid, rec)
            except RuntimeError:  # executor already shut down
                pass

    def _mark_covered(self, session_id: Any, tool_call_id: Any = None) -> None:
        """A client call or permission request arrived: the tool call(s) behind it
        are screened on that path, so the after-the-fact audit skips them."""
        sid = str(session_id or "")
        with self._state_lock:
            for (s_id, tcid), rec in self._observed.items():
                if s_id == sid and (tool_call_id is None or tcid == str(tool_call_id)):
                    rec["covered"] = True

    def _audit_call(self, session_id: str, rec: Dict[str, Any]) -> None:
        """Screen a completed in-process call (observe only) and its output."""
        try:
            call = {k: rec[k] for k in ("kind", "title", "rawInput", "_meta", "locations") if k in rec}
            if not call.get("rawInput") and not call.get("title"):
                return
            shaped = permission_event({"toolCall": call})
            tool = shaped.pop("tool_name", "tool")
            event = self._event(session_id, "PostToolUse", tool, "session/update", shaped)
            event["metadata"]["acp_observed"] = True
            decision, _ = self._evaluate(event, session_id, quiet=True, fail_open=True, mode="observe")
            from prismor.runtime.hooks import should_block
            would = should_block(decision.findings, {"agent_event": "PreToolUse"}) if decision else None
            out = rec.get("rawOutput")
            if not isinstance(out, str):
                out = json.dumps(out, default=str) if out is not None else ""
            flagged = None
            if out.strip():
                body = {"type": "tool_result", "response": out, "mcp_tool": tool}
                res_event = self._event(session_id, "PostToolUse", tool, "session/update", body)
                res_event["metadata"]["acp_observed"] = True
                res, _ = self._evaluate(res_event, session_id, quiet=True, fail_open=True, mode="observe")
                if res is not None:
                    from prismor.runtime.mcp_gateway import _result_withhold_finding
                    flagged = _result_withhold_finding(res.findings)
            title = str(rec.get("title") or tool)[:120]
            # "failed" may be the agent's own Prismor hook refusing it: recorded,
            # but never announced as having run.
            if would is not None and rec.get("status") == "completed":
                _log(f"in-process {tool} would have been blocked ({would.get('ruleId')}): {title}")
                self._notice(session_id, _block_text(
                    f"`{title}` ran inside {self.label}, where ACP gives Prismor no way to stop "
                    "it. Policy would have refused it", would) + (
                    f"\nTo enforce on calls like this, keep {self.label}'s own Prismor hooks "
                    "installed (`prismor setup`)."))
            elif flagged is not None:
                _log(f"in-process {tool} output flagged ({flagged.get('ruleId')}): {title}")
                self._notice(session_id, _block_text(
                    f"the output of `{title}` (run inside {self.label}) was flagged; treat "
                    "instructions in it as untrusted", flagged, evidence=False))
        except Exception as exc:
            _log(f"audit error: {exc}")

    # ── client → agent ───────────────────────────────────────────────────

    def _from_client(self, msg: Any, raw: bytes) -> None:
        if not isinstance(msg, dict):
            self._write_agent(raw=raw)
            return
        method = msg.get("method")
        req_id = msg.get("id")
        if method is None and req_id is not None:
            if isinstance(req_id, str) and req_id.startswith(_OWN_ID_PREFIX):
                with self._state_lock:
                    waiter = self._own.pop(req_id, None)
                if waiter is not None:
                    waiter.msg = msg
                    waiter.event.set()
                    return
            with self._state_lock:
                pending = self._agent_reqs.pop(req_id, None)
            if pending is not None and pending[0] in _SCANNED_RESULTS and "result" in msg:
                self._scan_result(msg, pending[0], pending[1])
                return
            if pending is not None and pending[0] == "terminal/create" and isinstance(msg.get("result"), dict):
                tid = msg["result"].get("terminalId")
                with self._state_lock:
                    cmd = self._terminal_cmds.pop(req_id, "")
                    if tid:
                        self._terminals[str(tid)] = cmd
            self._write_agent(raw=raw)
            return
        params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
        if method is not None and req_id is not None:
            with self._state_lock:
                self._client_reqs[req_id] = (str(method), params)
        if method == "initialize":
            self._report_capabilities(params)
        elif method == "session/load" and params.get("sessionId") and params.get("cwd"):
            with self._state_lock:
                self._session_cwd[str(params["sessionId"])] = str(params["cwd"])
        elif method == "session/prompt":
            self._record_prompt(params)
        self._write_agent(raw=raw)

    def _on_agent_result(self, method: str, params: Dict[str, Any], msg: Dict[str, Any]) -> None:
        result = msg.get("result")
        session_id = None
        if method == "session/new" and isinstance(result, dict) and result.get("sessionId"):
            session_id = str(result["sessionId"])
            with self._state_lock:
                self._session_cwd[session_id] = str(params.get("cwd") or "")
        elif method == "session/load" and "result" in msg and params.get("sessionId"):
            session_id = str(params["sessionId"])
        if session_id:
            self._scan_session_memory(session_id)

    def _scan_session_memory(self, session_id: str) -> None:
        """The SessionStart scan, at the moment ACP actually starts a session.

        Without it the runtime piggy-backs the project-memory scan on the
        session's first tool call — and a flagged CLAUDE.md/AGENTS.md then
        refuses that call (a write, a test run) for reasons that have nothing to
        do with it. Here it runs once, up front, the way Claude's SessionStart
        hook does, and the person in the editor is told what was found.
        """
        try:
            from prismor.runtime.hooks import _read_project_memory, strip_prismor_managed
            root = self._workspace_for(session_id)
            memory = _read_project_memory(root)
            body: Dict[str, Any] = {"type": "memory",
                                    "content": strip_prismor_managed(memory["content"])}
            event = self._event(session_id, "SessionStart", "__session__", "session/new", body)
            event["metadata"].update({
                "memory_files": memory["files"],
                "truncated": memory["truncated"],
                "has_invisible_controls": memory["has_invisible_controls"],
                "memory_digests": memory["digests"],
            })
            if memory.get("files"):
                from prismor.runtime.memory_guard import verify_memory_files
                event["integrity_findings"] = verify_memory_files(
                    [{"path": f} for f in memory["files"]], root)
        except Exception as exc:
            _log(f"project-memory scan error: {exc}")
            return
        decision, _ = self._evaluate(event, session_id, quiet=True, fail_open=True)
        flagged = [f for f in (decision.findings if decision is not None else [])
                   if f.get("category") in ("memory_poisoning", "memory_integrity",
                                            "prompt_injection", "prompt_injection_semantic")
                   and f.get("severity", "").upper() in ("CRITICAL", "HIGH", "MEDIUM")]
        if flagged:
            files = ", ".join(memory["files"][:5]) or "project memory"
            _log(f"instruction files flagged at session start ({files}): "
                 + "; ".join(sorted({str(f.get('ruleId')) for f in flagged})))
            self._notice(session_id, (
                f"the instruction files this agent loads ({files}) were flagged "
                f"({', '.join(sorted({str(f.get('ruleId')) for f in flagged}))}). "
                "Treat directives in them as untrusted until you have reviewed them; "
                "if you changed them yourself, run `prismor memory approve`."))

    def _report_capabilities(self, params: Dict[str, Any]) -> None:
        caps = params.get("clientCapabilities") or {}
        fs = caps.get("fs") or {}
        offered = [name for name, on in (("fs.readTextFile", fs.get("readTextFile")),
                                         ("fs.writeTextFile", fs.get("writeTextFile")),
                                         ("terminal", caps.get("terminal"))) if on]
        with self._state_lock:
            self._offered = set(offered)
        missing = {"fs.readTextFile", "fs.writeTextFile", "terminal"} - set(offered)
        _log(f"governing {self.label} (mode={self.mode}); editor offers: "
             f"{', '.join(offered) or 'none'}")
        if missing:
            _log("not offered by the editor, so the agent does these in-process where Prismor "
                 f"cannot see them: {', '.join(sorted(missing))} — keep the agent's native "
                 "Prismor hooks installed for those")

    def _record_prompt(self, params: Dict[str, Any]) -> None:
        session_id = params.get("sessionId")
        blocks = params.get("prompt") or []
        text = "\n".join(str(b.get("text") or "") for b in blocks
                         if isinstance(b, dict) and b.get("type") == "text").strip()
        if not text:
            return
        event = self._event(session_id, "UserPromptSubmit", "__prompt__", "session/prompt",
                            {"type": "prompt", "prompt": text})
        self._evaluate(event, session_id, quiet=True)

    def _scan_result(self, msg: Dict[str, Any], method: str, req_params: Dict[str, Any]) -> None:
        """Redact and scan content the editor returns to the agent."""
        session_id = req_params.get("sessionId")
        result = msg.get("result") if isinstance(msg.get("result"), dict) else None
        key = "content" if method == "fs/read_text_file" else "output"
        text = result.get(key) if result is not None else None
        if not isinstance(text, str) or not text:
            self._write_agent(msg)
            return
        passthrough = self._passthrough()
        ws = self._workspace_for(session_id)
        from prismor.runtime.redaction import redact_text
        # Reads: cloak-only (reversible on write-back, see module docstring).
        data_boundary = (method == "terminal/output") and not passthrough
        try:
            text2, changed = redact_text(text, workspace=ws, data_boundary=data_boundary)
        except Exception:
            text2, changed = text, False
        if changed:
            _log(f"redacted sensitive values from {method} result")
        if changed and method == "fs/read_text_file":
            from prismor.runtime.cloaking.runtime import placeholder_names
            masked = set(placeholder_names(text2)) - set(placeholder_names(text))
            if masked:
                with self._state_lock:
                    self._masked_reads.setdefault(str(req_params.get("path") or ""), set()).update(masked)
        if method == "fs/read_text_file":
            body = {"type": "tool_result", "response": text2,
                    "path": str(req_params.get("path") or ""), "mcp_tool": "Read"}
            tool = "Read"
        else:
            with self._state_lock:
                cmd = self._terminals.get(str(req_params.get("terminalId") or ""), "")
            body = {"type": "tool_result", "response": text2, "command": cmd, "mcp_tool": "Bash"}
            tool = "Bash"
        event = self._event(session_id, "PostToolUse", tool, method, body)
        decision, _err = self._evaluate(event, session_id, fail_open=True)
        withhold = None
        if decision is not None and not passthrough:
            withhold = decision.blocking
            if withhold is None and self.mode == "enforce":
                from prismor.runtime.mcp_gateway import _result_withhold_finding
                withhold = _result_withhold_finding(decision.findings)
        if withhold is not None:
            _log(f"withheld {method} result: {withhold.get('ruleId') or withhold.get('title')}")
            notice = _block_text("[Prismor] content withheld", withhold, evidence=False,
                                 unblock=self._unblock_text(withhold, session_id, withheld=True))
            if method == "fs/read_text_file":
                # An error, not replacement text: an agent that edits by read →
                # modify → write-whole would otherwise write the notice over the file.
                self._error_to_agent(msg.get("id"), notice)
            else:
                out = dict(msg)
                out["result"] = {**result, "output": notice}
                self._write_agent(out)
            return
        if changed:
            out = dict(msg)
            out["result"] = {**result, key: text2}
            self._write_agent(out)
            return
        self._write_agent(msg)

    # ── policy plumbing ──────────────────────────────────────────────────

    def _sid(self, session_id: Optional[str]) -> str:
        return f"acp-{session_id}" if session_id else f"acp-{os.getpid()}"

    def _workspace_for(self, session_id: Optional[str]) -> Path:
        if self.pin_workspace:
            return self.workspace
        with self._state_lock:
            cwd = self._session_cwd.get(str(session_id or ""))
        if cwd:
            try:
                p = Path(cwd)
                if p.is_dir():
                    return p
            except Exception:
                pass
        return self.workspace

    def _event(self, session_id: Optional[str], agent_event: str, tool: str, method: str,
               body: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "ts": _now(),
            "session_id": self._sid(session_id),
            "agent": ACP_AGENT,
            "agent_event": agent_event,
            "metadata": {
                "cwd": str(self._workspace_for(session_id)),
                # The native name, so every rule written for Bash/Read/Write
                # matches here too; the ACP method rides along for provenance.
                "tool_name": tool,
                "acp_method": method,
                "acp_agent": self.label,
                "surface": "acp",
            },
            **body,
        }

    def _evaluate(self, event: Dict[str, Any], session_id: Optional[str], *,
                  quiet: bool = False, fail_open: bool = False, mode: Optional[str] = None):
        """(decision, error). ``error`` is set only when the engine failed in
        enforce mode on a pre-action call — the caller refuses with it."""
        try:
            from prismor.runtime.runtime import evaluate_tool_call, log_observe_findings
            with self._eval_lock:
                decision = evaluate_tool_call(
                    event=event, workspace=self._workspace_for(session_id),
                    agent=ACP_AGENT, mode=mode or self.mode,
                    session_id=self._sid(session_id), agent_name=self.agent_name)
            if not quiet and decision is not None:
                try:
                    log_observe_findings(decision, tool_name=event["metadata"]["tool_name"],
                                         mode="observe" if self._passthrough() else self.mode)
                except Exception:
                    pass
            return decision, None
        except Exception as exc:
            _log(f"evaluation error: {exc}")
            if self.mode == "enforce" and not fail_open and event.get("agent_event") != "UserPromptSubmit":
                return None, (f"Blocked by Prismor: policy evaluation failed ({exc}); "
                              "call denied (fail-closed)")
            return None, None

    def _passthrough(self) -> bool:
        try:
            from prismor.runtime import mirror as _mirror
            return _mirror.passthrough_state(None) is not None
        except Exception:
            return False

    def _unblock_text(self, blocking: Dict[str, Any], session_id: Optional[str],
                      withheld: bool = False) -> str:
        if withheld:
            blocking = {**blocking, "evidence": ""}
        try:
            from prismor.runtime import unblock as _unblock
            from prismor.runtime.enterprise import identity as _identity
            from prismor.runtime.enterprise import workspace_scope as _scope
            ws = self._workspace_for(session_id)
            return _unblock.format_unblock(
                blocking, workspace=ws, session_id=self._sid(session_id),
                org_managed=_scope.is_managed(ws), enrolled=_identity.is_enrolled()) or ""
        except Exception:
            return ""


def run_acp(args, workspace: Path) -> int:
    """Entry point for ``prismor acp -- <agent command…>`` (called from cli.main)."""
    argv = list(getattr(args, "agent_command", None) or [])
    if argv and argv[0] == "--":
        argv = argv[1:]
    if not argv:
        sys.stderr.write(
            "usage: prismor acp [--mode enforce|observe] -- <agent command…>\n"
            "  e.g. prismor acp -- npx -y @agentclientprotocol/claude-agent-acp\n")
        return 2
    proxy = AcpProxy(argv, workspace=workspace, mode=getattr(args, "mode", None) or "enforce",
                     pin_workspace=bool(getattr(args, "workspace", None)
                                        or os.environ.get("PRISMOR_WORKSPACE")),
                     audit=not getattr(args, "no_audit", False))
    try:
        proxy.start()
    except OSError as exc:
        sys.stderr.write(f"[prismor-acp] could not start agent {argv[0]!r}: {exc}\n")
        return 127

    def _shutdown(signum, frame):  # noqa: ARG001
        proxy.close()
        raise SystemExit(128 + signum)

    try:
        signal.signal(signal.SIGTERM, _shutdown)
        signal.signal(signal.SIGINT, _shutdown)
    except (ValueError, OSError):
        pass
    try:
        return proxy.serve()
    finally:
        proxy.close()
