"""A scripted ACP agent for the `prismor acp` proxy tests.

Speaks newline-delimited JSON-RPC on stdio like a real ACP agent. Each
`session/prompt` carries one JSON instruction as its text block, and the agent
performs it by calling the matching *client* method, then reports what came
back as an `agent_message_chunk` before ending the turn:

    {"op": "run", "command": "ls", "args": [], "env": [...]}
        -> terminal/create, terminal/output, terminal/release
    {"op": "write", "path": "...", "content": "..."}   -> fs/write_text_file
    {"op": "read", "path": "..."}                       -> fs/read_text_file
    {"op": "perm", "toolCall": {...}, "options": [...]} -> session/request_permission
    {"op": "echo"}                                       -> no client call

The report is a JSON object: {"ok": <result>} or {"error": <error>}.
"""
import base64
import itertools
import json
import sys
import threading

_ids = itertools.count(1)
_pending = {}
_lock = threading.Lock()


def send(msg):
    with _lock:
        sys.stdout.write(json.dumps(msg) + "\n")
        sys.stdout.flush()


def call(method, params):
    req_id = next(_ids)
    ev = threading.Event()
    _pending[req_id] = [ev, None]
    send({"jsonrpc": "2.0", "id": req_id, "method": method, "params": params})
    ev.wait()
    return _pending.pop(req_id)[1]


def say(session_id, obj):
    send({"jsonrpc": "2.0", "method": "session/update", "params": {
        "sessionId": session_id,
        "update": {"sessionUpdate": "agent_message_chunk",
                   "content": {"type": "text", "text": json.dumps(obj)}}}})


def report(session_id, reply):
    say(session_id, {"error": reply["error"]} if "error" in reply else {"ok": reply.get("result")})


def do_prompt(req_id, params):
    sid = params["sessionId"]
    text = "".join(b.get("text", "") for b in params.get("prompt", []) if b.get("type") == "text")
    try:
        op = json.loads(text)
    except ValueError:
        op = {"op": "echo"}
    kind = op.get("op")
    if kind == "run":
        reply = call("terminal/create", {"sessionId": sid, "command": op["command"],
                                         "args": op.get("args", []), "env": op.get("env", [])})
        if "error" in reply:
            report(sid, reply)
        else:
            tid = reply["result"]["terminalId"]
            out = call("terminal/output", {"sessionId": sid, "terminalId": tid})
            call("terminal/release", {"sessionId": sid, "terminalId": tid})
            report(sid, out)
    elif kind == "write":
        report(sid, call("fs/write_text_file", {"sessionId": sid, "path": op["path"],
                                                "content": op["content"]}))
    elif kind == "read":
        report(sid, call("fs/read_text_file", {"sessionId": sid, "path": op["path"]}))
    elif kind == "inproc":
        # A tool the agent runs itself: described to the editor, never routed
        # through a client method (how Claude's and Codex's adapters run Bash).
        tcid = op.get("id", "inproc-1")
        send({"jsonrpc": "2.0", "method": "session/update", "params": {"sessionId": sid, "update": {
            "sessionUpdate": "tool_call", "toolCallId": tcid, "status": "pending",
            "title": "Terminal", "kind": op.get("kind", "execute"), "rawInput": {},
            "_meta": {"claudeCode": {"toolName": op.get("tool", "Bash")}}}}})
        send({"jsonrpc": "2.0", "method": "session/update", "params": {"sessionId": sid, "update": {
            "sessionUpdate": "tool_call_update", "toolCallId": tcid,
            "title": op.get("title", ""), "rawInput": op["rawInput"]}}})
        if op.get("ask"):  # Claude's canUseTool: ask the human about this very call
            call("session/request_permission", {"sessionId": sid, "options": [
                {"optionId": "allow", "name": "Allow", "kind": "allow_once"},
                {"optionId": "reject", "name": "Reject", "kind": "reject_once"}],
                "toolCall": {"toolCallId": tcid, "title": op.get("title", ""),
                             "kind": op.get("kind", "execute"), "rawInput": op["rawInput"]}})
        send({"jsonrpc": "2.0", "method": "session/update", "params": {"sessionId": sid, "update": {
            "sessionUpdate": "tool_call_update", "toolCallId": tcid, "status": "completed",
            # base64 form keeps test payloads out of the prompt text itself
            "rawOutput": (base64.b64decode(op["rawOutputB64"]).decode() if "rawOutputB64" in op
                          else op.get("rawOutput", ""))}}})
        say(sid, {"ok": "inproc"})
    elif kind == "perm":
        report(sid, call("session/request_permission", {
            "sessionId": sid, "toolCall": op["toolCall"], "options": op["options"]}))
    else:
        say(sid, {"ok": "echo"})
    send({"jsonrpc": "2.0", "id": req_id, "result": {"stopReason": "end_turn"}})


def main():
    for line in sys.stdin:
        if not line.strip():
            continue
        msg = json.loads(line)
        if "method" not in msg:  # a reply to one of our client calls
            slot = _pending.get(msg.get("id"))
            if slot:
                slot[1] = msg
                slot[0].set()
            continue
        method, req_id, params = msg["method"], msg.get("id"), msg.get("params") or {}
        if method == "initialize":
            send({"jsonrpc": "2.0", "id": req_id, "result": {
                "protocolVersion": 1, "agentCapabilities": {}, "authMethods": []}})
        elif method == "session/new":
            send({"jsonrpc": "2.0", "id": req_id, "result": {"sessionId": "sess-1"}})
        elif method == "session/prompt":
            threading.Thread(target=do_prompt, args=(req_id, params), daemon=True).start()
        elif req_id is not None:
            send({"jsonrpc": "2.0", "id": req_id,
                  "error": {"code": -32601, "message": f"no such method: {method}"}})


if __name__ == "__main__":
    main()
