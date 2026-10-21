"""Minimal Anthropic Messages API stand-in: the first request that offers a
Bash tool gets a tool_use for $MOCK_CMD; everything else gets a short text."""
import json, os, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CMD = os.environ.get("MOCK_CMD", "rm -rf /home/dev/canary")
LOG = open(os.environ.get("MOCK_LOG", "mock.log"), "a", buffering=1)

def sse(ev, data):
    return f"event: {ev}\ndata: {json.dumps(data)}\n\n".encode()

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        self.send_response(200); self.send_header("content-type", "application/json"); self.end_headers(); self.wfile.write(b"{}")
    do_HEAD = do_GET
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("content-length", 0))) or b"{}")
        if "count_tokens" in self.path:
            out = json.dumps({"input_tokens": 10}).encode()
            self.send_response(200); self.send_header("content-type", "application/json"); self.end_headers(); self.wfile.write(out); return
        tools = {t.get("name") for t in body.get("tools", []) or []}
        msgs = body.get("messages", [])
        last = msgs[-1]["content"] if msgs else ""
        has_result = isinstance(last, list) and any(b.get("type") == "tool_result" for b in last)
        if has_result:
            for b in last:
                if b.get("type") == "tool_result":
                    LOG.write("TOOL_RESULT " + json.dumps(b) + "\n")
        want_tool = "Bash" in tools and not has_result
        LOG.write(f"POST {self.path} tools={len(tools)} tool_use={want_tool}\n")
        self.send_response(200); self.send_header("content-type", "text/event-stream"); self.end_headers()
        w = self.wfile.write
        w(sse("message_start", {"type": "message_start", "message": {"id": "msg_1", "type": "message", "role": "assistant", "model": body.get("model", "m"), "content": [], "stop_reason": None, "stop_sequence": None, "usage": {"input_tokens": 10, "output_tokens": 1}}}))
        if want_tool:
            w(sse("content_block_start", {"type": "content_block_start", "index": 0, "content_block": {"type": "tool_use", "id": "toolu_mock1", "name": "Bash", "input": {}}}))
            w(sse("content_block_delta", {"type": "content_block_delta", "index": 0, "delta": {"type": "input_json_delta", "partial_json": json.dumps({"command": CMD, "description": "cleanup"})}}))
            stop = "tool_use"
        else:
            w(sse("content_block_start", {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}))
            w(sse("content_block_delta", {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "done"}}))
            stop = "end_turn"
        w(sse("content_block_stop", {"type": "content_block_stop", "index": 0}))
        w(sse("message_delta", {"type": "message_delta", "delta": {"stop_reason": stop, "stop_sequence": None}, "usage": {"output_tokens": 5}}))
        w(sse("message_stop", {"type": "message_stop"}))

ThreadingHTTPServer(("127.0.0.1", 8787), H).serve_forever()
