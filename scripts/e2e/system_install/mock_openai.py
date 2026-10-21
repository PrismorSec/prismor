"""Minimal OpenAI Responses API stand-in for Codex: the first turn gets a
shell tool call running $MOCK_CMD; once a tool output comes back, "done"."""
import json, os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CMD = os.environ.get("MOCK_CMD", "rm -rf /home/dev/canary")
LOG = open(os.environ.get("MOCK_LOG", "mock-openai.log"), "a", buffering=1)

def sse(data):
    return f"event: {data['type']}\ndata: {json.dumps(data)}\n\n".encode()

def call_for(tools):
    names = [t.get("name") or (t.get("function") or {}).get("name") for t in tools]
    for name, args in (("exec_command", {"cmd": CMD}), ("shell_command", {"command": CMD}),
                       ("shell", {"command": ["bash", "-lc", CMD] if os.name != "nt" else ["powershell.exe", "-NoProfile", "-Command", CMD]})):
        if name in names:
            return name, args
    return None, None

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        self.send_response(200); self.send_header("content-type", "application/json"); self.end_headers()
        self.wfile.write(json.dumps({"data": [{"id": "mock", "object": "model"}], "models": []}).encode())
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("content-length", 0))) or b"{}")
        items = body.get("input") or []
        outputs = [i for i in items if isinstance(i, dict) and i.get("type", "").endswith("call_output")]
        for o in outputs:
            LOG.write("TOOL_OUTPUT " + json.dumps(o.get("output"))[:900] + "\n")
        name, args = call_for(body.get("tools") or [])
        LOG.write(f"POST {self.path} tools={[t.get('name') for t in body.get('tools') or []]} pick={name}\n")
        self.send_response(200); self.send_header("content-type", "text/event-stream"); self.end_headers()
        w = self.wfile.write
        w(sse({"type": "response.created", "response": {"id": "resp_1"}}))
        if name and not outputs:
            item = {"type": "function_call", "id": "fc_1", "call_id": "call_1", "name": name, "arguments": json.dumps(args)}
        else:
            item = {"type": "message", "id": "msg_1", "role": "assistant", "content": [{"type": "output_text", "text": "done"}]}
        w(sse({"type": "response.output_item.added", "output_index": 0, "item": item}))
        w(sse({"type": "response.output_item.done", "output_index": 0, "item": item}))
        w(sse({"type": "response.completed", "response": {"id": "resp_1", "usage": {"input_tokens": 10, "output_tokens": 5, "total_tokens": 15, "input_tokens_details": {"cached_tokens": 0}, "output_tokens_details": {"reasoning_tokens": 0}}}}))

ThreadingHTTPServer(("127.0.0.1", 8788), H).serve_forever()
