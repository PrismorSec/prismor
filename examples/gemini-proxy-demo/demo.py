#!/usr/bin/env python3
"""Show `prismor proxy` governing Google Gen AI traffic, end to end, offline.

Runs three things in one process:

  1. a stub Gemini upstream on :7099 that answers in the real wire format
     (``candidates[].content.parts[].functionCall``, and SSE frames for
     ``:streamGenerateContent``),
  2. ``prismor proxy`` on :7080 in enforce mode, pointed at that stub,
  3. a client that talks to the proxy exactly as the Google Gen AI SDK would.

No API key, no network, no google-genai install — so it is reproducible in CI
and on a plane. The point being demonstrated is not that Gemini works; it is
that a tool call the *model proposed* is judged by the same rule that would
stop the same command at a Bash hook, and that a denied call never reaches the
client in complete form.

    python examples/gemini-proxy-demo/demo.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

UPSTREAM_PORT = 7099
PROXY_PORT = 7080
MODEL = "gemini-2.5-pro"

BENIGN = "list the files in this directory"
DESTRUCTIVE = "wipe the machine"


def _call(command: str) -> dict:
    """A Gemini response whose model proposed one shell command."""
    return {"candidates": [{"index": 0, "finishReason": "STOP",
                            "content": {"role": "model", "parts": [
                                {"functionCall": {"name": "Bash",
                                                  "args": {"command": command}}}]}}],
            "usageMetadata": {"promptTokenCount": 18, "candidatesTokenCount": 9,
                              "totalTokenCount": 27}}


class StubGemini(BaseHTTPRequestHandler):
    """Stands in for generativelanguage.googleapis.com."""

    def log_message(self, *a):  # quiet
        pass

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        prompt = json.dumps(json.loads(raw or b"{}").get("contents", []))
        command = "rm -rf / --no-preserve-root" if "wipe" in prompt else "ls -la"
        body = _call(command)

        if ":streamGenerateContent" in self.path:
            payload = f"data: {json.dumps(body)}\n\n".encode()
            ctype = "text/event-stream"
        else:
            payload = json.dumps(body).encode()
            ctype = "application/json"

        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def ask(prompt: str, *, stream: bool) -> str:
    """POST to the proxy the way the Gen AI SDK would, return the raw body."""
    method = ":streamGenerateContent?alt=sse" if stream else ":generateContent"
    url = f"http://127.0.0.1:{PROXY_PORT}/v1beta/models/{MODEL}{method}"
    payload = json.dumps({
        "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        "tools": [{"functionDeclarations": [{
            "name": "Bash", "description": "Run a shell command",
            "parameters": {"type": "object",
                           "properties": {"command": {"type": "string"}}}}]}],
    }).encode()
    req = urllib.request.Request(url, data=payload, headers={
        "Content-Type": "application/json", "x-goog-api-key": "stub-key"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.read().decode()


def show(label: str, prompt: str, body: str) -> None:
    print(f"\n\033[1m{label}\033[0m")
    print(f"  prompt        {prompt!r}")
    parts = _parts(body)
    for part in parts:
        if "functionCall" in part:
            call = part["functionCall"]
            print(f"  \033[31mfunctionCall\033[0m  {call['name']}("
                  f"{json.dumps(call.get('args', {}))})")
        elif "text" in part:
            print(f"  \033[32mtext\033[0m          {part['text']}")
    if not parts:
        print(f"  raw           {body[:200]}")


def _parts(body: str) -> list:
    blob = body.split("data: ", 1)[1] if body.startswith("data: ") else body
    try:
        parsed = json.loads(blob)
    except Exception:
        return []
    out = []
    for candidate in parsed.get("candidates") or []:
        out.extend((candidate.get("content") or {}).get("parts") or [])
    return out


def main() -> int:
    home = Path(tempfile.mkdtemp(prefix="prismor-demo-"))
    workspace = home / "workspace"
    workspace.mkdir()
    os.environ["PRISMOR_HOME"] = str(home)

    (home / "proxy.json").write_text(json.dumps({
        "default_upstream": "google",
        "upstreams": {"google": {"base_url": f"http://127.0.0.1:{UPSTREAM_PORT}"}},
    }))

    upstream = HTTPServer(("127.0.0.1", UPSTREAM_PORT), StubGemini)
    threading.Thread(target=upstream.serve_forever, daemon=True).start()

    from prismor.runtime.proxy import run_proxy
    threading.Thread(target=run_proxy, kwargs=dict(
        host="127.0.0.1", port=PROXY_PORT, workspace=workspace, mode="enforce",
        config_path=home / "proxy.json", session_id="gemini-demo",
    ), daemon=True).start()
    time.sleep(1.5)

    print("\n\033[1m── prismor proxy · Google Gen AI ──────────────────────────"
          "──────────────\033[0m")
    print("  upstream   stub Gemini on 127.0.0.1:7099 (real wire format)")
    print("  policy     default rules, enforce mode")

    show("1. benign call — released verbatim", BENIGN, ask(BENIGN, stream=False))
    show("2. destructive call — replaced before the client sees it",
         DESTRUCTIVE, ask(DESTRUCTIVE, stream=False))
    show("3. same, streaming — held, judged, replaced mid-stream",
         DESTRUCTIVE, ask(DESTRUCTIVE, stream=True))

    print("\n  The model proposed `rm -rf /` three times. The client never "
          "received it once.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
