"""prismor-lite: a local tool-call judge (allow / ask / deny) next to the policy rules.

`prismor judge serve` loads a prismor-lite model once (default: its 8k ettin-32m
student) and answers on 127.0.0.1. While it runs it writes local-judge.json in the
Prismor home; the hook path reads that file and, for each pre-tool call, sends
the call plus the session history from the agent's transcript. No file, no
server, or no answer within the timeout: the call goes on with no judge finding.
The judge's deny is a block finding, its ask a step-up (the agent's own approval
prompt where it has one); both carry the server's mode
(observe unless started with --enforce), so policy semantics decide the rest.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

REPO = "prismor/prismor-lite"
REVISION = "student-ettin32m-8k"
TIMEOUT = float(os.environ.get("PRISMOR_JUDGE_TIMEOUT", "5"))
_EXCERPT = 600          # per context item, as in canon.fit
_TAIL_BYTES = 400_000   # transcript tail scanned for history


def _config_path() -> Path:
    from prismor.runtime.store import prismor_home
    return prismor_home() / "local-judge.json"


def _transcript_context(path: str) -> tuple[str, List[Dict[str, Any]]]:
    """(latest user prompt, earlier prompts + tool results) from a Claude Code transcript.

    Tool output dominates a transcript, so the last prompt can sit megabytes back:
    the tail widens until it holds one.
    """
    task, ctx = "", []
    for tail in (_TAIL_BYTES, 10 * _TAIL_BYTES, 100 * _TAIL_BYTES):
        task, ctx = _parse_tail(path, tail)
        if task:
            break
    return task, ctx


def _parse_tail(path: str, tail: int) -> tuple[str, List[Dict[str, Any]]]:
    try:
        with open(path, "rb") as fh:
            fh.seek(0, 2)
            fh.seek(max(0, fh.tell() - tail))
            lines = fh.read().decode("utf-8", errors="ignore").splitlines()
    except OSError:
        return "", []
    calls: Dict[str, Dict[str, Any]] = {}
    ctx: List[Dict[str, Any]] = []
    task = ""
    for line in lines:
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        msg = entry.get("message") or {}
        content = msg.get("content")
        if entry.get("type") == "user" and isinstance(content, str) and not entry.get("isMeta"):
            if content.startswith("<") or not content.strip():   # command/system wrappers
                continue
            if task:
                ctx.append({"type": "user_message", "source": "user", "excerpt": task[:_EXCERPT]})
            task = content
            continue
        if not isinstance(content, list):
            continue
        for block in content:
            if not isinstance(block, dict):
                continue
            if block.get("type") == "tool_use":
                calls[str(block.get("id"))] = block
            elif block.get("type") == "tool_result":
                call = calls.get(str(block.get("tool_use_id"))) or {}
                ctx.append(_result_item(call, block.get("content")))
    return task, ctx


def _result_item(call: Dict[str, Any], content: Any) -> Dict[str, Any]:
    """One tool result in the training vocabulary: file_read, shell_output, web_fetch, tool_output."""
    if isinstance(content, list):
        content = "\n".join(str(c.get("text", "")) for c in content if isinstance(c, dict))
    text = str(content or "")[:_EXCERPT]
    name, args = str(call.get("name") or "tool"), call.get("input") or {}
    if name == "Read":
        return {"type": "file_read", "source": str(args.get("file_path", "")), "excerpt": text}
    if name == "Bash":
        return {"type": "shell_output", "source": str(args.get("command", ""))[:200], "excerpt": text}
    if name in ("WebFetch", "WebSearch"):
        return {"type": "web_fetch", "source": str(args.get("url") or args.get("query") or ""), "excerpt": text}
    return {"type": "tool_output", "source": name, "excerpt": text}


def build_state(event: Dict[str, Any], agent: str) -> Optional[Dict[str, Any]]:
    """The model state for a pre-tool hook event, or None when it is not one."""
    meta = event.get("metadata") or {}
    raw = meta.get("raw") or {}
    tool = raw.get("tool_name") or meta.get("tool_name")
    if not tool or not isinstance(raw.get("tool_input"), dict):
        return None
    task, ctx = _transcript_context(str(raw.get("transcript_path") or meta.get("transcript_path") or ""))
    return {"agent": "claude-code" if agent == "claude" else agent, "user_task": task,
            "cwd": str(raw.get("cwd") or meta.get("cwd") or ""), "recent_context": ctx,
            "tool_call": {"tool": tool, "input": raw["tool_input"]}}


def judge_finding(event: Dict[str, Any], agent: str, session_id: str) -> Optional[Dict[str, Any]]:
    """Ask the local prismor-lite server about this call; a finding for ask/deny, else None."""
    if not str(event.get("agent_event") or "").lower().startswith("pre"):
        return None
    try:
        cfg = json.loads(_config_path().read_text())
    except (OSError, ValueError):
        return None   # no server running
    state = build_state(event, agent)
    if state is None:
        return None
    req = urllib.request.Request(cfg["url"] + "/judge", data=json.dumps({"state": state}).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:  # 127.0.0.1 from our own local-judge.json  # nosec B310
            v = json.load(resp)
    except Exception as exc:
        sys.stderr.write(f"[prismor] prismor-lite judge unavailable: {exc}\n")
        return None
    if v.get("verdict") not in ("ask", "deny"):
        return None
    deny = v["verdict"] == "deny"
    tool = state["tool_call"]["tool"]
    digest = hashlib.sha256(json.dumps(state["tool_call"], sort_keys=True).encode()).hexdigest()[:12]
    return {
        "id": f"{session_id}:prismor-lite:{digest}", "severity": "HIGH" if deny else "MEDIUM",
        "category": "prismor_lite_judge", "ruleId": f"prismor-lite-{v['verdict']}", "action": "block" if deny else "step_up",
        "title": f"prismor-lite: {v['verdict']} {tool} (P(deny) {v['p_deny']:.2f}, P(ask) {v['p_ask']:.2f})",
        "evidence": (f"{v['model']} on {v['state_tokens']} tokens, {len(state['recent_context'])} history "
                     f"items kept {v['kept_context']}, {v['ms']} ms"),
        "mode": cfg.get("mode", "observe"),
    }


def serve(revision: str = REVISION, port: int = 8765, enforce: bool = False, device: str = "auto",
          budget: str = "prismor-lite-8k") -> int:
    """Load the model once and answer POST /judge {state} until interrupted."""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import threading
    try:
        import laya
        import torch
        from huggingface_hub import snapshot_download
    except ImportError as exc:
        sys.stderr.write(f"prismor judge needs laya, torch and huggingface_hub ({exc.name} missing): "
                         "prismor supplychain pip install laya huggingface_hub\n")
        return 1
    path = revision if os.path.isdir(revision) else snapshot_download(REPO, revision=revision)
    sys.path.insert(0, path)
    from canon import fit   # the model's own key order + history budget
    if device == "auto":
        device = "mps" if torch.backends.mps.is_available() else "cuda" if torch.cuda.is_available() else "cpu"
    torch.backends.mha.set_fastpath_enabled(False)
    agent = laya.load(path, device=device)
    q = json.load(open(f"{path}/questions.json"))
    th = json.load(open(f"{path}/thresholds.json"))
    qs = {k: q[k] for k in ("verdict", "needs_context")}
    lock = threading.Lock()   # ponytail: one judgment at a time; a batch queue if calls overlap often

    def judge(state: Dict[str, Any]) -> Dict[str, Any]:
        t0 = time.perf_counter()
        s = fit(state, budget)
        with lock:
            out = agent.predict(s, qs)
        p = out["answers"]["verdict"]["probabilities"]
        nc = float(out["answers"]["needs_context"]["noul"])
        verdict = ("deny" if p["deny"] >= th["deny"] else
                   "ask" if p["deny"] + p["ask"] >= th["ask"] or nc >= th["needs_context"] else "allow")
        return {"verdict": verdict, "p_deny": p["deny"], "p_ask": p["ask"], "needs_context": nc,
                "model": f"{REPO}@{revision}" if not os.path.isdir(revision) else revision,
                "state_tokens": out["usage"]["state_tokens"], "truncated": out["usage"]["truncated"],
                "kept_context": len(s.get("recent_context") or []), "ms": int((time.perf_counter() - t0) * 1000)}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            try:
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
                res, code = judge(body["state"]), 200
                call = body["state"]["tool_call"]
                what = " ".join(json.dumps(call["input"], ensure_ascii=False).split())[:90]
                sys.stderr.write(f"prismor-lite {res['verdict']:5s} deny {res['p_deny']:.2f} ask {res['p_ask']:.2f} "
                                 f"{res['state_tokens']:5d} tok {res['ms']:5d} ms  {call['tool']} {what}\n")
            except Exception as exc:
                res, code = {"error": repr(exc)}, 400
            data = json.dumps(res).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *_):
            pass

    import signal
    signal.signal(signal.SIGTERM, signal.default_int_handler)   # `kill` unhooks too, not just Ctrl-C
    try:
        server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    except OSError as exc:
        sys.stderr.write(f"judge: port {port} is taken ({exc.strerror}). Another `prismor judge serve`? "
                         f"Stop it (see pid in {_config_path()}) or pass --port.\n")
        return 1
    cfg = _config_path()
    cfg.write_text(json.dumps({"url": f"http://127.0.0.1:{port}", "mode": "enforce" if enforce else "observe",
                               "model": revision, "pid": os.getpid()}))
    print(f"prismor-lite: {revision} on {device}, http://127.0.0.1:{port}, mode "
          f"{'enforce' if enforce else 'observe'}; Ctrl-C stops and unhooks it", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        cfg.unlink(missing_ok=True)
    return 0


if __name__ == "__main__":   # self-check: transcript -> state mapping
    import tempfile
    rows = [{"type": "user", "message": {"content": "fix the build"}},
            {"type": "assistant", "message": {"content": [{"type": "tool_use", "id": "a", "name": "Read",
                                                            "input": {"file_path": "/r/x.py"}}]}},
            {"type": "user", "message": {"content": [{"type": "tool_result", "tool_use_id": "a", "content": "print(1)"}]}},
            {"type": "user", "message": {"content": "now push it"}}]
    with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
        f.write("\n".join(json.dumps(r) for r in rows))
    ev = {"agent_event": "PreToolUse", "metadata": {"raw": {"tool_name": "Bash", "cwd": "/r", "transcript_path": f.name,
                                                             "tool_input": {"command": "git push"}}}}
    st = build_state(ev, "claude")
    assert st["user_task"] == "now push it", st
    assert st["recent_context"] == [{"type": "file_read", "source": "/r/x.py", "excerpt": "print(1)"},
                                    {"type": "user_message", "source": "user", "excerpt": "fix the build"}], st
    assert st["tool_call"] == {"tool": "Bash", "input": {"command": "git push"}}
    print("ok")
