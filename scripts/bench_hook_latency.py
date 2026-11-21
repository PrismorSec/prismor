"""Benchmark hook dispatch end to end, as an agent spawns it.

    python3 scripts/bench_hook_latency.py [-n 30] [--hookd] [--base /path/to/other/checkout]

Each call runs the generated dispatch shim (``python3 hook-dispatch.py
hook-dispatch --agent claude ...``, what ``prismor setup`` installs) against a
throwaway PRISMOR_HOME and workspace; nothing touches your real store. Every
call gets its own tool_use_id (a repeated one hits the dedupe and skips
recording) and all calls of one payload share a session, so history grows the
way it does live. Configurations are interleaved call by call so machine load
hits them equally.

Configurations: this checkout in-process; with ``--hookd`` also this checkout
through the opt-in warm server (PRISMOR_HOOKD=1, prismor/runtime/hookd.py);
with ``--base`` another checkout (say ``git worktree add --detach /tmp/base
origin/main``) in-process. Prints p50/p95 wall ms per payload and
configuration, the interpreter floor, and the p50 of each recorded stage
(hook_timings.detail_json, see prismor/runtime/perf.py).
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

PAYLOADS = {
    "pre-bash": ("PreToolUse", "Bash", {"command": "git status && ls -la"}),
    "pre-read": ("PreToolUse", "Read", {"file_path": "README.md"}),
    "pre-webfetch": ("PreToolUse", "WebFetch", {"url": "https://example.com/docs", "prompt": "summarise"}),
    "post-bash": ("PostToolUse", "Bash", {"command": "git status"}),
}


def _q(values, p):
    s = sorted(values)
    return s[min(len(s) - 1, max(0, int(round(p * len(s))) - 1))] if s else 0.0


def _run(cmd, env, stdin=""):
    t0 = time.perf_counter()
    subprocess.run(cmd, input=stdin, capture_output=True, text=True, env=env, check=False)
    return (time.perf_counter() - t0) * 1000


class Config:
    def __init__(self, name, root, hookd, py):
        self.name, self.root = name, root
        self.home = Path(tempfile.mkdtemp(prefix="pb-h-"))  # short: unix socket paths cap at 104
        self.ws = Path(tempfile.mkdtemp(prefix="pb-w-"))
        env = {k: v for k, v in os.environ.items() if not k.startswith("PRISMOR_")}
        env.pop("PYTHONDONTWRITEBYTECODE", None)  # a real install has .pyc files
        env.update(PRISMOR_HOME=str(self.home), PRISMOR_SECRETS_DIR=str(self.home / "secrets"),
                   PRISMOR_WORKSPACE=str(self.ws), HOME=str(self.home))
        env.pop("PYTHONPATH", None)
        if hookd:
            env["PRISMOR_HOOKD"] = "1"
        self.env = env
        shim = self.home / "hook-dispatch.py"
        subprocess.run([py, "-c", "import sys; sys.path.insert(0, sys.argv[1]); from prismor.runtime import hooks;"
                        "open(sys.argv[2], 'w', encoding='utf-8').write(hooks._SHIM_TEMPLATE.format(repo_root=sys.argv[1]))",
                        str(root), str(shim)], check=True, env=env)
        self.cmd = [py, str(shim), "hook-dispatch", "--agent", "claude", "--workspace", str(self.ws), "--mode", "enforce"]
        self.walls = {k: [] for k in PAYLOADS}

    def call(self, name, i):
        event, tool, tool_input = PAYLOADS[name]
        payload = {"hook_event_name": event, "session_id": f"bench-{name}", "cwd": str(self.ws),
                   "tool_name": tool, "tool_input": tool_input, "tool_use_id": f"{name}-{i}-{time.time_ns()}"}
        if event == "PostToolUse":
            payload["tool_response"] = {"stdout": "On branch main\nnothing to commit", "stderr": ""}
        return _run(self.cmd, self.env, json.dumps(payload))

    def stages(self, name):
        found = list(self.home.rglob("prismor.db"))
        out: dict = {}
        for path in found:
            try:
                rows = sqlite3.connect(path).execute(
                    "SELECT detail_json FROM hook_timings WHERE session_id=?", (f"bench-{name}",)).fetchall()
            except sqlite3.Error:
                continue
            for (raw,) in rows:
                for k, v in (json.loads(raw or "{}").get("stages") or {}).items():
                    out.setdefault(k, []).append(v)
        return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("-n", type=int, default=30)
    ap.add_argument("--hookd", action="store_true", help="also measure the opt-in warm server")
    ap.add_argument("--base", help="another checkout to compare against (in-process)")
    ap.add_argument("--stages", action="store_true", help="print the per-stage breakdown")
    ap.add_argument("--python", default=sys.executable)
    args = ap.parse_args()
    py = args.python

    configs = []
    if args.base:
        configs.append(Config("base", Path(args.base).resolve(), False, py))
    configs.append(Config("this", ROOT, False, py))
    if args.hookd:
        configs.append(Config("this+hookd", ROOT, True, py))

    env = configs[-1].env
    print(f"python {py}  n={args.n}")
    for label, cmd in (("python -S -c pass", [py, "-S", "-c", "pass"]),
                       ("python -I -c pass", [py, "-I", "-c", "pass"]),
                       ("python -c pass", [py, "-c", "pass"])):
        v = [_run(cmd, env) for _ in range(args.n)]
        print(f"  {label:22s} p50={_q(v, .5):6.1f}  p95={_q(v, .95):6.1f} ms")

    warm = json.dumps({"hook_event_name": "SessionStart", "session_id": "warm"})
    for c in configs:  # db creation, .pyc compile, server spawn
        for _ in range(3):
            _run(c.cmd, c.env, warm)
            time.sleep(0.5)
    if args.hookd:
        time.sleep(3)  # the server profiles and preloads before it listens

    for name in PAYLOADS:
        for i in range(args.n):
            for c in configs:
                c.walls[name].append(c.call(name, i))
    print(f"\n{'payload':14s}" + "".join(f"{c.name:>24s}" for c in configs) + "   (p50 / p95 wall ms)")
    for name in PAYLOADS:
        print(f"{name:14s}" + "".join(f"{_q(c.walls[name], .5):>13.1f} / {_q(c.walls[name], .95):6.1f}"
                                      for c in configs))
    if args.stages:
        for c in configs:
            print(f"\nstages, {c.name} (p50 ms):")
            for name in PAYLOADS:
                st = c.stages(name)
                top = sorted(st.items(), key=lambda kv: -_q(kv[1], .5))[:8]
                print(f"  {name:14s} " + "  ".join(f"{k}={_q(v, .5):.1f}" for k, v in top))
    for c in configs:  # a warm server exits within a second of its socket going
        shutil.rmtree(c.home, ignore_errors=True)
        shutil.rmtree(c.ws, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
