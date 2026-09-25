"""Dogfood launcher: run hook-dispatch from THIS working tree, not the installed release.

The committed agent configs (.claude/settings.json, .codex/hooks.json,
.cursor/hooks.json, .github/hooks/prismor.json) point here, via a sh guard on
POSIX and scripts/dev-hook.cmd on Windows. Their shapes are pinned by
tests/test_dogfood_configs.py.
"""
import io
import json
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.environ["PRISMOR_HOOK_T0"] = str(time.time())

# Tools the agent needs to look at and repair a broken tree. Blocking them too
# would leave it unable to fix the very import error that is blocking it.
_REPAIR_TOOLS = {
    "Read", "Grep", "Glob", "Edit", "Write", "MultiEdit", "NotebookEdit",  # Claude
    "apply_patch",                                                        # Codex
    "view", "edit", "create", "read", "write",                            # Copilot et al.
}


def _fail(exc, payload, agent):
    event = str(payload.get("hook_event_name") or payload.get("hookEventName") or "")
    msg = (
        f"prismor dogfood hook: the working tree at {ROOT} is broken ({exc!r}), so this "
        "session is not being screened by it. Fix it, or relaunch with PRISMOR_DOGFOOD=0."
    )
    print(msg, file=sys.stderr)
    low = event.lower()
    if "stop" in low or payload.get("stop_hook_active"):
        return 1  # exit 2 on a Stop-class event means "keep going": an endless loop
    if "prompt" in low or "session" in low:
        if agent == "claude":
            print(msg)  # Claude adds this stdout to the model's context
        return 0  # never swallow the user's prompt
    if payload.get("tool_name") in _REPAIR_TOOLS or "file" in low:
        return 0
    return 2


def run():
    agent = sys.argv[sys.argv.index("--agent") + 1] if "--agent" in sys.argv[:-1] else ""
    data = sys.stdin.read()
    try:
        payload = json.loads(data or "{}")
    except ValueError:
        payload = {}
    if not isinstance(payload, dict):
        payload = {}
    event = str(payload.get("hook_event_name") or "")
    # Cursor also runs .claude/settings.json hooks, sending camelCase Cursor
    # payloads (preToolUse, Shell) that the claude normalizer misreads.
    if agent == "claude" and event[:1].islower():
        return 0
    sys.stdin = io.StringIO(data)
    sys.path.insert(0, ROOT)
    try:
        from prismor.runtime.immunity_cli import main
        return main()
    except Exception as exc:  # SystemExit (the normal exit path) is not an Exception
        return _fail(exc, payload, agent)


if __name__ == "__main__":
    sys.exit(run())
