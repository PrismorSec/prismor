"""What a hook does when it crashes before it can decide.

Standard library only, and no ``prismor`` imports: the generated launcher
(``hook-dispatch.py``) loads this file by path when the rest of the package
cannot be imported, so it has to work with a broken or half-upgraded install.

Exit-code hosts read any nonzero exit other than 2 as "hook errored" and run the
tool, and JSON-on-stdout hosts allow when nothing is printed, so an uncaught
exception would otherwise open every call.
"""
import io
import json
import os
import sys
from typing import List, Optional

# Tools that only look. A crashed enforce hook still lets these run so the
# person can see what broke; everything else is denied.
READ_ONLY_TOOLS = {"Read", "Grep", "Glob", "LS", "view", "read", "read_file", "grep", "glob", "list_dir"}

# Hosts that read a JSON deny on stdout (exit 0) instead of exit code 2.
_JSON_DENY_EXIT0 = ("copilot", "qwen", "antigravity")


def handle_crash(rest: List[str], crash: BaseException, data: Optional[str] = None) -> None:
    """Turn a crash into a deny when the hook enforces. Always raises SystemExit.

    ``rest`` is the argv after ``hook-dispatch`` (``--agent X --mode Y``); ``data``
    is the hook payload when the caller already read stdin, else it is read here.
    """
    if data is None:
        try:
            data = sys.stdin.read()
        except Exception:
            data = ""
    try:
        payload = json.loads(data or "{}")
    except ValueError:
        payload = {}
    if not isinstance(payload, dict):
        payload = {}
    agent = rest[rest.index("--agent") + 1] if "--agent" in rest[:-1] else ""
    mode = rest[rest.index("--mode") + 1] if "--mode" in rest[:-1] else "observe"
    event = str(payload.get("hook_event_name") or payload.get("hookEventName")
                or payload.get("event") or "").lower()
    tool = str(payload.get("tool_name") or payload.get("toolName") or "")
    msg = f"Prismor hook failed ({type(crash).__name__}: {crash}); "
    if (mode != "enforce" or tool in READ_ONLY_TOOLS
            or any(k in event for k in ("stop", "prompt", "session", "post", "after", "notification"))):
        # Observe, a read, or not a pre-tool event: denying here would swallow
        # a prompt or loop a Stop hook ("keep going") forever.
        sys.stderr.write(msg + "this call was not screened.\n")
        raise SystemExit(1)
    reason = msg + "blocked because this hook enforces and could not decide. Reinstall or upgrade prismor to fix it."
    sys.stderr.write(reason + "\n")
    codex_windows = agent == "codex" and os.name == "nt"
    if agent == "copilot":
        sys.stdout.write(json.dumps({"permissionDecision": "deny", "permissionDecisionReason": reason}) + "\n")
    elif agent == "qwen" or codex_windows:
        # Codex on Windows reports exit 2 as 1 through powershell; the JSON
        # deny with exit 0 is what it honors there.
        sys.stdout.write(json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse", "permissionDecision": "deny",
            "permissionDecisionReason": reason}}) + "\n")
    elif agent in ("antigravity", "grok"):
        sys.stdout.write(json.dumps({"decision": "deny", "reason": reason}) + "\n")
    elif agent == "cursor":
        sys.stdout.write(reason + "\n")
    raise SystemExit(0 if agent in _JSON_DENY_EXIT0 or codex_windows else 2)
