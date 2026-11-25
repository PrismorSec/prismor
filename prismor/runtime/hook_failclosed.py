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
            raw = getattr(sys.stdin, "buffer", None)
            data = raw.read().decode("utf-8-sig", errors="replace") if raw else sys.stdin.read()
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
    fix = ("Shorten the command or payload, or raise PRISMOR_HOOK_BUDGET_MS."
           if isinstance(crash, TimeoutError) else "Reinstall or upgrade prismor to fix it.")
    reason = msg + "blocked because this hook enforces and could not decide. " + fix
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


def hook_budget_ms() -> int:
    """Wall-clock budget for one hook call (``PRISMOR_HOOK_BUDGET_MS``, default 8000; 0 = off)."""
    try:
        return max(int(os.environ.get("PRISMOR_HOOK_BUDGET_MS", "") or 8000), 0)
    except ValueError:
        return 8000


def arm_watchdog(rest: List[str], data: Optional[str]):
    """Make the hook answer inside its budget; returns a ``disarm()`` callable.

    A hook that outlives the agent's own timeout is killed, and most agents then
    run the tool, so a payload that makes the guard slow would switch it off.
    On expiry the hook gives the same answer as a crash: deny when it enforces a
    pre-tool call, not-screened (exit 1) otherwise.

    POSIX uses SIGALRM (it also interrupts a long regex, which a thread cannot:
    ``re`` holds the GIL). Elsewhere a daemon timer thread fires, which covers
    Python-level loops only; a regex stuck in C on Windows is bounded by
    ``payload_bounds`` instead.
    """
    ms = hook_budget_ms()
    if not ms:
        return lambda: None
    state = {"live": True}

    def expire(*_args) -> None:
        if not state["live"]:
            return
        state["live"] = False
        code: object = 1
        try:
            handle_crash(rest, TimeoutError(f"hook exceeded its {ms} ms time budget"), data or "")
        except SystemExit as exc:
            code = exc.code
        except BaseException:
            pass
        for stream in (sys.stdout, sys.stderr):
            try:
                stream.flush()
            except Exception:
                pass
        os._exit(code if isinstance(code, int) else 1)

    try:
        import signal
        signal.signal(signal.SIGALRM, expire)
        signal.setitimer(signal.ITIMER_REAL, ms / 1000.0)

        def disarm() -> None:
            state["live"] = False
            signal.setitimer(signal.ITIMER_REAL, 0)
        return disarm
    except (ImportError, AttributeError, ValueError, OSError):
        pass  # no SIGALRM (Windows) or not the main thread
    import threading
    timer = threading.Timer(ms / 1000.0, expire)
    timer.daemon = True
    timer.start()

    def disarm_thread() -> None:
        state["live"] = False
        timer.cancel()
    return disarm_thread
