"""Bound the size of what one hook call makes the guard analyse.

Rules, normalisers and tokenisers (shlex builds a token by repeated string
concatenation, so one 5 MB word costs minutes) are not linear on adversarial
input.  A model that pads a command past the agent's hook timeout makes the
hook die, and most agents then run the tool: padding would turn enforcement
off.  So every oversize string is cut to a head+tail window before anything
reads it, and the oversize itself is a finding:

* a shell command over the command cap cannot be fully read in the time budget,
  and the unread middle is exactly where a padded attack hides: in enforce it
  is blocked (``payload-too-large``) with a message saying how to proceed;
* any other field (file content, a tool's output, a prompt) is scanned through
  its head and tail windows and allowed when they are clean, with a warn
  finding.  ponytail: a secret or injection only in the middle of a >256 KB
  field is not seen; a chunked pass is the upgrade if that gap matters.

Standard library only.
"""
import os
import re
from typing import Any, Dict, List

_CMD_KEYS = {"command", "cmd", "commands", "script", "code"}
_LONG_RUN = re.compile(r"\S{513,}")
# Several policy regexes restart at every `;`/`|`/`$(` and then run `\S*` to
# the end of the word, so an unbroken word of n characters costs ~n^2 per rule
# (a 20 KB `;;;;...` took 17 s). Real commands have no 512+ character words
# except a base64 blob; the sum of squares caps how much of that is analysed.
_RUN_BUDGET = 2048 * 2048
_COMMAND_WINDOW = 8192


def _pathological(text: str) -> bool:
    return sum(len(m.group()) ** 2 for m in _LONG_RUN.finditer(text)) > _RUN_BUDGET


def _cap(name: str, default: int) -> int:
    try:
        return max(int(os.environ.get(name, "") or default), 1024)
    except ValueError:
        return default


def command_cap() -> int:
    return _cap("PRISMOR_MAX_COMMAND_BYTES", 128 * 1024)


def field_cap() -> int:
    return _cap("PRISMOR_MAX_FIELD_BYTES", 256 * 1024)


def _window(text: str, cap: int) -> str:
    half = cap // 2
    return f"{text[:half]}\n[prismor: {len(text) - cap} characters elided]\n{text[-half:]}"


def bound_event(event: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Cut oversize strings in ``event`` to windows, in place.

    Returns one record per cut: ``{"path", "size", "command"}``.
    """
    cuts: List[Dict[str, Any]] = []
    shell = event.get("type") == "shell"
    ccap, fcap = command_cap(), field_cap()

    def walk(node: Any, path: str, depth: int) -> None:
        if depth > 8:
            return
        items = node.items() if isinstance(node, dict) else enumerate(node) if isinstance(node, list) else ()
        for key, val in list(items):
            here = f"{path}.{key}" if path else str(key)
            if isinstance(val, str):
                is_cmd = shell and str(key) in _CMD_KEYS
                cap = ccap if is_cmd else fcap
                if len(val) > cap or (is_cmd and _pathological(val)):
                    node[key] = _window(val, _COMMAND_WINDOW if is_cmd else cap)
                    cuts.append({"path": here, "size": len(val), "command": is_cmd})
            elif isinstance(val, (dict, list)):
                walk(val, here, depth + 1)

    walk(event, "", 0)
    return cuts


def findings_for(cuts: List[Dict[str, Any]], session_id: str, seq: int) -> List[Dict[str, Any]]:
    """The finding for the cuts: block for a command, warn for anything else."""
    out: List[Dict[str, Any]] = []
    cmd = [c for c in cuts if c["command"]]
    rest = [c for c in cuts if not c["command"]]
    if cmd:
        size = max(c["size"] for c in cmd)
        out.append({
            "id": f"{session_id}:payload-too-large:{seq}", "ruleId": "payload-too-large",
            "action": "block", "mode": "enforce", "severity": "high", "category": "payload-too-large",
            "title": (f"Shell command is {size:,} characters with an oversized unbroken word or "
                      f"more than {command_cap():,} characters, so it cannot be screened in full. "
                      "Put the bulk in a file (Write tool) and run a short command, or raise "
                      "PRISMOR_MAX_COMMAND_BYTES."),
            "evidence": f"{cmd[0]['path']}: {size} characters", "eventIndex": seq,
        })
    if rest:
        out.append({
            "id": f"{session_id}:payload-truncated:{seq}", "ruleId": "payload-truncated",
            "action": "warn", "mode": "observe", "severity": "low", "category": "payload-too-large",
            "title": "Large field screened through its first and last windows only",
            "evidence": "; ".join(f"{c['path']}: {c['size']} characters" for c in rest[:5]),
            "eventIndex": seq,
        })
    return out
