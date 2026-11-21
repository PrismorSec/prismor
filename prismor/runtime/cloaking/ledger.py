"""Cloak event ledger: turns the bash hooks' catches into telemetry findings.

The cloak hooks (hooks/*.sh) cannot reach the telemetry pipeline, so each one
appends a JSON line to ``$PRISMOR_HOME/cloak_events.jsonl`` (hooks/_ledger.sh).
The Python hook drains that file on its next evaluated call and ships every
line as a finding through the normal sink path, so the console can count how
often a secret was caught, redacted, blocked or used, per agent and session.

A line carries labels only: the vault NAME (``auto_<hash>`` or the name the
user registered), the static pattern that matched, the source and the action.
The secret value is never written to the ledger.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List

# What the hook saw -> (ruleId, category, title). The hook knows where the
# secret was; the console groups on ruleId and category.
_SOURCES = {
    "prompt": ("cloak-prompt", "secret_exfiltration", "Secret in prompt cloaked"),
    "prompt_file": ("cloak-prompt-file", "secret_exfiltration", "Prompt @-mention of a file holding a secret blocked"),
    "tool_input": ("cloak-tool-input", "secret_exfiltration", "Raw secret in tool call cloaked"),
    "read": ("cloak-read", "secret_access", "Read of a file holding a secret blocked"),
    "mcp_output": ("cloak-mcp-output", "secret_access", "MCP tool output scrubbed of a secret"),
    "output": ("cloak-output", "secret_access", "Command output scrubbed of a secret"),
    "command": ("cloak-command", "secret_access", "Placeholder resolved to its secret at execution"),
}
# Titles read "<thing> ... a secret", never "Secret <word>": the SIEM sink's
# scrubber takes the word after "secret" for a value and masks it.
_ACTIONS = {"redacted", "blocked", "used"}
_MAX_LINES = 500


def ledger_path() -> Path:
    override = os.environ.get("PRISMOR_CLOAK_LEDGER")
    if override:
        return Path(override)
    home = os.environ.get("PRISMOR_HOME") or str(Path.home() / ".prismor")
    return Path(home) / "cloak_events.jsonl"


def drain() -> List[Dict[str, Any]]:
    """Take every pending ledger line. The file is renamed first, so a hook
    appending at the same moment writes to a fresh file instead of racing the
    read. Malformed lines are dropped."""
    path = ledger_path()
    try:
        if not path.exists() or path.stat().st_size == 0:
            return []
        taken = path.with_name(f"{path.name}.{os.getpid()}.draining")
        os.replace(path, taken)
    except OSError:
        return []
    records: List[Dict[str, Any]] = []
    try:
        with open(taken, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if len(records) >= _MAX_LINES:
                    break
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                if isinstance(rec, dict) and rec.get("source") in _SOURCES and rec.get("action") in _ACTIONS:
                    records.append(rec)
    except OSError:
        pass
    finally:
        try:
            taken.unlink()
        except OSError:
            pass
    return records


def to_finding(rec: Dict[str, Any]) -> Dict[str, Any]:
    """One ledger line as a finding. A redaction or a block already happened
    on the device, so the finding reports what was done (mode=enforce for a
    block); it is never re-evaluated."""
    rule_id, category, title = _SOURCES[rec["source"]]
    action = rec["action"]
    name = str(rec.get("name") or "")[:128]
    finding: Dict[str, Any] = {
        "ruleId": rule_id,
        "category": category,
        "severity": "info" if action == "used" else "HIGH",
        "title": title,
        "action": "block" if action == "blocked" else ("allow" if action == "used" else "modify"),
        "dataClasses": ["secret"],
        "redactionApplied": action == "redacted",
        "cloakAction": action,
    }
    # No mode on a use: telemetry then reads action=allow as "allowed".
    if action != "used":
        finding["mode"] = "enforce" if action == "blocked" else "observe"
    if name:
        finding["secretName"] = name
    if rec.get("pattern"):
        finding["pattern"] = str(rec["pattern"])[:200]
    if rec.get("tool"):
        finding["toolName"] = str(rec["tool"])[:100]
    return finding
