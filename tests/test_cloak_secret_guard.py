"""Tests for the cloaking detect-and-block secret guard.

Covers two layers:

  A. patterns.py        — built-in + custom pattern management
  B. secret-guard.sh    — PreToolUse detect + vault + deny hook (end-to-end)

Each test runs against an isolated $PRISMOR_HOME so the developer's real vault
is never touched. Run:  python3 tests/test_cloak_secret_guard.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

# Allow running as a plain script from the repo root.
_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO))

# Isolate the vault / pattern file before importing the module under test.
_HOME = Path(tempfile.mkdtemp(prefix="prismor-test-"))
os.environ["PRISMOR_HOME"] = str(_HOME)
os.environ["PRISMOR_SECRETS_DIR"] = str(_HOME / "secrets")
os.environ["PRISMOR_CLOAK_PATTERNS"] = str(_HOME / "cloak_patterns.txt")

from prismor.runtime.cloaking import patterns  # noqa: E402

_GUARD = _REPO / "prismor" / "runtime" / "cloaking" / "hooks" / "secret-guard.sh"

_passed = 0
_failed = 0


def check(name: str, ok: bool, detail: str = "") -> None:
    global _passed, _failed
    if ok:
        _passed += 1
        print(f"  PASS  {name}")
    else:
        _failed += 1
        print(f"  FAIL  {name}  {detail}")


def run_guard(payload: dict) -> dict | None:
    """Invoke secret-guard.sh with a tool payload; return parsed JSON or None."""
    proc = subprocess.run(
        ["bash", str(_GUARD)],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        env=os.environ,
    )
    out = proc.stdout.strip()
    return json.loads(out) if out else None


# ── A. patterns.py ───────────────────────────────────────────────────────────
print("\n[A] pattern management")

builtins = patterns.builtin_patterns()
check("ships >= 14 built-in patterns", len(builtins) >= 14, len(builtins))
check("AKIA built-in present", "AKIA[0-9A-Z]{16}" in builtins)
check("custom list starts empty", patterns.list_custom_patterns() == [])

added = patterns.add_pattern("mycorp_[0-9a-f]{32}")
check("add_pattern returns True for new pattern", added is True)
check("custom pattern now listed", "mycorp_[0-9a-f]{32}" in patterns.list_custom_patterns())
check("all_patterns includes built-in + custom",
      "mycorp_[0-9a-f]{32}" in patterns.all_patterns() and "AKIA[0-9A-Z]{16}" in patterns.all_patterns())

dup = patterns.add_pattern("mycorp_[0-9a-f]{32}")
check("adding a duplicate returns False", dup is False)
check("duplicate not written twice",
      patterns.list_custom_patterns().count("mycorp_[0-9a-f]{32}") == 1)

try:
    patterns.add_pattern("bad([regex")
    check("invalid regex raises ValueError", False, "no exception")
except ValueError:
    check("invalid regex raises ValueError", True)

try:
    patterns.remove_pattern("AKIA[0-9A-Z]{16}")
    check("removing a built-in raises ValueError", False, "no exception")
except ValueError:
    check("removing a built-in raises ValueError", True)

removed = patterns.remove_pattern("mycorp_[0-9a-f]{32}")
check("remove_pattern returns True", removed is True)
check("custom list empty after removal", patterns.list_custom_patterns() == [])
check("removing a missing pattern returns False",
      patterns.remove_pattern("nope_[0-9]{9}") is False)

# Org-pushed patterns: projected from the signed policy, read-only on device.
n = patterns.write_org_patterns(["orgco_[A-Z0-9]{20}", "bad([regex", "orgco_[A-Z0-9]{20}", ""])
check("write_org_patterns keeps only valid, distinct regexes", n == 1, n)
check("org pattern listed", patterns.list_org_patterns() == ["orgco_[A-Z0-9]{20}"])
check("all_patterns includes the org pattern", "orgco_[A-Z0-9]{20}" in patterns.all_patterns())
check("add_pattern treats an org pattern as already present",
      patterns.add_pattern("orgco_[A-Z0-9]{20}") is False)
try:
    patterns.remove_pattern("orgco_[A-Z0-9]{20}")
    check("removing an org pattern raises ValueError", False, "no exception")
except ValueError:
    check("removing an org pattern raises ValueError", True)
patterns.write_org_patterns([])
check("empty org list removes the file",
      not patterns.org_patterns_file().exists() and patterns.list_org_patterns() == [])


# ── B. secret-guard.sh end-to-end ────────────────────────────────────────────
print("\n[B] secret-guard hook")

# 1. Raw secret in a Bash command → deny + vault.
res = run_guard({"tool_name": "Bash",
                 "tool_input": {"command": "deploy --key sk_live_abcd1234efgh5678ijkl"}})
decision = (res or {}).get("hookSpecificOutput", {}).get("permissionDecision")
check("raw secret in Bash is denied", decision == "deny", res)
reason = (res or {}).get("hookSpecificOutput", {}).get("permissionDecisionReason", "")
check("deny reason references a placeholder, never the raw value",
      "@@SECRET:auto_" in reason and "sk_live_abcd1234efgh5678ijkl" not in reason)
vaulted = list((_HOME / "secrets").glob("auto_*"))
check("secret was written to the vault", len(vaulted) == 1, vaulted)

# 2. Same secret again (now vaulted) → allowed (no-op).
res2 = run_guard({"tool_name": "Bash",
                  "tool_input": {"command": "deploy --key sk_live_abcd1234efgh5678ijkl"}})
check("already-vaulted value is allowed through (idempotent)", res2 is None, res2)

# 3. Placeholder reference → allowed.
res3 = run_guard({"tool_name": "Bash",
                  "tool_input": {"command": "deploy --key @@SECRET:stripe@@"}})
check("placeholder reference is allowed", res3 is None, res3)

# 4. Secret in a Write file body → deny with file-specific guidance.
res4 = run_guard({"tool_name": "Write",
                  "tool_input": {"file_path": "/tmp/x.env", "content": "AWS=AKIAIOSFODNN7EXAMPLE"}})
d4 = (res4 or {}).get("hookSpecificOutput", {})
check("secret in Write body is denied", d4.get("permissionDecision") == "deny", res4)
check("Write guidance says not to write the literal secret",
      "Do NOT write the literal secret" in d4.get("permissionDecisionReason", ""))

# 5. Secret in MCP tool args → deny.
res5 = run_guard({"tool_name": "mcp__github__create",
                  "tool_input": {"token": "ghp_1234567890abcdefghij1234567890abcdef"}})
check("secret in MCP args is denied",
      (res5 or {}).get("hookSpecificOutput", {}).get("permissionDecision") == "deny", res5)

# 6. Non-scanned tool (Read) → allowed even if input looks secret-ish.
res6 = run_guard({"tool_name": "Read", "tool_input": {"file_path": "AKIAIOSFODNN7EXAMPLE"}})
check("non-scanned tool is not inspected", res6 is None, res6)

# 7. Custom pattern is honored by the hook.
patterns.add_pattern("mycorp_[0-9a-f]{32}")
res7 = run_guard({"tool_name": "Bash",
                  "tool_input": {"command": "login mycorp_0123456789abcdef0123456789abcdef"}})
check("custom pattern triggers the guard",
      (res7 or {}).get("hookSpecificOutput", {}).get("permissionDecision") == "deny", res7)


# ── summary ──────────────────────────────────────────────────────────────────
import shutil  # noqa: E402
shutil.rmtree(_HOME, ignore_errors=True)

print(f"\n{_passed} passed, {_failed} failed")
if __name__ == "__main__":
    sys.exit(1 if _failed else 0)
