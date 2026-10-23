"""recloak-mcp.sh: literal scrub of MCP tool output, fast on multi-MB responses.

The old bash ${var//"$real"/...} loop was quadratic in response size and pinned
the hook for minutes per secret on browser screenshots; its jq --arg output
overflowed ARG_MAX on large responses. Uses a throwaway secrets dir.
"""
from __future__ import annotations

import base64
import json
import os
import subprocess
import time
from pathlib import Path

_HOOK = Path(__file__).resolve().parent.parent / "prismor/runtime/cloaking/hooks/recloak-mcp.sh"

_SECRETS = {
    "A_KEY": "sk-test-abc123\n",            # trailing newline is stripped, like $(cat)
    "RE_KEY": "a.b*c[d]$x\\1/@@",           # regex/glob metacharacters stay literal
    "PEM": "-----BEGIN-----\nline2\nline3",  # multi-line
    "EMPTY": "",
}


def _run(tmp_path: Path, response: str) -> str:
    d = tmp_path / "secrets dir"
    d.mkdir(exist_ok=True)
    for name, value in _SECRETS.items():
        (d / name).write_text(value)
    payload = json.dumps({"tool_name": "mcp__x__y", "tool_response": response})
    out = subprocess.run(["bash", str(_HOOK)], input=payload, text=True, capture_output=True,
                         env={**os.environ, "PRISMOR_SECRETS_DIR": str(d)}, timeout=60).stdout
    return json.loads(out)["hookSpecificOutput"]["updatedMCPToolOutput"] if out else ""


def test_scrubs_literally(tmp_path):
    got = _run(tmp_path, "x sk-test-abc123 a.b*c[d]$x\\1/@@ aXb*c[d]$x\\1/@@ -----BEGIN-----\nline2\nline3 é✓")
    assert got == "x @@SECRET:A_KEY@@ @@SECRET:RE_KEY@@ aXb*c[d]$x\\1/@@ @@SECRET:PEM@@ é✓"


def test_no_secret_is_noop(tmp_path):
    assert _run(tmp_path, "nothing here") == ""


def test_large_response_is_fast(tmp_path):
    big = base64.b64encode(os.urandom(3_000_000)).decode() + " sk-test-abc123"
    t = time.time()
    got = _run(tmp_path, big)
    assert got.endswith(" @@SECRET:A_KEY@@") and time.time() - t < 15
