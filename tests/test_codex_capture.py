"""Codex event capture: apply_patch file paths and skill loads.

Codex sends apply_patch as {"command": "<patch>"} with no path field, and loads a
skill by reading its SKILL.md in the shell, so neither the file a patch writes
nor the skill in use reached the store or the path rules before this.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prismor.runtime.hooks import normalize_payload
from prismor.runtime.scoped_agent import resolve_skill_name
from prismor.runtime.store import _extract_mcp_or_tool

REPO_ROOT = Path(__file__).resolve().parents[1]


def _patch(*files):
    body = "".join(f"*** Add File: {f}\n+x\n" for f in files)
    return f"*** Begin Patch\n{body}*** End Patch"


def _codex(tool, tool_input, ws):
    return normalize_payload(agent="codex", workspace=ws, payload={
        "session_id": "s", "hook_event_name": "PreToolUse", "cwd": str(ws),
        "tool_name": tool, "tool_input": tool_input})["event"]


class TestCodexCapture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self.tmp.name) / "ws"
        self.ws.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def test_apply_patch_path_from_body(self):
        ev = _codex("apply_patch", {"command": _patch("/w/a.txt")}, self.ws)
        self.assertEqual(ev["type"], "file_write")
        self.assertEqual(ev["path"], "/w/a.txt")
        self.assertNotIn("patch_paths", ev["metadata"])

    def test_apply_patch_multi_file_and_move(self):
        patch = ("*** Begin Patch\n*** Update File: a.py\n*** Move to: b.py\n@@\n-x\n+y\n"
                 "*** Delete File: c.py\n*** End Patch")
        ev = _codex("apply_patch", {"command": patch}, self.ws)
        self.assertEqual(ev["path"], "a.py")
        self.assertEqual(ev["metadata"]["patch_paths"], ["a.py", "b.py", "c.py"])

    def test_skill_read_tagged(self):
        for cmd in ("sed -n '1,220p' /home/u/.codex/skills/wiki-agent/SKILL.md",
                    "cat skills/foo.bar/SKILL.md"):
            ev = _codex("Bash", {"command": cmd}, self.ws)
            skill = cmd.split("skills/")[1].split("/")[0]
            self.assertEqual(ev["type"], "shell")
            self.assertEqual(resolve_skill_name(ev), skill)
            self.assertEqual(_extract_mcp_or_tool(json.dumps(ev)), {"kind": "skill", "name": skill})

    def test_plain_shell_not_a_skill(self):
        for cmd in ("ls skills/", "cat docs/SKILL.md", "cat myskills/x/SKILL.md"):
            ev = _codex("Bash", {"command": cmd}, self.ws)
            self.assertIsNone(resolve_skill_name(ev), cmd)

    def test_sensitive_second_file_in_patch_is_blocked(self):
        home = Path(self.tmp.name) / "home"
        payload = {"session_id": "s", "hook_event_name": "PreToolUse", "cwd": str(self.ws),
                   "tool_name": "apply_patch",
                   "tool_input": {"command": _patch(str(self.ws / "README.md"),
                                                    str(home / ".ssh" / "authorized_keys"))}}
        env = {**os.environ, "HOME": str(home), "PRISMOR_HOME": str(home / ".prismor")}
        proc = subprocess.run(
            [sys.executable, str(REPO_ROOT / "prismor" / "runtime" / "cli.py"), "hook-dispatch",
             "--agent", "codex", "--mode", "enforce", "--workspace", str(self.ws)],
            input=json.dumps(payload), capture_output=True, text=True, env=env, timeout=120)
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertIn("secret-access", proc.stderr)


if __name__ == "__main__":
    unittest.main()
