"""`prismor aibom`: CycloneDX shape and the things it must never leak.

Schema validity itself was checked against cyclonedx-python-lib's strict 1.6
validator; these pin the two bugs that check found or would have found.
"""
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prismor.runtime import aibom  # noqa: E402

def _inv(HOME):
    return {
        "agents": [{"id": "claude", "name": "Claude Code", "managed": True, "mode": "enforce", "coverable": True},
                   {"id": "gemini", "name": "Gemini CLI", "managed": False, "coverable": True}],
        "models": [{"model": "claude-opus-5-5", "provider": "anthropic", "sessions": 3, "last_seen": "2026-10-17"}],
        "mcp": [{"name": "docs", "agent": "claude", "source": f"{HOME}/.claude.json", "transport": "http",
                 "url": "https://mcp.example.com/mcp?token=abcdef0123456789abcdef", "remote": True,
                 "command": [], "managed": False, "risk": "medium", "findings": []},
                {"name": "local", "agent": "claude", "source": f"{HOME}/.claude.json", "transport": "stdio",
                 "url": "", "command": ["node", f"{HOME}/tools/server.js", "--api-key=sk-abcdefghijklmnop0123"],
                 "managed": False, "risk": "none", "findings": []}],
        "extensions": [{"id": f"skill:{HOME}/.claude/skills/x/SKILL.md", "kind": "skill", "name": "x",
                        "path": f"{HOME}/.claude/skills/x/SKILL.md", "sha256": "ab" * 32, "status": "new",
                        "capabilities": ["runs_code"], "hosts": [], "agents": ["claude"],
                        "origin": "https://github.com/acme/skills.git", "installed_by": "out-of-band"}],
        "instructions": [{"path": f"{HOME}/proj/CLAUDE.md", "sha256": "sha256:" + "cd" * 32, "signed": False}],
    }


class TestAibom(unittest.TestCase):
    def setUp(self):
        global HOME
        HOME = str(Path.home())
        self.bom = aibom.to_cyclonedx(_inv(HOME))
        self.text = str(self.bom)

    def test_cyclonedx_envelope_and_layers(self):
        self.assertEqual((self.bom["bomFormat"], self.bom["specVersion"]), ("CycloneDX", "1.6"))
        types = {c["bom-ref"]: c["type"] for c in self.bom["components"]}
        self.assertEqual(types["model:claude-opus-5-5"], "machine-learning-model")
        self.assertEqual(len(types), len(self.bom["components"]), "bom-refs are unique")
        refs = set(types)
        for dep in self.bom["dependencies"]:
            self.assertTrue({dep["ref"], *dep["dependsOn"]} <= refs)

    def test_never_leaks_home_paths_or_secrets(self):
        self.assertNotIn(HOME, self.text)
        self.assertNotIn("abcdef0123456789abcdef", self.text)
        self.assertNotIn("sk-abcdefghijklmnop0123", self.text)

    def test_urls_are_valid_iris_after_redaction(self):
        urls = [r["url"] for c in self.bom["components"] for r in c.get("externalReferences", [])]
        self.assertTrue(urls)
        for url in urls:
            self.assertFalse(set(url) & set('<> "{}|\\^`'), url)

    def test_markdown_names_ungoverned_agents(self):
        md = aibom.to_markdown(self.bom)
        self.assertIn("can be hooked: Gemini CLI", md)
        self.assertIn("| Skills | 1 |", md)


if __name__ == "__main__":
    unittest.main()
