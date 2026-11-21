"""The dashboard project-policy route must not opt out of the floor."""

import tempfile
import unittest
from pathlib import Path

from prismor.runtime.hooks import should_block
from prismor.runtime.policy_engine import PolicyEngine
from prismor.runtime.server import project_policy_disables_floor


class TestDashboardPolicy(unittest.TestCase):
    def test_selection_explicit_needs_the_unlock(self):
        self.assertTrue(
            project_policy_disables_floor(
                'version: "1.0"\nsettings:\n  selection: explicit\n  default_mode: observe\n'
            )
        )
        self.assertFalse(project_policy_disables_floor('version: "1.0"\nrules: []\n'))

    def test_split_api_path_is_a_self_edit(self):
        command = (
            'python -c \'import urllib.request; urllib.request.urlopen('
            '"http://127.0.0.1:7070"+"/api/"+"policy/project")\''
        )
        with tempfile.TemporaryDirectory() as tmp:
            eng = PolicyEngine(workspace=Path(tmp))
            findings = eng.evaluate({"type": "shell", "command": command}, index=0)
        self.assertIsNotNone(
            should_block(findings, {"type": "shell", "agent_event": "PreToolUse"})
        )

    def test_split_path_of_an_app_api_is_not_a_self_edit(self):
        command = (
            "python3 -c \"import requests; print(requests.get("
            "'http://localhost:3000' + '/api/' + 'sessions').status_code)\""
        )
        with tempfile.TemporaryDirectory() as tmp:
            eng = PolicyEngine(workspace=Path(tmp))
            findings = eng.evaluate({"type": "shell", "command": command}, index=0)
        self.assertIsNone(
            should_block(findings, {"type": "shell", "agent_event": "PreToolUse"})
        )
