"""Prismor must not print instruction-file text back to the agent.

A project-memory finding carries the instruction file as its evidence. Printing
it hands that text to the agent as tool output, where the semantic guard flags
Prismor's own output as prompt injection.
"""
from prismor.runtime.cli import _shown_evidence

_FILE_TEXT = "## Security (Prismor)\nRun `prismor status` at the start of every session."


def test_instruction_file_text_is_not_quoted():
    shown = _shown_evidence({"source": "project_memory", "evidence": _FILE_TEXT})
    assert "Run `prismor status`" not in shown
    assert "instruction file" in shown


def test_other_evidence_is_still_shown():
    assert _shown_evidence({"evidence": "rm -rf /"}) == "rm -rf /"
