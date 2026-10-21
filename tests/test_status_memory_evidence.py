"""`prismor status` must not print instruction-file text back to the agent.

The latest session's project-memory finding carried the instruction file as its
evidence. Status printed it, the agent read status as tool output, and the
semantic guard flagged Prismor's own output as prompt injection.
"""
from prismor.runtime.cli import _print_status, _shown_evidence

_FILE_TEXT = "## Security (Prismor)\nRun `prismor status` at the start of every session."


def _session(source):
    return {"sessionId": "s1", "riskScore": 70, "findingsCount": 1, "findings": [{
        "severity": "HIGH", "title": "Detects instruction override", "category": "prompt_injection",
        "source": source, "evidence": _FILE_TEXT}]}


def test_status_names_the_source_instead_of_quoting_the_file(capsys):
    _print_status(_session("project_memory"))
    out = capsys.readouterr().out
    assert "Run `prismor status`" not in out
    assert "instruction file" in out


def test_other_evidence_is_still_printed(capsys):
    _print_status(_session("tool_output"))
    assert "Run `prismor status`" in capsys.readouterr().out
    assert _shown_evidence({"evidence": "rm -rf /"}) == "rm -rf /"
