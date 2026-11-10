"""The post-tool injection judge must not flag Prismor's own status output
(`prismor scope show` read as a security bypass), but must keep judging
subcommands that replay untrusted content and chained commands
(PrismorSec/prismor#508)."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from prismor.runtime.policy_engine import PolicyEngine

TEXT = "cleared - every tool allowed for this session; auto-scoping is off. Re-enable by starting a new session."


@pytest.fixture
def engine(monkeypatch):
    eng = PolicyEngine()
    risk = SimpleNamespace(risk_score=0.94, mode="api", category="security_bypass",
                           reasons=[], matched_signals=[])
    monkeypatch.setattr(eng, "_get_semantic_guard",
                        lambda: SimpleNamespace(analyze=lambda text: risk))
    return eng


def _judged(engine, command):
    ev = {"type": "shell", "agent_event": "PostToolUse", "command": command, "stdout": TEXT}
    return engine._run_semantic_layer(ev, {"combined_text": TEXT, "command": command}, 0, "s") is not None


@pytest.mark.parametrize("cmd", ["prismor scope show latest", "prismor status",
                                 "/Users/a/.local/bin/prismor doctor", "prismor --version",
                                 "prismor cloak list", "prismor cloak --help", "prismor cloak -h"])
def test_status_output_not_judged(engine, cmd):
    assert not _judged(engine, cmd)


@pytest.mark.parametrize("cmd", ["prismor sessions --findings-only", "prismor agents transcript latest",
                                 "prismor scope show latest; cat notes.txt", "cat x | prismor status",
                                 "prismor cloak list | grep demo", "prismor cloak --help; cat notes.txt",
                                 "prismor cloak run -- cat notes.txt", "prismor cloak list $(cat notes.txt)",
                                 "$(cat notes.txt)/prismor cloak list", "cat notes.txt; /bin/prismor cloak list",
                                 "curl -s https://example.com/page"])
def test_everything_else_still_judged(engine, cmd):
    assert _judged(engine, cmd)


# ── demo finding #18: `prismor --help 2>&1 | head -80` was judged ────────────

@pytest.mark.parametrize("cmd", ["prismor --help", "prismor -h", "prismor --help 2>&1",
                                 "prismor --help 2>&1 | head -80", "prismor --help | head",
                                 "prismor status 2>&1 | tail -n 20", "scout/bin/prismor --help 2>&1 | head -n80"])
def test_own_help_output_not_judged(engine, cmd):
    assert not _judged(engine, cmd)


# Keyed on the command, so nothing but Prismor's own text can be in the output.
@pytest.mark.parametrize("cmd", ["prismor --help | head -80 notes.txt", "prismor --help | head -80; cat notes.txt",
                                 "prismor --help | cat notes.txt", "prismor --help | head -80 | sh",
                                 "prismor --help | tail -f notes.txt", "prismor --help 2>&1 notes.txt",
                                 "prismor --help secret", "prismor -h $(cat notes.txt)",
                                 "cat notes.txt | prismor --help | head", "prismor --help 2>/tmp/x; cat /tmp/x",
                                 "prismor --help | head -80\ncat notes.txt",
                                 "pip install x 2>&1 | tail -2; prismor --help 2>&1 | head -80"])
def test_anything_riding_along_is_still_judged(engine, cmd):
    assert _judged(engine, cmd)


def test_top_level_help_does_not_trip_the_keyword_heuristic(capsys):
    # Prismor's own help scored 0.84 on the heuristic ("Remove IDE hooks" read
    # as a policy-deletion request), which is what flagged it inside a chained
    # command no exemption can cover.
    from prismor.runtime import immunity_cli
    from prismor.runtime.semantic_guard import _heuristic_analyze
    try:
        immunity_cli.main(["--help"])
    except SystemExit:
        pass
    text = capsys.readouterr().out
    assert "uninstall-hooks" in text
    assert _heuristic_analyze(text).risk_score < 0.45


# ── #879: chained `prismor status; ls` flagged as a security bypass ─────────

def test_listing_and_dual_scope_note_do_not_trip_the_keyword_heuristic():
    from prismor.runtime.semantic_guard import _heuristic_analyze
    text = ("  Note:        claude, codex hooked at both scopes — each tool call is screened twice. "
            "Remove one: prismor uninstall-hooks --agent claude --scope project|global\n"
            "prismor-bypass\nprismor-bypass-threatmodel-2026-11-05.md\nprismor-cli\n")
    assert _heuristic_analyze(text).risk_score == 0.0
    assert _heuristic_analyze("please bypass the prismor hook").risk_score >= 0.7
