"""`prismor help`: every real command is listed exactly once, search and typo hints work."""
import pytest

from prismor.runtime import immunity_cli as cli


def test_every_visible_command_listed_once():
    table = cli._command_table()
    listed = [n for _, rows in cli._help_sections(table) for n, _, _ in rows]
    assert len(listed) == len(set(listed))
    assert set(listed) == {n for n, (h, _, _) in table.items()
                           if n not in cli._HELP_HIDDEN and h and h != "==SUPPRESS=="}
    assert "exec-hook" not in listed and "hook-dispatch" not in listed


def test_search_returns_exact_subcommands(capsys):
    cli.main(["--help", "secret"])
    out = capsys.readouterr().out
    assert "prismor cloak add" in out and "Register one secret" in out


def test_help_search_and_forward(capsys):
    cli.main(["help", "npm"])  # matches supplychain's sub-actions, not a command name
    assert "supplychain" in capsys.readouterr().out
    with pytest.raises(SystemExit) as e:
        cli.main(["help", "cloak", "add"])
    assert e.value.code == 0
    assert "usage: prismor cloak add" in capsys.readouterr().out


def test_unknown_command_suggests(capsys):
    with pytest.raises(SystemExit) as e:
        cli.main(["clok"])
    assert e.value.code == 2
    assert "Did you mean: cloak" in capsys.readouterr().err


def test_agent_bare_setup_asks_instead_of_installing(tmp_path, monkeypatch, capsys):
    """An agent's shell has no TTY; a bare `prismor setup` must hand back the
    wizard's questions and install nothing. Any explicit flag still installs."""
    from prismor.runtime.cli import main as runtime_main
    monkeypatch.setenv("AI_AGENT", "test-agent")
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    for k in ("PRISMOR_MODE", "PRISMOR_CLOAK", "PRISMOR_SCOPE"):
        monkeypatch.delenv(k, raising=False)
    runtime_main(["setup", str(tmp_path)])
    out = capsys.readouterr().out
    assert "Nothing has been installed yet" in out
    assert "prismor setup --non-interactive --mode enforce --recommended" in out
    assert not (tmp_path / ".claude").exists()
