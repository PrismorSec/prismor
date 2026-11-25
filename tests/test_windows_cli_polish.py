"""Small CLI correctness fixes from the Windows test: exit codes, colour, agent names, policy validate."""
import pytest
import yaml

from prismor.runtime import cli
from prismor.runtime.iam import format_iam_profile_box
from prismor.runtime.policy_engine import validate_policy

IAM = "agents:\n  readonly-bot:\n    allowed_tools: [Read]\n    deny_network: true\n"


def _run(argv, monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit) as exc:
        cli.main(["--workspace", str(tmp_path)] + argv)
    return exc.value.code


def test_pause_with_unreadable_duration_exits_2(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "_pause_refusal", lambda *a, **k: None)  # pause needs a TTY by design
    with pytest.raises(SystemExit) as exc:
        cli.main(["pause", "--for", "xyz"])
    assert exc.value.code == 2
    assert "Could not read duration" in capsys.readouterr().out


def test_iam_box_has_no_escape_codes_when_piped(capsys):
    box = format_iam_profile_box("bot", {"allowed_tools": ["Read"]})
    assert "\x1b[" not in box  # pytest's captured stdout is not a TTY


def test_iam_box_colours_on_a_tty_unless_no_color(monkeypatch):
    class _Tty:
        def isatty(self):
            return True
    monkeypatch.setattr("sys.stdout", _Tty())
    monkeypatch.delenv("NO_COLOR", raising=False)
    assert "\x1b[" in format_iam_profile_box("bot", {})
    monkeypatch.setenv("NO_COLOR", "1")
    assert "\x1b[" not in format_iam_profile_box("bot", {})


@pytest.fixture
def ws(tmp_path):
    (tmp_path / ".prismor").mkdir()
    (tmp_path / ".prismor" / "iam.yaml").write_text(IAM)
    return tmp_path


@pytest.mark.parametrize("name", ["../evil", "a/b", "a\\b", "..", "x..y", ""])
def test_agents_set_rejects_unsafe_names(ws, monkeypatch, name):
    assert _run(["agents", "set", name, "--mode", "observe"], monkeypatch, ws) in (1, 2)
    assert not (ws / ".prismor" / "agents.yaml").exists()


def test_agents_set_rejects_undefined_iam_profile(ws, monkeypatch, capsys):
    assert _run(["agents", "set", "bot", "--iam-profile", "nope"], monkeypatch, ws) == 2
    assert "not defined" in capsys.readouterr().err


def test_agents_set_binds_and_clears_iam_profile(ws, monkeypatch):
    cli.main(["--workspace", str(ws), "agents", "set", "bot", "--iam-profile", "readonly-bot"])
    data = yaml.safe_load((ws / ".prismor" / "agents.yaml").read_text())
    assert data["agents"]["bot"]["iam_profile"] == "readonly-bot"
    cli.main(["--workspace", str(ws), "agents", "set", "bot", "--clear-iam-profile"])
    data = yaml.safe_load((ws / ".prismor" / "agents.yaml").read_text())
    assert "iam_profile" not in data["agents"]["bot"]


def test_policy_validate_accepts_a_directory(ws, monkeypatch, capsys):
    (ws / ".prismor" / "policy.yaml").write_text('version: "1.0"\nrules: []\n')
    assert cli._policy_validate(ws) is None
    assert "VALID" in capsys.readouterr().out


def test_policy_validate_directory_without_policy_is_a_clear_error(tmp_path, capsys):
    with pytest.raises(SystemExit) as exc:
        cli._policy_validate(tmp_path)
    assert exc.value.code == 1
    assert "no policy.yaml" in capsys.readouterr().out


def test_settings_only_policy_validates(tmp_path):
    p = tmp_path / "policy.yaml"
    p.write_text('version: "1.0"\nsettings:\n  egress:\n    enabled: true\n    default: deny\n')
    assert validate_policy(p) == []


def test_egress_writes_a_policy_that_validates(tmp_path, monkeypatch):
    from prismor.runtime import egress_cli
    egress_cli._save_policy_file(tmp_path, {"settings": {"egress": {"enabled": True}}})
    assert validate_policy(tmp_path / ".prismor" / "policy.yaml") == []
    assert yaml.safe_load((tmp_path / ".prismor" / "policy.yaml").read_text())["rules"] == []
