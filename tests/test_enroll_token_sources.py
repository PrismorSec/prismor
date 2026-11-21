"""prismor enroll reads the token from argv, --token-file or $PRISMOR_ENROLL_TOKEN (#350)."""
import pytest

from prismor.runtime import cli
from prismor.runtime.enterprise import identity, remote_policy


@pytest.fixture
def captured(monkeypatch):
    seen = {}

    def fake_enroll(token, base=None, label=None):
        seen["token"] = token
        raise RuntimeError("stop after token resolution")

    monkeypatch.setattr(identity, "enroll", fake_enroll)
    monkeypatch.setattr(remote_policy, "fetch", lambda **_: None)
    monkeypatch.delenv("PRISMOR_ENROLL_TOKEN", raising=False)
    return seen


def _run(argv):
    with pytest.raises(SystemExit):
        cli.main(["enroll", *argv])


def test_token_file(tmp_path, captured):
    f = tmp_path / "enroll.token"
    f.write_text("tok-from-file\n")
    _run(["--token-file", str(f)])
    assert captured["token"] == "tok-from-file"


def test_env_var(monkeypatch, captured):
    monkeypatch.setenv("PRISMOR_ENROLL_TOKEN", "tok-from-env")
    _run([])
    assert captured["token"] == "tok-from-env"


def test_argv_wins_over_env(monkeypatch, captured):
    monkeypatch.setenv("PRISMOR_ENROLL_TOKEN", "tok-from-env")
    _run(["tok-from-argv"])
    assert captured["token"] == "tok-from-argv"


def test_missing_token_file_fails(tmp_path, captured):
    _run(["--token-file", str(tmp_path / "nope")])
    assert "token" not in captured
