"""The update notice must only fire for a genuinely newer release.

It compared with `==`, so anyone running ahead of PyPI — a dev build, or every
user for the cache's lifetime right after a release — was told an OLDER version
was available and asked to upgrade to it.
"""
from prismor.runtime.immunity_cli import _is_newer, _version_tuple


def test_only_a_strictly_newer_version_notifies():
    assert _is_newer("1.43.1", "1.43.0")
    assert _is_newer("1.44.0", "1.43.9")
    assert _is_newer("2.0.0", "1.99.99")


def test_older_or_equal_never_notifies():
    assert not _is_newer("1.42.2", "1.43.0"), "the bug: an older release advertised as an upgrade"
    assert not _is_newer("1.43.0", "1.43.0")
    assert not _is_newer("1.9.0", "1.10.0"), "1.10 is newer than 1.9 — string compare would get this wrong"


def test_odd_versions_do_not_raise():
    assert _version_tuple("1.43.0rc1")[:2] == (1, 43)
    assert _is_newer("1.44.0.dev1", "1.43.0")
    for bad in ("", "not-a-version", "..."):
        _is_newer(bad, "1.43.0")  # must not raise


def _notice(monkeypatch, capsys, **env):
    from prismor.runtime import immunity_cli, version_check
    for k in ("PRISMOR_NO_UPDATE_CHECK", "AI_AGENT", "CLAUDECODE", "CODEX_THREAD_ID",
              "CODEX_SANDBOX", "CURSOR_AGENT", "GEMINI_CLI"):
        monkeypatch.delenv(k, raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setattr(version_check, "latest_known_version", lambda: "999.0.0")
    immunity_cli._update_notice()
    return capsys.readouterr().err


def test_notice_shows_in_a_human_terminal(monkeypatch, capsys):
    assert "999.0.0 is available" in _notice(monkeypatch, capsys)


def test_notice_is_not_shown_to_an_agent(monkeypatch, capsys):
    # Agents relayed it into answers about something else (demo finding #7).
    assert _notice(monkeypatch, capsys, CLAUDECODE="1") == ""
    assert _notice(monkeypatch, capsys, CODEX_THREAD_ID="t") == ""
