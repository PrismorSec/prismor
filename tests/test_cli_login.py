"""`prismor login`: the device-authorization flow the Prismor API signs in with."""
import io
import json
import webbrowser

import pytest

from prismor.runtime.enterprise import cli_login, identity

START = {
    "device_code": "cli_secret", "user_code": "WXYZ-2345",
    "verification_uri": "https://cp.example/cli",
    "verification_uri_complete": "https://cp.example/cli?code=WXYZ-2345",
    "interval": 0, "expires_in": 900,
}
APPROVED = {
    "status": "approved", "device_key": "dk_live", "device_id": "dev_1",
    "org": {"id": "org_1", "name": "Ada's Org", "plan": "free"},
    "quota": {"used": 0, "limit": 1000, "resets": "2026-10-01T00:00:00.000Z"},
}


class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


@pytest.fixture
def home(monkeypatch, tmp_path):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path))
    monkeypatch.setenv("PRISMOR_API_BASE", "https://cp.example")
    monkeypatch.setattr(webbrowser, "open", lambda *a, **k: False)
    return tmp_path


def transport(monkeypatch, replies):
    """Queue one reply per request; records what was sent."""
    sent = []

    def fake_urlopen(req, timeout=None):
        sent.append({"url": req.full_url,
                     "body": json.loads(req.data) if req.data else None,
                     "auth": req.get_header("Authorization")})
        return _Resp(json.dumps(replies[min(len(sent) - 1, len(replies) - 1)]).encode())
    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    return sent


def test_start_asks_for_a_code_and_says_which_machine(home, monkeypatch):
    sent = transport(monkeypatch, [START])
    got = cli_login.start(label="laptop-7")
    assert got["user_code"] == "WXYZ-2345"
    assert sent[0]["url"] == "https://cp.example/api/v1/cli/login/start"
    assert sent[0]["body"]["label"] == "laptop-7" and sent[0]["body"]["platform"]


def test_polling_waits_for_the_human_then_returns_the_key(home, monkeypatch):
    transport(monkeypatch, [{"status": "pending"}, {"status": "pending"}, APPROVED])
    got = cli_login.wait_for_approval("cli_secret", interval=0)
    assert got["device_key"] == "dk_live"


@pytest.mark.parametrize("status, reason", [
    ("denied", "denied"), ("expired", "expired"), ("already_claimed", "already used"),
])
def test_a_refused_login_says_why(home, monkeypatch, status, reason):
    transport(monkeypatch, [{"status": status}])
    with pytest.raises(RuntimeError, match=reason):
        cli_login.wait_for_approval("cli_secret", interval=0)


def test_save_stores_the_identity_this_machine_will_judge_with(home, monkeypatch):
    cli_login.save(APPROVED)
    saved = identity.load_identity()
    assert saved["device_key"] == "dk_live" and saved["org_id"] == "org_1"
    assert saved["api_base"] == "https://cp.example"


def test_quota_is_read_with_the_device_key(home, monkeypatch):
    cli_login.save(APPROVED)
    sent = transport(monkeypatch, [{"plan": "free", "used": 12, "limit": 1000, "remaining": 988}])
    got = cli_login.quota()
    assert got["remaining"] == 988
    assert sent[0]["url"] == "https://cp.example/api/v1/judge/quota"
    assert sent[0]["auth"] == "Bearer dk_live"


def test_quota_is_none_when_this_machine_has_no_identity(home):
    assert cli_login.quota() is None


def test_the_flow_shows_the_code_the_link_and_what_you_got(home, monkeypatch):
    transport(monkeypatch, [START, APPROVED])
    out = io.StringIO()
    assert cli_login.run_interactive(out=out) is True
    text = out.getvalue()
    assert "WXYZ-2345" in text                      # the code to compare
    assert "https://cp.example/cli?code=WXYZ-2345" in text
    assert "1,000 verdicts a month" in text         # what the free plan includes
    assert "Ada's Org" in text
    assert identity.load_identity()["device_key"] == "dk_live"


def test_the_flow_can_set_the_workspace_judge(home, monkeypatch, tmp_path):
    transport(monkeypatch, [START, APPROVED])
    workspace = tmp_path / "repo"
    workspace.mkdir()
    assert cli_login.run_interactive(out=io.StringIO(), set_judge_for=workspace) is True
    policy = (workspace / ".prismor" / "policy.yaml").read_text()
    assert "provider: prismor" in policy


def test_a_failed_start_reports_instead_of_raising(home, monkeypatch):
    def boom(req, timeout=None):
        raise OSError("no route to host")
    monkeypatch.setattr("urllib.request.urlopen", boom)
    out = io.StringIO()
    assert cli_login.run_interactive(out=out) is False
    assert "Could not start sign-in" in out.getvalue()


def _engine(provider):
    return type("E", (), {"rules": [], "semantic_guard_config": {"provider": provider}})()


def test_status_reports_what_is_left_when_the_hosted_judge_is_configured(home, monkeypatch, capsys):
    """The docs promised `prismor status` shows this; 1.51.0 shipped without it."""
    from prismor.runtime import cli as _cli

    cli_login.save(APPROVED)
    transport(monkeypatch, [{"plan": "free", "used": 12, "limit": 1000, "remaining": 988,
                             "resets": "2026-10-01T00:00:00.000Z"}])
    _cli._print_status_quota(_engine("prismor"))
    out = capsys.readouterr().out
    assert "988 of 1,000 verdicts left" in out and "12 used" in out
    assert "resets 2026-10-01" in out


def test_status_says_nothing_about_quota_without_the_hosted_judge(home, monkeypatch, capsys):
    from prismor.runtime import cli as _cli

    monkeypatch.setattr("urllib.request.urlopen", lambda *a, **k: pytest.fail("no network call"))
    _cli._print_status_quota(_engine("codex"))
    assert capsys.readouterr().out == ""


def test_status_says_so_when_the_machine_is_not_signed_in(home, monkeypatch, capsys):
    from prismor.runtime import cli as _cli

    _cli._print_status_quota(_engine("prismor"))       # no identity saved
    assert "prismor login" in capsys.readouterr().out


def test_status_renders_for_an_unlimited_plan(home, monkeypatch, capsys):
    from prismor.runtime import cli as _cli

    cli_login.save(APPROVED)
    transport(monkeypatch, [{"plan": "enterprise", "used": 4210, "limit": None, "remaining": None}])
    _cli._print_status_quota(_engine("prismor"))
    assert "4,210 used this month (unlimited)" in capsys.readouterr().out
