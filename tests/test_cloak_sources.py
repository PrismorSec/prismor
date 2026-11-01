"""Secret sources: `prismor cloak add NAME --from-ref REF` and `cloak sync`.

The value lands in the vault like any other secret (so the bash decloak hooks
and scrubbers need no change); only the reference is kept beside it. Every
backend is faked at its boundary -- the `op` process, the HTTPS calls to Okta
Privileged Access, the boto3 client -- and the tests check the exact requests
and that a value never reaches stdout, an error or the references file.
"""
from __future__ import annotations

import io
import json
import stat
import subprocess
import sys
import types
import urllib.error
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

from prismor.runtime.cloaking import sources  # noqa: E402
from prismor.runtime.cloaking.sources import SourceError  # noqa: E402

VALUE = "sk-live-9f8e7d6c5b4a39281706"


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path))
    monkeypatch.delenv("PRISMOR_SECRETS_DIR", raising=False)
    return tmp_path


def vaulted(home: Path, name: str) -> str:
    return (home / "secrets" / name).read_text(encoding="utf-8")


# ── 1Password ───────────────────────────────────────────────────────────────

@pytest.fixture
def op(monkeypatch):
    calls = []
    state = {"value": VALUE, "rc": 0, "stderr": "", "timeout": False}

    def run(argv, **kw):
        calls.append((argv, kw))
        if state["timeout"]:
            raise subprocess.TimeoutExpired(argv, kw.get("timeout"))
        return subprocess.CompletedProcess(argv, state["rc"], stdout=state["value"] if state["rc"] == 0 else "",
                                           stderr=state["stderr"])

    monkeypatch.setattr(sources.shutil, "which", lambda name: "/usr/bin/op" if name == "op" else None)
    monkeypatch.setattr(sources.subprocess, "run", run)
    state["calls"] = calls
    return state


def test_1password_value_goes_to_the_vault_and_only_the_ref_is_kept(home, op):
    path = sources.add_from_ref("OPENAI_KEY", "op://Private/OpenAI/credential")
    assert vaulted(home, "OPENAI_KEY") == VALUE
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    argv, kw = op["calls"][0]
    # -n and no --out-file: nothing written to disk by op.
    assert argv == ["/usr/bin/op", "read", "-n", "op://Private/OpenAI/credential"]
    assert kw["timeout"] == sources.TIMEOUT
    refs = (home / "secret-sources.json").read_text()
    assert json.loads(refs) == {"OPENAI_KEY": {"ref": "op://Private/OpenAI/credential"}}
    assert VALUE not in refs
    assert stat.S_IMODE((home / "secret-sources.json").stat().st_mode) == 0o600


def test_1password_locked_app_times_out_and_nothing_is_written(home, op):
    op["timeout"] = True
    with pytest.raises(SourceError, match="locked"):
        sources.add_from_ref("K", "op://v/i/f")
    assert not (home / "secrets" / "K").exists()
    assert not (home / "secret-sources.json").exists()


def test_1password_error_is_reported_without_a_value(op):
    op["rc"], op["stderr"] = 1, '[ERROR] "Private" isn\'t a vault in this account'
    with pytest.raises(SourceError) as exc:
        sources.fetch("op://Private/x/y")
    assert "isn't a vault" in str(exc.value)


def test_missing_op_cli(monkeypatch):
    monkeypatch.setattr(sources.shutil, "which", lambda name: None)
    with pytest.raises(SourceError, match="not installed"):
        sources.fetch("op://v/i/f")


def test_empty_value_is_refused(op):
    op["value"] = ""
    with pytest.raises(SourceError, match="empty"):
        sources.fetch("op://v/i/f")


# ── Okta Privileged Access ─────────────────────────────────────────────────

class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


@pytest.fixture
def okta(monkeypatch):
    monkeypatch.setenv("PRISMOR_OKTA_PAM_URL", "https://acme.pam.okta.com/")
    monkeypatch.setenv("PRISMOR_OKTA_PAM_KEY_ID", "kid-1")
    monkeypatch.setenv("PRISMOR_OKTA_PAM_KEY_SECRET", "ksecret-1")
    state = {"plain": {"api_key": VALUE}, "fail": None, "calls": []}

    def urlopen(req, timeout=None):
        body = json.loads(req.data.decode())
        assert req.get_header("User-agent", "").startswith("prismor")
        state["calls"].append((req.get_method(), req.full_url, body, req.get_header("Authorization"), timeout))
        if state["fail"] and state["fail"][0] in req.full_url:
            raise urllib.error.HTTPError(req.full_url, state["fail"][1], "x", {},
                                         io.BytesIO(b'{"echo": "ksecret-1"}'))
        if req.full_url.endswith("/service_token"):
            return _Resp(json.dumps({"bearer_token": "bt-1", "expires_at": "2026-11-01T01:00:00Z", "team_name": "acme"}).encode())
        return _Resp(json.dumps({"plain_text": state["plain"], "sensitive_fields": ["plain_text"]}).encode())

    monkeypatch.setattr(sources.urllib.request, "urlopen", urlopen)
    return state


def test_okta_pam_token_then_plain_text_reveal(home, okta):
    sources.add_from_ref("STRIPE", "okta-pam://acme/rg-1/proj-1/sec-1")
    assert vaulted(home, "STRIPE") == VALUE
    (m1, u1, b1, a1, t1), (m2, u2, b2, a2, _) = okta["calls"]
    assert (m1, u1, b1, a1) == ("POST", "https://acme.pam.okta.com/v1/teams/acme/service_token",
                                {"key_id": "kid-1", "key_secret": "ksecret-1"}, None)
    assert t1 == sources.TIMEOUT
    assert (m2, u2, b2, a2) == ("POST", "https://acme.pam.okta.com/v1/teams/acme/resource_groups/rg-1/projects/proj-1/secrets/sec-1",
                                {"use_plain_text": True}, "Bearer bt-1")


def test_okta_pam_field_selection(okta):
    okta["plain"] = {"username": "svc", "password": VALUE}
    assert sources.fetch("okta-pam://acme/rg/p/s#password") == VALUE
    with pytest.raises(SourceError, match="several fields"):
        sources.fetch("okta-pam://acme/rg/p/s")
    with pytest.raises(SourceError, match="no field 'pin'"):
        sources.fetch("okta-pam://acme/rg/p/s#pin")


def test_okta_pam_http_error_never_echoes_the_body(okta):
    okta["fail"] = ("/service_token", 401)
    with pytest.raises(SourceError) as exc:
        sources.fetch("okta-pam://acme/rg/p/s")
    assert "HTTP 401" in str(exc.value) and "ksecret-1" not in str(exc.value)


def test_okta_pam_path_parts_are_escaped(okta):
    sources.fetch("okta-pam://acme/rg/p/..%2F..")
    assert "/secrets/..%252F.." in okta["calls"][1][1]


def test_okta_pam_needs_https_and_credentials(monkeypatch, okta):
    monkeypatch.setenv("PRISMOR_OKTA_PAM_URL", "http://acme.pam.okta.com")
    with pytest.raises(SourceError, match="PRISMOR_OKTA_PAM_URL"):
        sources.fetch("okta-pam://acme/rg/p/s")
    assert okta["calls"] == []


def test_okta_pam_bad_reference():
    with pytest.raises(SourceError, match="must be okta-pam://"):
        sources.fetch("okta-pam://acme/rg/p")


# ── AWS Bedrock AgentCore Identity ─────────────────────────────────────────

@pytest.fixture
def agentcore(monkeypatch):
    class ClientError(Exception):
        def __init__(self, response, operation_name):
            self.response, self.operation_name = response, operation_name

    class BotoCoreError(Exception):
        pass

    state = {"calls": [], "error": None}

    class Client:
        def get_workload_access_token(self, **kw):
            state["calls"].append(("get_workload_access_token", kw))
            if state["error"]:
                raise state["error"]
            return {"workloadAccessToken": "wat-1"}

        def get_resource_api_key(self, **kw):
            state["calls"].append(("get_resource_api_key", kw))
            return {"apiKey": VALUE}

    def client(service, region_name=None, config=None):
        state["client"] = (service, region_name)
        return Client()

    boto3 = types.SimpleNamespace(client=client)
    botocore = types.ModuleType("botocore")
    config = types.ModuleType("botocore.config")
    config.Config = lambda **kw: kw
    exceptions = types.ModuleType("botocore.exceptions")
    exceptions.ClientError, exceptions.BotoCoreError = ClientError, BotoCoreError
    monkeypatch.setitem(sys.modules, "boto3", boto3)
    monkeypatch.setitem(sys.modules, "botocore", botocore)
    monkeypatch.setitem(sys.modules, "botocore.config", config)
    monkeypatch.setitem(sys.modules, "botocore.exceptions", exceptions)
    state["ClientError"], state["BotoCoreError"] = ClientError, BotoCoreError
    return state


def test_agentcore_workload_token_then_api_key(home, agentcore):
    sources.add_from_ref("OPENAI_KEY", "agentcore://us-east-1/dev-cli/openai")
    assert vaulted(home, "OPENAI_KEY") == VALUE
    assert agentcore["client"] == ("bedrock-agentcore", "us-east-1")
    assert agentcore["calls"] == [
        ("get_workload_access_token", {"workloadName": "dev-cli"}),
        ("get_resource_api_key", {"resourceCredentialProviderName": "openai", "workloadIdentityToken": "wat-1"}),
    ]


def test_agentcore_access_denied(agentcore):
    agentcore["error"] = agentcore["ClientError"](
        {"Error": {"Code": "AccessDeniedException", "Message": "not authorized"}}, "GetWorkloadAccessToken")
    with pytest.raises(SourceError, match="GetWorkloadAccessToken: AccessDeniedException"):
        sources.fetch("agentcore://us-east-1/dev-cli/openai")


def test_agentcore_expired_sso(agentcore):
    agentcore["error"] = agentcore["BotoCoreError"]("The SSO session has expired")
    with pytest.raises(SourceError, match="AWS credentials: The SSO session has expired"):
        sources.fetch("agentcore://us-east-1/dev-cli/openai")


def test_agentcore_without_boto3(monkeypatch):
    monkeypatch.setitem(sys.modules, "boto3", None)
    with pytest.raises(SourceError, match="need boto3"):
        sources.fetch("agentcore://us-east-1/w/p")


def test_agentcore_bad_reference():
    with pytest.raises(SourceError, match="must be agentcore://"):
        sources.fetch("agentcore://us-east-1/w")


# ── references, sync, remove ────────────────────────────────────────────────

def test_unsupported_scheme_and_bad_name_fetch_nothing(op):
    with pytest.raises(SourceError, match="unsupported reference"):
        sources.add_from_ref("K", "vault://x")
    with pytest.raises(ValueError):
        sources.add_from_ref("../escape", "op://v/i/f")
    assert op["calls"] == []


def test_sync_updates_rotated_keeps_unchanged_and_survives_a_failure(home, op):
    sources.add_from_ref("A", "op://v/a/f")
    sources.add_from_ref("B", "op://v/b/f")
    op["value"] = "sk-rotated-000111222333"
    assert sources.sync(["A"]) == [{"name": "A", "status": "updated"}]
    assert vaulted(home, "A") == "sk-rotated-000111222333"
    assert sources.sync(["A"]) == [{"name": "A", "status": "unchanged"}]
    # A locked source keeps the last good value instead of emptying the vault.
    op["timeout"] = True
    res = sources.sync()
    assert [r["status"] for r in res] == ["error", "error"]
    assert vaulted(home, "B") == VALUE
    assert sources.sync(["nope"]) == [{"name": "nope", "status": "unknown", "error": "not added with --from-ref"}]


def test_cli_add_list_sync_remove_never_print_the_value(home, op, capsys, monkeypatch):
    from prismor.runtime.cli import main
    monkeypatch.setattr(sys, "argv", ["prismor", "cloak", "add", "OPENAI_KEY", "--from-ref", "op://Private/OpenAI/credential"])
    main()
    monkeypatch.setattr(sys, "argv", ["prismor", "cloak", "list"])
    main()
    monkeypatch.setattr(sys, "argv", ["prismor", "cloak", "sync"])
    main()
    out = capsys.readouterr().out
    assert VALUE not in out
    assert "from op://Private/OpenAI/credential" in out
    assert "@@SECRET:OPENAI_KEY@@  unchanged" in out
    monkeypatch.setattr(sys, "argv", ["prismor", "cloak", "remove", "OPENAI_KEY"])
    main()
    assert json.loads((home / "secret-sources.json").read_text()) == {}


def test_cli_sync_exits_nonzero_on_a_failed_source(home, op, monkeypatch):
    from prismor.runtime.cli import main
    sources.add_from_ref("A", "op://v/a/f")
    op["timeout"] = True
    monkeypatch.setattr(sys, "argv", ["prismor", "cloak", "sync"])
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 1


def test_real_op_process_then_the_unchanged_decloak_and_scrub_paths(home, tmp_path, monkeypatch):
    """No fakes inside Python: a stand-in `op` on PATH, the real subprocess
    call, then the cloaking runtime's own decloak and scrub on the result."""
    from prismor.runtime.cloaking.runtime import _SECRET_MAP_CACHE, decloak_text, scrub_text
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake = bin_dir / "op"
    fake.write_text('#!/bin/sh\n[ "$1 $2" = "read -n" ] && [ "$3" = "op://Eng/OpenAI/credential" ] '
                    f'&& printf %s "{VALUE}" && exit 0\necho "bad args: $*" >&2; exit 1\n')
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}:/usr/bin:/bin")
    _SECRET_MAP_CACHE.clear()
    sources.add_from_ref("OPENAI_KEY", "op://Eng/OpenAI/credential")
    placeholder = "@@" + "SECRET:OPENAI_KEY@@"
    assert decloak_text(f"curl -H 'Authorization: Bearer {placeholder}' api") == f"curl -H 'Authorization: Bearer {VALUE}' api"
    assert VALUE not in scrub_text(f"echo {VALUE}")
    with pytest.raises(SourceError, match="bad args"):
        sources.fetch("op://Eng/Other/credential")


def test_cli_from_ref_and_from_file_conflict(monkeypatch, capsys):
    from prismor.runtime.cli import main
    monkeypatch.setattr(sys, "argv", ["prismor", "cloak", "add", "K", "--from-ref", "op://v/i/f", "--from-file", "/tmp/x"])
    with pytest.raises(SystemExit):
        main()
    assert "cannot be combined" in capsys.readouterr().err
