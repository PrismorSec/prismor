"""Verified end-user identity (settings.identity).

The subject a call is attributed to used to be whatever the caller asserted.
These tests pin what changes when an org configures an IdP:
  - a valid token replaces the asserted subject, roles included;
  - forged/expired/wrong-audience/alg-confusion tokens are rejected;
  - `require` blocks unverified calls, except a coding agent's own hook on an
    enrolled device; `observe` only tags them;
  - identity config is honored only from the signed org layer;
  - a user-scoped exemption no longer follows an asserted user id.
"""

import json
import time

import pytest
import yaml

jwt = pytest.importorskip("jwt")
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402

from prismor.runtime import identity_token  # noqa: E402
from prismor.runtime.identity_token import IdentityError, apply, verify  # noqa: E402
from prismor.runtime.principal import Subject, use_subject  # noqa: E402

ISS = "https://idp.example.com/"
AUD = "api://support-bot"
JWKS = "https://idp.example.com/jwks"
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
CFG = {"mode": "require", "issuer": ISS, "audience": [AUD], "jwks_uri": JWKS,
       "team_claim": "team", "roles_claim": "groups"}


def _jwks():
    pub = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(KEY.public_key()))
    return {"keys": [{**pub, "kid": "k1", "use": "sig", "alg": "RS256"}]}


@pytest.fixture(autouse=True)
def fake_jwks(monkeypatch):
    identity_token._jwks_clients.clear()
    monkeypatch.setattr(jwt.PyJWKClient, "fetch_data", lambda self: _jwks())
    identity_token.set_server_config(None)
    yield
    identity_token.set_server_config(None)


def tok(key=KEY, kid="k1", alg="RS256", **claims):
    base = {"iss": ISS, "aud": AUD, "sub": "carol", "exp": int(time.time()) + 300,
            "team": "finance", "groups": ["finance", "support"]}
    base.update(claims)
    return jwt.encode({k: v for k, v in base.items() if v is not None}, key, algorithm=alg,
                      headers={"kid": kid})


def test_valid_token_yields_verified_subject_with_roles():
    s = verify(tok(), CFG)
    assert (s.user_id, s.team_id, s.source, s.verified) == ("carol", "finance", "jwt", True)
    assert s.roles == ("finance", "support")


def test_roles_claim_as_space_separated_string():
    assert verify(tok(groups="a b,c"), CFG).roles == ("a", "b", "c")


@pytest.mark.parametrize("bad", [
    dict(exp=int(time.time()) - 3600),
    dict(aud="api://other"),
    dict(iss="https://evil.example.com/"),
    dict(exp=None),
    dict(sub=None),
    dict(key=OTHER_KEY),
    dict(kid="nope"),
], ids=["expired", "audience", "issuer", "no-exp", "no-sub", "wrong-key", "unknown-kid"])
def test_rejected_tokens(bad):
    with pytest.raises(IdentityError):
        verify(tok(**bad), CFG)


def test_alg_none_rejected():
    t = jwt.encode({"iss": ISS, "aud": AUD, "sub": "x", "exp": int(time.time()) + 60},
                   None, algorithm="none", headers={"kid": "k1"})
    with pytest.raises(IdentityError):
        verify(t, CFG)


def test_hs256_with_public_key_as_secret_rejected():
    from cryptography.hazmat.primitives import serialization
    pem = KEY.public_key().public_bytes(serialization.Encoding.PEM,
                                        serialization.PublicFormat.SubjectPublicKeyInfo)
    import hmac, hashlib, base64  # noqa: E401
    b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()  # noqa: E731
    head = b64(json.dumps({"alg": "HS256", "kid": "k1", "typ": "JWT"}).encode())
    body = b64(json.dumps({"iss": ISS, "aud": AUD, "sub": "x", "exp": int(time.time()) + 60}).encode())
    sig = b64(hmac.new(pem, f"{head}.{body}".encode(), hashlib.sha256).digest())
    with pytest.raises(IdentityError):
        verify(f"{head}.{body}.{sig}", CFG)


def test_misconfigured_is_an_error_not_a_pass():
    with pytest.raises(IdentityError):
        verify(tok(), {"mode": "require", "issuer": ISS, "jwks_uri": JWKS})  # no audience


ASSERTED = Subject(user_id="carol", source="explicit")
DEVICE = Subject(user_id="dev@acme", source="device")


def test_require_blocks_missing_and_invalid_tokens():
    _, status, finding = apply(ASSERTED, None, CFG, surface="eval-server")
    assert status == "missing" and finding["ruleId"] == "identity-unverified"
    _, status, finding = apply(ASSERTED, "garbage", CFG, surface="eval-server")
    assert status.startswith("invalid") and finding is not None


def test_observe_tags_but_never_blocks():
    cfg = {**CFG, "mode": "observe"}
    subject, status, finding = apply(ASSERTED, None, cfg, surface="eval-server")
    assert (subject, status, finding) == (ASSERTED, "missing", None)


def test_device_identity_counts_only_on_its_own_hook():
    assert apply(DEVICE, None, CFG, surface="hook")[2] is None
    # The same device fallback under an SDK/eval-server proves nothing about
    # the end user being served.
    assert apply(DEVICE, None, CFG, surface="eval-server")[2] is not None


def test_valid_token_overrides_asserted_subject():
    subject, status, finding = apply(Subject(user_id="mallory", source="explicit"),
                                     tok(), CFG, surface="eval-server")
    assert (subject.user_id, status, finding) == ("carol", "verified", None)


def test_effective_config_off_and_precedence():
    assert identity_token.effective_config({"mode": "off", **{k: v for k, v in CFG.items() if k != "mode"}}) is None
    assert identity_token.effective_config({}) is None
    identity_token.set_server_config({**CFG, "mode": "observe"})
    assert identity_token.effective_config({})["mode"] == "observe"
    assert identity_token.effective_config(CFG)["mode"] == "require"  # signed policy wins


# ── end to end through evaluate_tool_call ─────────────────────────────────

_REFUND = {
    "id": "refund-cap", "severity": "HIGH", "category": "custom-authz",
    "title": "Large refunds need finance", "event_types": ["shell"],
    "fields": ["tool_name"], "patterns": ["^refund_order$"], "action": "block",
    "mode": "enforce", "when": "args.amount >= 500 and 'finance' not in principal.roles",
}


@pytest.fixture
def ws(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("PRISMOR_SUBJECT", raising=False)
    (tmp_path / ".prismor").mkdir()
    (tmp_path / ".prismor" / "policy.yaml").write_text(
        yaml.safe_dump({"version": "1.0", "rules": [_REFUND]}))
    return tmp_path


def _call(ws, subject=None, token=None, amount=900):
    from prismor.runtime.runtime import evaluate_tool_call
    event = {"type": "shell", "agent_event": "PreToolUse", "command": str(amount),
             "metadata": {"tool_name": "refund_order", "kwargs": {"amount": amount},
                          "surface": "eval-server"}}
    return evaluate_tool_call(event=event, workspace=ws, agent="sdk", persist=False,
                              register_agent=False, flush_at_exit=False,
                              subject=subject, identity_token=token)


def test_e2e_no_identity_configured_is_unchanged(ws):
    assert _call(ws, Subject(user_id="carol", source="explicit")).allow is False  # no roles
    assert _call(ws, amount=10).allow is True


def test_e2e_role_from_verified_token_allows(ws):
    identity_token.set_server_config(CFG)
    assert _call(ws, token=tok()).allow is True
    assert _call(ws, token=tok(groups=["support"])).allow is False
    d = _call(ws, Subject(user_id="carol", source="explicit"))
    assert d.allow is False and d.rule_id == "identity-unverified"


def test_e2e_use_subject_token(ws):
    identity_token.set_server_config(CFG)
    with use_subject(token=tok()):
        assert _call(ws).allow is True


def test_identity_from_project_layer_is_ignored(ws, capsys):
    pol = yaml.safe_load((ws / ".prismor" / "policy.yaml").read_text())
    pol["settings"] = {"identity": CFG}
    (ws / ".prismor" / "policy.yaml").write_text(yaml.safe_dump(pol))
    from prismor.runtime.policy_engine import PolicyEngine
    assert PolicyEngine(workspace=ws).identity == {}
    # ...so a call with no token is not blocked for identity.
    assert _call(ws, amount=10).allow is True


def test_user_exemption_needs_verified_subject_when_identity_on():
    from prismor.runtime.runtime import _apply_rule_exemptions
    findings = [{"ruleId": "refund-cap", "category": "custom-authz"}]
    ex = [{"ruleId": "refund-cap", "scope": "user", "scopeId": "carol", "action": "allow"}]
    asserted = Subject(user_id="carol", source="explicit")
    verified = Subject(user_id="carol", source="jwt", verified=True)
    kw = dict(session_id="s", verified_users_only=True, surface="eval-server")
    assert _apply_rule_exemptions(findings, ex, session_id="s", subject=asserted) == []
    assert _apply_rule_exemptions(findings, ex, subject=asserted, **kw) == findings
    assert _apply_rule_exemptions(findings, ex, subject=verified, **kw) == []


def test_identity_sig_matches_server_format(monkeypatch):
    import hashlib
    from prismor.runtime.enterprise import remote_policy
    block = {"mode": "require", "issuer": ISS, "audience": [AUD], "jwks_uri": JWKS}
    monkeypatch.setattr(remote_policy, "verify_and_load", lambda: {"settings": {"identity": block}})
    want = hashlib.sha256(json.dumps(block, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:16]
    assert remote_policy._current_identity_sig() == want
    monkeypatch.setattr(remote_policy, "verify_and_load", lambda: {"settings": {}})
    assert remote_policy._current_identity_sig() == ""


def test_nested_and_namespaced_claims():
    cfg = {**CFG, "user_claim": "preferred_username", "roles_claim": "realm_access.roles",
           "team_claim": "https://acme.com/team"}
    s = verify(tok(preferred_username="carol.k", realm_access={"roles": ["finance"]},
                   **{"https://acme.com/team": "fin"}), cfg)
    assert (s.user_id, s.team_id, s.roles) == ("carol.k", "fin", ("finance",))
