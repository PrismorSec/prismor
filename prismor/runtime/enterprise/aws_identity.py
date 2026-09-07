"""AWS workload identity for enrollment — stdlib only.

A runtime on AWS (EC2, ECS/EKS task, Lambda) already holds IAM role
credentials. Instead of a shared enrollment token it proves *which role it is*
by SigV4-signing an ``sts:GetCallerIdentity`` request and handing the signed
request (not the credentials) to the control plane, which replays it to STS.

Two extra headers are folded into the signature so a captured request is
useless anywhere else: ``X-Prismor-Server-Id`` (the control-plane host) and
``X-Prismor-Org`` (the org the workload is enrolling into). STS ignores
unknown headers but the signature still covers them.

No boto, no ``cryptography``: ``hmac`` + ``hashlib`` + ``urllib``.
"""
from __future__ import annotations

import configparser
import datetime as _dt
import hashlib
import hmac
import json
import os
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, Optional

STS_BODY = "Action=GetCallerIdentity&Version=2011-06-15"
_IMDS = "http://169.254.169.254"
_ECS_RELATIVE_BASE = "http://169.254.170.2"


# ---------------------------------------------------------------------------
# Credential resolution: env → container → IMDSv2 → ~/.aws/credentials


def _get_json(url: str, headers: Optional[Dict[str, str]] = None, method: str = "GET",
              timeout: float = 1.0) -> Optional[Dict[str, Any]]:
    req = urllib.request.Request(url, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, OSError, ValueError):
        return None


def _get_text(url: str, headers: Optional[Dict[str, str]] = None, method: str = "GET",
              timeout: float = 1.0) -> Optional[str]:
    req = urllib.request.Request(url, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8")
    except (urllib.error.URLError, OSError):
        return None


def _from_env() -> Optional[Dict[str, str]]:
    ak = os.environ.get("AWS_ACCESS_KEY_ID")
    sk = os.environ.get("AWS_SECRET_ACCESS_KEY")
    if ak and sk:
        return {"access_key": ak, "secret_key": sk,
                "token": os.environ.get("AWS_SESSION_TOKEN") or ""}
    return None


def _from_container() -> Optional[Dict[str, str]]:
    """ECS task role / EKS pod identity credential endpoint."""
    url = os.environ.get("AWS_CONTAINER_CREDENTIALS_FULL_URI")
    rel = os.environ.get("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")
    if not url and rel:
        url = _ECS_RELATIVE_BASE + rel
    if not url:
        return None
    headers = {}
    tok = os.environ.get("AWS_CONTAINER_AUTHORIZATION_TOKEN")
    tok_file = os.environ.get("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE")
    if not tok and tok_file:
        try:
            tok = Path(tok_file).read_text(encoding="utf-8").strip()
        except OSError:
            tok = None
    if tok:
        headers["Authorization"] = tok
    return _shape(_get_json(url, headers))


def _from_imds() -> Optional[Dict[str, str]]:
    """IMDSv2 (token-required) instance role credentials."""
    token = _get_text(f"{_IMDS}/latest/api/token",
                      {"X-aws-ec2-metadata-token-ttl-seconds": "60"}, method="PUT")
    if not token:
        return None
    h = {"X-aws-ec2-metadata-token": token}
    role = _get_text(f"{_IMDS}/latest/meta-data/iam/security-credentials/", h)
    if not role:
        return None
    role = role.strip().splitlines()[0]
    return _shape(_get_json(f"{_IMDS}/latest/meta-data/iam/security-credentials/{role}", h))


def _from_profile() -> Optional[Dict[str, str]]:
    path = Path(os.environ.get("AWS_SHARED_CREDENTIALS_FILE") or Path.home() / ".aws" / "credentials")
    if not path.exists():
        return None
    cp = configparser.RawConfigParser()
    try:
        cp.read(path, encoding="utf-8")
    except (configparser.Error, OSError):
        return None
    prof = os.environ.get("AWS_PROFILE") or "default"
    if not cp.has_section(prof):
        return None
    ak = cp.get(prof, "aws_access_key_id", fallback=None)
    sk = cp.get(prof, "aws_secret_access_key", fallback=None)
    if not (ak and sk):
        return None
    return {"access_key": ak, "secret_key": sk, "token": cp.get(prof, "aws_session_token", fallback="") or ""}


def _shape(d: Optional[Dict[str, Any]]) -> Optional[Dict[str, str]]:
    if not d or not d.get("AccessKeyId") or not d.get("SecretAccessKey"):
        return None
    return {"access_key": str(d["AccessKeyId"]), "secret_key": str(d["SecretAccessKey"]),
            "token": str(d.get("Token") or "")}


def resolve_credentials() -> Optional[Dict[str, str]]:
    """Find role credentials the way the AWS SDKs do, minus the config-file role
    chains. Returns ``{access_key, secret_key, token}`` or None."""
    for src in (_from_env, _from_container, _from_imds, _from_profile):
        creds = src()
        if creds:
            return creds
    return None


# ---------------------------------------------------------------------------
# SigV4


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def signing_key(secret_key: str, date: str, region: str, service: str) -> bytes:
    """The four-step SigV4 derived key (date is YYYYMMDD)."""
    k = _hmac(("AWS4" + secret_key).encode("utf-8"), date)
    k = _hmac(k, region)
    k = _hmac(k, service)
    return _hmac(k, "aws4_request")


def sts_host(region: Optional[str]) -> str:
    return f"sts.{region}.amazonaws.com" if region else "sts.amazonaws.com"


def sign_get_caller_identity(creds: Dict[str, str], region: Optional[str], server_id: str,
                             org_id: str, now: Optional[_dt.datetime] = None) -> Dict[str, Any]:
    """Build a SigV4-signed ``sts:GetCallerIdentity`` request bound to
    ``server_id`` and ``org_id``. Returns ``{method, url, headers, body}``
    ready to be handed to the control plane."""
    now = now or _dt.datetime.now(_dt.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date = now.strftime("%Y%m%d")
    # STS is signed with the region in the credential scope; the global endpoint
    # takes us-east-1.
    scope_region = region or "us-east-1"
    host = sts_host(region)

    headers = {
        "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
        "Host": host,
        "X-Amz-Date": amz_date,
        "X-Prismor-Org": org_id,
        "X-Prismor-Server-Id": server_id,
    }
    if creds.get("token"):
        headers["X-Amz-Security-Token"] = creds["token"]

    lower = {k.lower(): " ".join(v.split()) for k, v in headers.items()}
    signed_names = sorted(lower)
    canonical_headers = "".join(f"{k}:{lower[k]}\n" for k in signed_names)
    signed_headers = ";".join(signed_names)
    canonical_request = "\n".join([
        "POST", "/", "", canonical_headers, signed_headers, _sha256_hex(STS_BODY.encode("utf-8")),
    ])
    scope = f"{date}/{scope_region}/sts/aws4_request"
    string_to_sign = "\n".join([
        "AWS4-HMAC-SHA256", amz_date, scope, _sha256_hex(canonical_request.encode("utf-8")),
    ])
    sig = hmac.new(signing_key(creds["secret_key"], date, scope_region, "sts"),
                   string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
    headers["Authorization"] = (
        f"AWS4-HMAC-SHA256 Credential={creds['access_key']}/{scope}, "
        f"SignedHeaders={signed_headers}, Signature={sig}"
    )
    return {"method": "POST", "url": f"https://{host}/", "headers": headers, "body": STS_BODY}
