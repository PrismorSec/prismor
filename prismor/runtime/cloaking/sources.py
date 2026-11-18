"""Secret sources: fill the cloaking vault from a secret manager.

``prismor cloak add NAME --from-ref REF`` fetches the value from where the
team already keeps it and writes it into the vault like any other secret, so
every reader (the bash decloak hooks, the scrubbers, the read guards) works
unchanged. Only the reference is kept, in ``$PRISMOR_HOME/secret-sources.json``
-- never the value -- and ``prismor cloak sync`` fetches again after a
rotation.

Supported references:
  op://vault/item[/section]/field[?attribute=...]
      1Password, through the ``op`` CLI (desktop-app sign-in, or
      OP_SERVICE_ACCOUNT_TOKEN / Connect in the environment).
  okta-pam://<team>/<resource_group>/<project>/<secret_id>[#field]
      Okta Privileged Access, plain-text reveal. Needs
      PRISMOR_OKTA_PAM_URL (https://<org>.pam.okta.com), and a service
      user's PRISMOR_OKTA_PAM_KEY_ID / PRISMOR_OKTA_PAM_KEY_SECRET.
  agentcore://<region>/<workload_identity>/<api_key_provider>
      AWS Bedrock AgentCore Identity token vault (an API key credential
      provider), with the caller's AWS credentials. Needs boto3.
  vault://<mount>/<path>[#field]   (openbao://… for OpenBao)
      HashiCorp Vault or OpenBao, KV v2 or v1 (detected). VAULT_ADDR and
      VAULT_TOKEN (or ~/.vault-token); BAO_ADDR / BAO_TOKEN for openbao://.
      VAULT_NAMESPACE is sent when set. https, or http only to localhost.
  infisical://<project_id>/<environment>[/<folder>...]/<SECRET_NAME>
      Infisical. INFISICAL_TOKEN, or a machine identity's
      INFISICAL_UNIVERSAL_AUTH_CLIENT_ID / _CLIENT_SECRET. INFISICAL_API_URL
      for a self-hosted instance (default https://app.infisical.com).
  aws-sm://<region>/<secret_id>[#field]
      AWS Secrets Manager, with the caller's AWS credentials. Needs boto3.
      #field picks a key of a JSON secret.

The reference file is guarded like the vault's other config by
``prismor-self-edit``: whoever edits it chooses which real secret a
placeholder unlocks.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess  # runs the 1Password CLI.  # nosec B404
import urllib.error
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import quote, urlencode, urlsplit

from prismor.runtime.cloaking.secrets_store import _validate_name, add_secret

#: Seconds one fetch may take. A locked 1Password app waits for a biometric
#: prompt; past this the fetch fails rather than hang the terminal.
TIMEOUT = float(os.environ.get("PRISMOR_SECRET_SOURCE_TIMEOUT", "20"))

SCHEMES = ("op://", "okta-pam://", "agentcore://", "vault://", "openbao://", "infisical://", "aws-sm://")


class SourceError(Exception):
    """A reference that could not be fetched. The message never holds the value."""


class _HTTPStatus(SourceError):
    def __init__(self, message: str, code: int) -> None:
        super().__init__(message)
        self.code = code


def sources_file() -> Path:
    return Path(os.environ.get("PRISMOR_HOME", Path.home() / ".prismor")) / "secret-sources.json"


def load_sources() -> Dict[str, Dict[str, str]]:
    try:
        data = json.loads(sources_file().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _save_sources(data: Dict[str, Dict[str, str]]) -> None:
    path = sources_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def check_ref(ref: str) -> str:
    ref = ref.strip()
    if not ref.startswith(SCHEMES):
        raise SourceError(f"unsupported reference {ref!r}: use one of {', '.join(SCHEMES)}")
    return ref


# ── backends ────────────────────────────────────────────────────────────────

def _fetch_1password(ref: str) -> str:
    op = shutil.which("op")
    if not op:
        raise SourceError("the 1Password CLI (op) is not installed")
    try:
        # -n: no trailing newline. Never --out-file: the value must not land on disk.
        proc = subprocess.run([op, "read", "-n", ref], capture_output=True, text=True,  # nosec B603
                              timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        raise SourceError(f"1Password did not answer within {TIMEOUT:g}s (is the app locked?)")
    if proc.returncode != 0:
        raise SourceError(f"op read failed: {proc.stderr.strip()[:300] or 'exit ' + str(proc.returncode)}")
    return proc.stdout


def _post_json(url: str, body: Optional[Dict[str, object]], token: str = "",
               headers: Optional[Dict[str, str]] = None) -> Dict[str, object]:
    """POST ``body`` as JSON, or GET when ``body`` is None."""
    from prismor.runtime.http_ua import user_agent
    req = urllib.request.Request(url, data=None if body is None else json.dumps(body).encode(),
                                 method="GET" if body is None else "POST",
                                 headers={"Content-Type": "application/json", "Accept": "application/json",
                                          "User-Agent": user_agent(),
                                          **({"Authorization": f"Bearer {token}"} if token else {}),
                                          **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:  # nosec B310 - https URL from config
            return json.loads(resp.read().decode() or "{}")
    except urllib.error.HTTPError as exc:
        # Only the status: an error body could echo request fields.
        raise _HTTPStatus(f"{url.split('?')[0]} returned HTTP {exc.code}", exc.code)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise SourceError(f"could not reach {url.split('/v1/')[0]}: {getattr(exc, 'reason', exc)}")
    except ValueError:
        raise SourceError(f"{url.split('?')[0]} did not return JSON")


def _fetch_okta_pam(ref: str) -> str:
    body, _, field = ref[len("okta-pam://"):].partition("#")
    parts = body.strip("/").split("/")
    if len(parts) != 4 or not all(parts):
        raise SourceError("okta-pam reference must be okta-pam://<team>/<resource_group>/<project>/<secret_id>[#field]")
    team, group, project, secret_id = (quote(p, safe="") for p in parts)
    base = os.environ.get("PRISMOR_OKTA_PAM_URL", "").rstrip("/")
    key_id, key_secret = os.environ.get("PRISMOR_OKTA_PAM_KEY_ID", ""), os.environ.get("PRISMOR_OKTA_PAM_KEY_SECRET", "")
    if not base.startswith("https://") or not key_id or not key_secret:
        raise SourceError("set PRISMOR_OKTA_PAM_URL (https://<org>.pam.okta.com), PRISMOR_OKTA_PAM_KEY_ID and PRISMOR_OKTA_PAM_KEY_SECRET")
    token = _post_json(f"{base}/v1/teams/{team}/service_token", {"key_id": key_id, "key_secret": key_secret}).get("bearer_token")
    if not isinstance(token, str) or not token:
        raise SourceError("Okta Privileged Access returned no bearer token")
    out = _post_json(f"{base}/v1/teams/{team}/resource_groups/{group}/projects/{project}/secrets/{secret_id}",
                     {"use_plain_text": True}, token)
    values = out.get("plain_text")
    if not isinstance(values, dict) or not values:
        raise SourceError("Okta Privileged Access returned no plain-text secret (is plain-text reveal allowed for this user?)")
    return _pick(values, field)


def _fetch_agentcore(ref: str) -> str:
    parts = ref[len("agentcore://"):].strip("/").split("/")
    if len(parts) != 3 or not all(parts):
        raise SourceError("agentcore reference must be agentcore://<region>/<workload_identity>/<api_key_provider>")
    region, workload, provider = parts
    try:
        import boto3
        from botocore.config import Config
        from botocore.exceptions import BotoCoreError, ClientError
    except ImportError:
        raise SourceError("agentcore references need boto3 (pip install boto3)")
    client = boto3.client("bedrock-agentcore", region_name=region,
                          config=Config(connect_timeout=5, read_timeout=TIMEOUT, retries={"max_attempts": 2}))
    try:
        token = client.get_workload_access_token(workloadName=workload)["workloadAccessToken"]
        return client.get_resource_api_key(resourceCredentialProviderName=provider,
                                           workloadIdentityToken=token)["apiKey"]
    except ClientError as exc:
        err = exc.response.get("Error", {})
        raise SourceError(f"AgentCore {exc.operation_name}: {err.get('Code', 'error')} {err.get('Message', '')[:200]}".rstrip())
    except BotoCoreError as exc:
        # Expired SSO sessions and missing credentials land here, before any call.
        raise SourceError(f"AWS credentials: {exc}")


def _pick(values: Dict[str, object], field: str) -> str:
    if field:
        if field not in values:
            raise SourceError(f"secret has no field {field!r} (fields: {', '.join(sorted(values))})")
        return str(values[field])
    if len(values) > 1:
        raise SourceError(f"secret has several fields, pick one with #field ({', '.join(sorted(values))})")
    return str(next(iter(values.values())))


def _safe_base(url: str, var: str) -> str:
    """https, or plain http only to this machine: a token must not cross a network in clear."""
    url = url.strip().rstrip("/")
    parts = urlsplit(url)
    if parts.scheme == "https" and parts.hostname:
        return url
    if parts.scheme == "http" and parts.hostname in ("127.0.0.1", "localhost", "::1"):
        return url
    raise SourceError(f"set {var} to an https:// address (http:// only for localhost)")


def _fetch_vault(ref: str) -> str:
    bao = ref.startswith("openbao://")
    body, _, field = ref.split("://", 1)[1].partition("#")
    parts = [p for p in body.strip("/").split("/") if p]
    if len(parts) < 2:
        raise SourceError("vault reference must be vault://<mount>/<path>[#field]")
    mount, path = quote(parts[0], safe=""), "/".join(quote(p, safe="") for p in parts[1:])
    env = (lambda b, v: os.environ.get(b) or os.environ.get(v, "")) if bao else (lambda b, v: os.environ.get(v, ""))
    addr_var = "BAO_ADDR" if bao else "VAULT_ADDR"
    if not env("BAO_ADDR", "VAULT_ADDR"):
        raise SourceError(f"set {addr_var} to your {'OpenBao' if bao else 'Vault'} address")
    base = _safe_base(env("BAO_ADDR", "VAULT_ADDR"), addr_var)
    token = env("BAO_TOKEN", "VAULT_TOKEN")
    if not token:
        try:  # what `vault login` / `bao login` leave behind
            token = (Path.home() / ".vault-token").read_text(encoding="utf-8").strip()
        except OSError:
            token = ""
    if not token:
        raise SourceError(f"set {'BAO_TOKEN' if bao else 'VAULT_TOKEN'} (or run `{'bao' if bao else 'vault'} login`)")
    headers = {"X-Vault-Token": token}
    if env("BAO_NAMESPACE", "VAULT_NAMESPACE"):
        headers["X-Vault-Namespace"] = env("BAO_NAMESPACE", "VAULT_NAMESPACE")
    first = None
    try:  # KV v2 keeps the value under data.data
        out = _post_json(f"{base}/v1/{mount}/data/{path}", None, headers=headers)
        data = out.get("data")
        values = data.get("data") if isinstance(data, dict) else None
    except _HTTPStatus as exc:
        if exc.code not in (403, 404):
            raise
        first, values = exc, None
    if not isinstance(values, dict):  # KV v1 (or a v2 path the token cannot read)
        try:
            out = _post_json(f"{base}/v1/{mount}/{path}", None, headers=headers)
        except _HTTPStatus:
            raise first or SourceError("the secret was not found") from None  # v2 error says more
        values = out.get("data")
    if not isinstance(values, dict) or not values:
        raise SourceError("the secret has no data (deleted, or not a KV secret)")
    return _pick(values, field)


def _fetch_infisical(ref: str) -> str:
    parts = [p for p in ref[len("infisical://"):].strip("/").split("/") if p]
    if len(parts) < 3:
        raise SourceError("infisical reference must be infisical://<project_id>/<environment>[/<folder>...]/<SECRET_NAME>")
    project, environment, name = parts[0], parts[1], parts[-1]
    folder = "/" + "/".join(parts[2:-1])
    base = _safe_base(os.environ.get("INFISICAL_API_URL") or "https://app.infisical.com", "INFISICAL_API_URL")
    if base.endswith("/api"):
        base = base[:-4]
    token = os.environ.get("INFISICAL_TOKEN", "")
    if not token:
        cid = os.environ.get("INFISICAL_UNIVERSAL_AUTH_CLIENT_ID", "")
        secret = os.environ.get("INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET", "")
        if not cid or not secret:
            raise SourceError("set INFISICAL_TOKEN, or INFISICAL_UNIVERSAL_AUTH_CLIENT_ID and "
                              "INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET (a machine identity)")
        token = _post_json(f"{base}/api/v1/auth/universal-auth/login",
                           {"clientId": cid, "clientSecret": secret}).get("accessToken") or ""
        if not isinstance(token, str) or not token:
            raise SourceError("Infisical returned no access token")
    query = urlencode({"workspaceId": project, "environment": environment, "secretPath": folder})
    out = _post_json(f"{base}/api/v3/secrets/raw/{quote(name, safe='')}?{query}", None, token)
    secret_obj = out.get("secret")
    value = secret_obj.get("secretValue") if isinstance(secret_obj, dict) else None
    if not isinstance(value, str):
        raise SourceError("Infisical returned no secret value")
    return value


def _fetch_aws_sm(ref: str) -> str:
    body, _, field = ref[len("aws-sm://"):].partition("#")
    region, _, secret_id = body.strip("/").partition("/")
    if not region or not secret_id:
        raise SourceError("aws-sm reference must be aws-sm://<region>/<secret_id>[#field]")
    try:
        import boto3
        from botocore.config import Config
        from botocore.exceptions import BotoCoreError, ClientError
    except ImportError:
        raise SourceError("aws-sm references need boto3 (pip install boto3)")
    # AWS_ENDPOINT_URL_SECRETS_MANAGER (boto3's own variable) points it elsewhere.
    client = boto3.client("secretsmanager", region_name=region,
                          config=Config(connect_timeout=5, read_timeout=TIMEOUT, retries={"max_attempts": 2}))
    try:
        out = client.get_secret_value(SecretId=secret_id)
    except ClientError as exc:
        err = exc.response.get("Error", {})
        raise SourceError(f"Secrets Manager {err.get('Code', 'error')}: {err.get('Message', '')[:200]}".rstrip())
    except BotoCoreError as exc:
        raise SourceError(f"AWS credentials: {exc}")
    value = out.get("SecretString")
    if value is None:
        raise SourceError("binary secrets are not supported; store the value as a string")
    try:
        parsed = json.loads(value)
    except ValueError:
        parsed = None
    if isinstance(parsed, dict) and parsed:
        return _pick(parsed, field)
    if field:
        raise SourceError(f"#{field} needs a JSON secret; this one is a plain string")
    return value


def fetch(ref: str) -> str:
    """The value a reference points at. Raises SourceError; never logs the value."""
    ref = check_ref(ref)
    if ref.startswith("op://"):
        value = _fetch_1password(ref)
    elif ref.startswith("okta-pam://"):
        value = _fetch_okta_pam(ref)
    elif ref.startswith(("vault://", "openbao://")):
        value = _fetch_vault(ref)
    elif ref.startswith("infisical://"):
        value = _fetch_infisical(ref)
    elif ref.startswith("aws-sm://"):
        value = _fetch_aws_sm(ref)
    else:
        value = _fetch_agentcore(ref)
    if not value:
        raise SourceError("the source returned an empty value")
    return value


# ── vault operations ────────────────────────────────────────────────────────

def add_from_ref(name: str, ref: str) -> Path:
    """Fetch ``ref`` into the vault as ``name`` and remember where it came from."""
    _validate_name(name)
    if ref.strip().startswith("prismor://"):
        raise SourceError("prismor:// secrets come from your org console; an admin adds them there")
    ref = check_ref(ref)
    path = add_secret(name, fetch(ref))
    data = load_sources()
    data[name] = {"ref": ref}
    _save_sources(data)
    return path


def sync(names: Optional[List[str]] = None) -> List[Dict[str, str]]:
    """Fetch every sourced secret (or ``names``) again. A failed fetch keeps
    the vaulted value and is reported, so one locked source never empties the
    vault. Returns ``{"name", "status": updated|unchanged|error|unknown, "error"?}``."""
    from prismor.runtime.cloaking.secrets_store import secrets_dir

    data = load_sources()
    out: List[Dict[str, str]] = []
    for name in (names or sorted(data)):
        entry = data.get(name)
        if not entry:
            out.append({"name": name, "status": "unknown", "error": "not added with --from-ref"})
            continue
        if str(entry.get("ref", "")).startswith("prismor://"):
            continue  # the org vault; managed.sync() handles these
        try:
            value = fetch(entry["ref"])
        except SourceError as exc:
            out.append({"name": name, "status": "error", "error": str(exc)})
            continue
        try:
            current = (secrets_dir() / name).read_text(encoding="utf-8")
        except OSError:
            current = None
        if current == value:
            out.append({"name": name, "status": "unchanged"})
        else:
            add_secret(name, value)
            out.append({"name": name, "status": "updated"})
    return out


def forget(name: str) -> None:
    """Drop the reference when the secret is removed."""
    data = load_sources()
    if data.pop(name, None) is not None:
        _save_sources(data)
