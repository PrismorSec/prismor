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
from urllib.parse import quote

from prismor.runtime.cloaking.secrets_store import _validate_name, add_secret

#: Seconds one fetch may take. A locked 1Password app waits for a biometric
#: prompt; past this the fetch fails rather than hang the terminal.
TIMEOUT = float(os.environ.get("PRISMOR_SECRET_SOURCE_TIMEOUT", "20"))

SCHEMES = ("op://", "okta-pam://", "agentcore://")


class SourceError(Exception):
    """A reference that could not be fetched. The message never holds the value."""


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


def _post_json(url: str, body: Dict[str, object], token: str = "") -> Dict[str, object]:
    from prismor.runtime.http_ua import user_agent
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "Accept": "application/json",
                                          "User-Agent": user_agent(),
                                          **({"Authorization": f"Bearer {token}"} if token else {})})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:  # nosec B310 - https URL from config
            return json.loads(resp.read().decode() or "{}")
    except urllib.error.HTTPError as exc:
        # Only the status: an error body could echo request fields.
        raise SourceError(f"{url.split('?')[0]} returned HTTP {exc.code}")
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
    if field:
        if field not in values:
            raise SourceError(f"secret has no field {field!r} (fields: {', '.join(sorted(values))})")
        return str(values[field])
    if len(values) > 1:
        raise SourceError(f"secret has several fields, pick one with #field ({', '.join(sorted(values))})")
    return str(next(iter(values.values())))


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


def fetch(ref: str) -> str:
    """The value a reference points at. Raises SourceError; never logs the value."""
    ref = check_ref(ref)
    if ref.startswith("op://"):
        value = _fetch_1password(ref)
    elif ref.startswith("okta-pam://"):
        value = _fetch_okta_pam(ref)
    else:
        value = _fetch_agentcore(ref)
    if not value:
        raise SourceError("the source returned an empty value")
    return value


# ── vault operations ────────────────────────────────────────────────────────

def add_from_ref(name: str, ref: str) -> Path:
    """Fetch ``ref`` into the vault as ``name`` and remember where it came from."""
    _validate_name(name)
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
