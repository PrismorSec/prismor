"""``prismor hosted-proxy connect``: put an app behind the hosted proxy from a terminal.

Built for coding agents: run on an org admin's enrolled machine, it creates an
agent key, stores the app's provider key (and endpoint) with Prismor, and
rewrites the app's own env file in place. The agent never reads or prints the
provider key, and the app keeps its variable names:

    prismor hosted-proxy connect support-bot --env-file .env \\
        --base-env OPENROUTER_BASE_URL --key-env OPENROUTER_API_KEY

Before:  OPENROUTER_BASE_URL=https://openrouter.ai/api/v1   OPENROUTER_API_KEY=<provider key>
After:   OPENROUTER_BASE_URL=https://proxy.prismor.dev/v1   OPENROUTER_API_KEY=<agent key>
"""
from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlsplit

from prismor.runtime.http_ua import user_agent

#: Provider hosts the proxy knows natively; any other endpoint is "custom" (OpenAI-compatible).
_NATIVE = {
    "api.openai.com": "openai",
    "api.anthropic.com": "anthropic",
    "generativelanguage.googleapis.com": "gemini",
}
_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$")


def read_env(text: str) -> Dict[str, str]:
    out = {}
    for line in text.splitlines():
        m = _LINE.match(line)
        if m and not line.lstrip().startswith("#"):
            v = m.group(2)
            if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
                v = v[1:-1]
            out[m.group(1)] = v
    return out


def set_env(text: str, values: Dict[str, str]) -> str:
    """Replace each NAME=... line in place (keeping an ``export``), append the ones missing."""
    lines: List[str] = text.splitlines()
    done = set()
    for i, line in enumerate(lines):
        m = _LINE.match(line)
        if m and m.group(1) in values and not line.lstrip().startswith("#"):
            prefix = "export " if line.lstrip().startswith("export ") else ""
            lines[i] = f"{prefix}{m.group(1)}={values[m.group(1)]}"
            done.add(m.group(1))
    lines += [f"{k}={v}" for k, v in values.items() if k not in done]
    return "\n".join(lines) + "\n"


def pick_provider(endpoint: Optional[str], provider: Optional[str]) -> Tuple[str, Optional[str]]:
    """(provider, custom endpoint or None). A known provider host needs no endpoint stored."""
    if endpoint:
        host = (urlsplit(endpoint).hostname or "").lower()
        if host in _NATIVE:
            return _NATIVE[host], None
        return "custom", endpoint.rstrip("/")
    return provider or "openai", None


def app_base_url(proxy_url: str, provider: str) -> str:
    """What the app's base-URL variable becomes: OpenAI-style clients expect the /v1."""
    return proxy_url.rstrip("/") + ("/v1" if provider in ("openai", "custom") else "")


def _fail(msg: str, code: int = 1) -> None:
    print(msg, file=sys.stderr)
    sys.exit(code)


def connect(name: str, env_file: Optional[str], base_env: str, key_env: str,
            endpoint: Optional[str], provider: Optional[str]) -> None:
    from prismor.runtime.enterprise import identity as _identity

    ident = _identity.load_identity()
    if not ident:
        _fail("This machine is not enrolled with an org. Enroll it (prismor enroll <token>), "
              "or create the agent in the console: Agents → Connect an agent → Hosted proxy.")
    if _identity.revoked_info():
        _fail("This device was removed from its org. Re-link it with: prismor enroll <token>")

    path = Path(env_file) if env_file else None
    text = path.read_text(encoding="utf-8") if path and path.exists() else ""
    # The app's file only: a key in this shell may not be the app's.
    env = read_env(text) if path else dict(os.environ)
    endpoint = endpoint or env.get(base_env) or None
    upstream_key = env.get(key_env) or ""
    if upstream_key.startswith("prism_"):
        _fail(f"{key_env} already holds a Prismor key; this app looks connected already.")
    provider, custom = pick_provider(endpoint, provider)

    body = {"label": name}
    if upstream_key:
        body.update({"provider": provider, "key": upstream_key})
        if custom:
            body["baseUrl"] = custom
    base = str(ident.get("api_base") or _identity.api_base()).rstrip("/")
    req = urllib.request.Request(
        f"{base}/api/devices/hosted-agent", data=json.dumps(body).encode(), method="POST",
        headers={"Content-Type": "application/json", "User-Agent": user_agent(),
                 "Authorization": f"Bearer {ident.get('device_key')}"})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:  # console URL from enrolment  # nosec B310
            out = json.loads(resp.read().decode() or "{}")
    except urllib.error.HTTPError as exc:
        try:
            detail = json.loads(exc.read().decode() or "{}").get("message") or ""
        except Exception:
            detail = ""
        if exc.code == 404 and not detail:
            _fail("Your org's Prismor console does not support this yet; use Agents → Connect an agent → Hosted proxy.")
        _fail(f"Could not create the agent ({exc.code}): {detail or exc.reason}")
    except (urllib.error.URLError, OSError, ValueError) as exc:
        _fail(f"Could not reach the Prismor console: {exc}")

    key, proxy_url = out["key"], out["proxyUrl"]
    new = {base_env: app_base_url(proxy_url, provider), key_env: key}
    where = custom or endpoint or provider
    print(f"Created agent key “{out['label']}” for {where}.")
    if upstream_key:
        print(f"Prismor now holds the {provider if not custom else 'endpoint'} key that was in {key_env}; "
              "the hosted proxy swaps it in, so the app only needs the agent key.")
    if path:
        if text:
            backup = path.with_name(path.name + ".before-prismor")
            backup.write_text(text, encoding="utf-8")
            os.chmod(backup, 0o600)
            print(f"Saved the previous file as {backup} (it still contains the old key).")
        path.write_text(set_env(text, new), encoding="utf-8")
        os.chmod(path, 0o600)
        print(f"Updated {path}: {base_env}={new[base_env]}, {key_env}=prism_agent_…{key[-4:]}")
    else:
        print("Set these in the app's environment (the key is shown once):")
        for k, v in new.items():
            print(f"  {k}={v}")
    if not upstream_key:
        print(f"No provider key found in {key_env}: the app must keep sending its own provider key "
              "and add the header X-Prismor-Key: <agent key>.")
    print("Restart the app; its calls now go through your org's policy. Blocked tool calls show under Sessions.")
