"""Per-workspace scoping — managed (org-governed) vs local-only (personal).

The privacy/UX model that lets Immunity not hinder developers while keeping
security followed:

* **Local protection is always on.** Every workspace gets Prismor's default +
  project policy — destructive commands, secret exfiltration, etc. are blocked
  locally regardless of scope. A developer can NOT turn the security floor off by
  calling a repo "personal".
* **The org claims its repos by pattern** (e.g. ``github.com/acme/*``), served in
  the signed org policy. A workspace whose git remote matches a claimed pattern
  is **org-managed**: org telemetry flows and the org policy overlay applies, and
  the developer cannot downgrade it — company/client code stays governed.
* **Everything else is the developer's personal space** — **local-only**: Prismor
  still protects them, but nothing is reported to any org and no org policy
  applies. A developer may explicitly opt a non-claimed repo into managed.

Concretely, "managed" gates two things at the runtime: the org policy overlay
merge (see policy_engine) — which also carries the org telemetry sink — and the
per-call heartbeat (see cli hook-dispatch). Personal workspaces therefore emit
no findings, no volume, and apply no org policy; the org never sees them.

**Deployed workloads.** Scope is inferred from the git remote, which a container
or CI runner does not have. With no remote and an org that claims patterns, such
a workspace falls through to local — correct for a laptop, silently wrong for a
production agent that reports nothing and says so nowhere. ``PRISMOR_WORKSPACE_SCOPE``
settles it explicitly (``managed`` | ``personal``) for exactly that case: it is
read from the environment, so it needs no writable ``$PRISMOR_HOME``, and it is
ranked below an org-claimed pattern — a deployment cannot use it to downgrade a
repo the org claims.
"""
from __future__ import annotations

import fnmatch
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from prismor.runtime.enterprise import identity as _identity


def detect_git_remote(workspace: Path) -> Optional[str]:
    """Return the normalized origin remote of ``workspace`` as ``host/owner/repo``
    (lowercased), or None if not a git repo / no origin. Walks up a few levels so
    a hook firing in a subdirectory still resolves the repo."""
    d = workspace
    for _ in range(8):
        cfg = d / ".git" / "config"
        if cfg.exists():
            try:
                text = cfg.read_text(encoding="utf-8", errors="replace")
            except OSError:
                return None
            m = re.search(r'\[remote "origin"\][^\[]*?url\s*=\s*(\S+)', text)
            return _normalize_remote(m.group(1)) if m else None
        if d.parent == d:
            break
        d = d.parent
    return None


def _normalize_remote(url: str) -> Optional[str]:
    url = url.strip().rstrip("/")
    if url.endswith(".git"):
        url = url[:-4]
    # git@github.com:acme/repo  ·  https://github.com/acme/repo  ·  ssh://git@host/acme/repo
    m = re.match(r"(?:git@|https?://|ssh://(?:git@)?)([^/:]+)[:/](.+)", url)
    if m:
        return f"{m.group(1).lower()}/{m.group(2).lower()}"
    return None


def _overrides_path() -> Path:
    return _identity.prismor_home() / "workspace-scopes.json"


def _load_overrides() -> Dict[str, str]:
    try:
        data = json.loads(_overrides_path().read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def set_override(workspace: Path, scope: Optional[str]) -> None:
    """Set a developer override for a workspace: 'managed' (opt-in), 'personal'
    (opt-out, only honored for non-claimed repos), or None to clear. Never
    raises on the happy path."""
    ov = _load_overrides()
    key = str(workspace.resolve())
    if scope is None:
        ov.pop(key, None)
    else:
        ov[key] = scope
    try:
        p = _overrides_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(ov, indent=2), encoding="utf-8")
    except OSError:
        pass


def _org_settings() -> Dict[str, Any]:
    """``settings`` block of the *verified* signed remote policy, or {}."""
    try:
        from prismor.runtime.enterprise import remote_policy as _remote
        pol = _remote.verify_and_load()
        if pol:
            return pol.get("settings") or {}
    except Exception:
        pass
    return {}


def org_managed_patterns() -> List[str]:
    """The org's claimed-repo glob patterns (settings.managed_repo_patterns).
    Empty if not enrolled / no policy — which means nothing is auto-managed."""
    pats = _org_settings().get("managed_repo_patterns")
    if isinstance(pats, list):
        return [str(p) for p in pats if p]
    return []


def org_allows_personal() -> bool:
    """``settings.allow_personal_workspaces`` (default True). When the org sets
    it False, every workspace on an enrolled device is managed: the personal
    override, PRISMOR_WORKSPACE_SCOPE=personal, and the non-claimed-repo default
    are all ignored. This is the only way to close the scope-is-the-git-remote
    hole — a developer can always rewrite or drop ``origin`` to dodge a claimed
    pattern, so orgs that need full coverage must disable personal space."""
    # A system install is the machine's admin deciding for every user, so no
    # user can declare a workspace personal and step outside org policy.
    from prismor.runtime import system_install as _si
    if _si.is_system_managed():
        return False
    return _org_settings().get("allow_personal_workspaces", True) is not False


def _matches(remote: str, pattern: str) -> bool:
    pattern = pattern.strip().lower().rstrip("/")
    if pattern.endswith(".git"):
        pattern = pattern[:-4]
    if not pattern:
        return False
    # Match against the full host/owner/repo and also the host-less owner/repo,
    # so a pattern like "acme/*" works without specifying the host.
    return fnmatch.fnmatch(remote, pattern) or fnmatch.fnmatch(remote.split("/", 1)[-1], pattern)


def _env_scope() -> Optional[str]:
    """``PRISMOR_WORKSPACE_SCOPE`` — explicit scope for repo-less workloads.

    ``managed`` (org policy + telemetry apply) or ``personal``/``local`` (opt
    out). Anything else is ignored rather than raising: a typo in a container
    env must not take the runtime down.
    """
    val = str(os.environ.get("PRISMOR_WORKSPACE_SCOPE", "")).strip().lower()
    if val == "managed":
        return "managed"
    if val in ("personal", "local"):
        return "personal"
    return None


def resolve_scope(workspace: Path) -> Dict[str, Any]:
    """Classify a workspace. Returns {scope: 'managed'|'local', reason, remote,
    org_id}. Decision order:
      1. not enrolled → local (nothing to report to).
      2. remote matches an org-claimed pattern → managed, FORCED (a developer
         cannot downgrade a company/client repo).
      3. org set settings.allow_personal_workspaces=false → managed, FORCED
         (no personal space on this device at all; closes the rewrite-the-
         remote bypass for orgs that need it).
      4. PRISMOR_WORKSPACE_SCOPE env override for a non-claimed workspace →
         honored (the deployed-workload path: no git remote, no writable home).
      5. developer override (opt-in 'managed' / opt-out 'personal') for a
         non-claimed repo → honored.
      6. default: if the org has claimed NO patterns, manage everything
         (backward-compatible "cover all dev machines"); if the org HAS claimed
         patterns, a non-matching repo is the developer's personal space.
    """
    ident = _identity.load_identity() or _identity.keyless_identity()
    remote = detect_git_remote(workspace)
    if not ident:
        return {"scope": "local", "reason": "not_enrolled", "remote": remote, "org_id": None}
    if _identity.revoked_info():
        return {"scope": "local", "reason": "revoked", "remote": remote, "org_id": None}

    org_id = ident.get("org_id")
    patterns = org_managed_patterns()

    if remote:
        for pat in patterns:
            if _matches(remote, pat):
                return {"scope": "managed", "reason": "org_claimed", "remote": remote, "org_id": org_id, "pattern": pat}

    if not org_allows_personal():
        return {"scope": "managed", "reason": "org_no_personal", "remote": remote, "org_id": org_id}

    env_scope = _env_scope()
    if env_scope == "managed":
        return {"scope": "managed", "reason": "env_override", "remote": remote, "org_id": org_id}
    if env_scope == "personal":
        return {"scope": "local", "reason": "env_opt_out", "remote": remote, "org_id": None}

    override = _load_overrides().get(str(workspace.resolve()))
    if override == "managed":
        return {"scope": "managed", "reason": "opt_in", "remote": remote, "org_id": org_id}
    if override == "personal":
        return {"scope": "local", "reason": "opt_out", "remote": remote, "org_id": None}

    if not patterns:
        # Org hasn't configured scoping → manage everything (legacy behavior).
        return {"scope": "managed", "reason": "default_all", "remote": remote, "org_id": org_id}
    # Org scopes to specific repos → this non-matching one is personal.
    return {"scope": "local", "reason": "personal", "remote": remote, "org_id": None}


def is_managed(workspace: Optional[Path]) -> bool:
    """True if org telemetry + org policy should apply to this workspace."""
    if workspace is None:
        return False
    try:
        return resolve_scope(workspace).get("scope") == "managed"
    except Exception:
        return False
