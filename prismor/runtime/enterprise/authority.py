"""What an agent was permitted at the moment it acted (#943).

Each trail record carries ``authority_hash``: the sha256 of a compact snapshot
of the scope that applied - IAM profile (allow/deny tools), session scope,
agent control (incl. tools inherited from a parent agent), org subject
controls and pause, and the policy version + hash. Each distinct snapshot is
stored once under ``~/.prismor/audit/authority/<hash>.json``. The hash sits in
the record, so the chain and signature cover it; an edited snapshot no longer
matches its name.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Optional

_POLICY_HASH: Dict[tuple, Optional[str]] = {}


def _canon(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, default=str).encode("utf-8")


def digest(value: Any) -> str:
    return hashlib.sha256(_canon(value)).hexdigest()


def _dir() -> Path:
    from prismor.runtime.enterprise import audit_trail as _audit
    return _audit.audit_dir() / "authority"


def _policy_hash() -> Optional[str]:
    """sha256 of the cached signed org policy, memoised by mtime."""
    try:
        from prismor.runtime.enterprise import remote_policy as _rp
        path = _rp.cached_policy_path()
        key = (str(path), path.stat().st_mtime_ns)
    except Exception:
        return None
    if key not in _POLICY_HASH:
        try:
            _POLICY_HASH.clear()
            _POLICY_HASH[key] = hashlib.sha256(Path(key[0]).read_bytes()).hexdigest()
        except OSError:
            return None
    return _POLICY_HASH[key]


def _profile(name: Optional[str], config: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if not name:
        return None
    from prismor.runtime.iam import resolve_agent_profile
    prof = resolve_agent_profile(name, config) or {}
    keep = {k: prof.get(k) for k in ("allowed_tools", "deny_tools", "allowed_paths", "deny_network")
            if prof.get(k) is not None}
    if prof.get("__suspended__"):
        keep["suspended"] = True
    return {"id": name, **keep, "hash": digest(prof)}


def snapshot(*, workspace: Path, subject: Any = None, control: Any = None, engine: Any = None,
             session_id: str = "", parent_agent: Optional[str] = None) -> Dict[str, Any]:
    """Build the authority snapshot for one decision. Best-effort per part."""
    remote = getattr(engine, "subject_controls", None) or {}
    snap: Dict[str, Any] = {}
    try:
        from prismor.runtime.iam import _merge_remote_subject_controls, _resolve_identity, load_iam_config
        config = _merge_remote_subject_controls(load_iam_config(workspace), remote)
        own = _resolve_identity(config, subject) or getattr(control, "iam_profile", None)
        snap["iam_profile"] = _profile(own, config)
        parents = [_profile(p, config) for p in getattr(control, "parent_iam_profiles", ()) or ()]
        if parents:
            snap["parent_iam_profiles"] = parents
    except Exception:
        snap["iam_profile"] = None
    if control is not None:
        snap["agent_control"] = {
            "agent": control.name, "enabled": control.enabled,
            "mode": control.org_mode or control.mode,
            "deny_tools": sorted(control.deny_tools), "ask_tools": sorted(control.ask_tools),
            "disabled_by": control.disabled_by,
        }
    if parent_agent:
        snap["inherited_from"] = parent_agent
    try:
        from prismor.runtime.scoped_agent import load_scoped_rules
        scoped = load_scoped_rules(workspace, session_id) if session_id else None
        if scoped:
            snap["scoped_rules"] = {k: scoped.get(k) for k in
                                    ("allowed_tools", "deny_tools", "allowed_paths", "deny_network")
                                    if scoped.get(k) is not None}
            snap["scoped_rules"]["hash"] = digest(scoped)
    except Exception:
        pass
    keys = [f"user:{getattr(subject, 'user_id', None)}", f"team:{getattr(subject, 'team_id', None)}"]
    controls = {k: remote[k] for k in keys if isinstance(remote, dict) and k in remote}
    try:
        from prismor.runtime.enterprise import remote_policy as _rp
        pause = _rp.remote_pause()
        snap["policy_version"] = _rp.current_version()
    except Exception:
        pause, snap["policy_version"] = None, None
    if controls or pause:
        snap["subject_controls"] = {**controls, **({"pause": pause} if pause else {})}
    snap["policy_hash"] = _policy_hash()
    return snap


def store(snap: Dict[str, Any]) -> str:
    """Write ``snap`` once, content-addressed. Returns its hash."""
    h = digest(snap)
    path = _dir() / f"{h}.json"
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_bytes(_canon(snap))
        tmp.replace(path)
    return h


def load(h: str) -> Optional[Dict[str, Any]]:
    try:
        return json.loads((_dir() / f"{h}.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
