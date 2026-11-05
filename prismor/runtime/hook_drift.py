"""Notice when Prismor's own hooks or cloaking disappear.

Another tool's uninstaller can restore an old ``~/.claude/settings.json`` and
take Prismor's hooks with it. Nothing then runs for that agent, so nothing
inside the hook can notice. Setup records what it installed here; ``status``,
``doctor`` and the hooks of any agent still wired compare that record with
what is configured now and flag "was installed, now missing".
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

_FILE = "installed_hooks.json"
_HOOK_CHECK_EVERY_S = 300  # a hook call pays for the comparison at most this often


def _path() -> Path:
    from prismor.runtime.store import prismor_home
    return prismor_home() / _FILE


def _load() -> Dict[str, Any]:
    try:
        data = json.loads(_path().read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save(data: Dict[str, Any]) -> None:
    try:
        p = _path()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(data, indent=1, sort_keys=True), encoding="utf-8")
    except OSError:
        pass


def _key(kind: str, agent: str, scope: str, workspace: Path) -> str:
    # A project install belongs to one workspace; a global one to the machine.
    # `install-hooks` says "user" where hook_health says "global"; cloaking
    # status takes "user".
    if kind == "hook" and scope == "user":
        scope = "global"
    where = "" if scope in ("global", "user") else f":{Path(workspace).resolve()}"
    return f"{kind}:{agent}:{scope}{where}"


def record(kind: str, agent: str, scope: str, workspace: Path, installed: bool) -> None:
    """Note that setup installed (or a deliberate uninstall removed) a hook.
    ``kind`` is ``hook`` (agent = the agent id) or ``cloak`` (agent = ``cloak``)."""
    if scope == "system":
        return
    data = _load()
    entries = data.setdefault("installed", {})
    key = _key(kind, agent, scope, workspace)
    if installed:
        entries[key] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    else:
        entries.pop(key, None)
    data.pop("reported", None)
    _save(data)


def missing(workspace: Path) -> List[str]:
    """Labels of recorded installs that are no longer configured, e.g.
    ``["claude hooks (global)", "cloaking (user)"]``."""
    entries = _load().get("installed") or {}
    if not entries:
        return []
    from prismor.runtime.hooks import hook_health
    configured = {_key("hook", c["agent"], c["scope"], workspace)
                  for c in hook_health(workspace) if c.get("configured")}
    out: List[str] = []
    for key in sorted(entries):
        kind, agent, rest = key.split(":", 2)
        scope, _, where = rest.partition(":")
        if where and Path(where) != Path(workspace).resolve():
            continue  # another workspace's project install
        if kind == "hook":
            if key not in configured:
                out.append(f"{agent} hooks ({scope})")
        elif kind == "cloak":
            try:
                from prismor.runtime.cloaking import status as cloak_status
                ok = cloak_status(workspace=workspace, scope=scope).get("installed")
            except Exception:
                ok = True  # cannot tell; do not cry wolf
            if not ok:
                out.append(f"cloaking ({scope})")
    return out


def report(workspace: Path, *, from_hook: bool = False) -> List[str]:
    """``missing()``, plus one telemetry event the first time a given set goes
    missing. ``from_hook`` rate-limits the check for the hook path."""
    data = _load()
    if not data.get("installed"):
        return []
    now = time.time()
    if from_hook:
        if now - float(data.get("checked") or 0) < _HOOK_CHECK_EVERY_S:
            return []
        data["checked"] = now
        _save(data)
    gone = missing(workspace)
    fingerprint = "|".join(gone)
    if gone and data.get("reported") != fingerprint:
        _emit(workspace, gone)
        data = _load()
        data["reported"] = fingerprint
        _save(data)
    elif not gone and data.get("reported"):
        data.pop("reported", None)
        _save(data)
    return gone


def _emit(workspace: Path, gone: List[str]) -> None:
    try:
        from prismor.runtime.policy_engine import PolicyEngine
        from prismor.runtime.sinks import dispatch
        outputs = list(getattr(PolicyEngine(workspace=workspace), "outputs", []) or [])
        finding = {
            "id": f"prismor-hooks-missing:{int(time.time())}",
            "ruleId": "prismor-hooks-missing",
            "severity": "HIGH",
            "category": "security_bypass",
            "action": "warn",
            "mode": "observe",
            "title": "Prismor hooks were installed and are now missing",
            "evidence": ", ".join(gone),
        }
        dispatch([finding], outputs, extra={"workspace": str(workspace), "agent": "prismor"},
                 raw_event={"type": "config", "agent_event": "hook_drift", "missing": gone})
    except Exception as exc:
        sys.stderr.write(f"[prismor] hook drift report error: {exc}\n")
