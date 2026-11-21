"""Run a set of collectors and seal the records.

A collector that raises becomes one diagnostic. Missing paths, permission
errors, and HTTP 403s are the collector's own diagnostics; they are not
raised to the caller.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Sequence

from prismor.runtime.inventory import correlate, risk
from prismor.runtime.inventory.collectors import (
    endpoint_core, endpoint_jetbrains, endpoint_wsl, ide_extensions,
)
from prismor.runtime.inventory.context import ScanContext, machine_id_default, os_name_default
from prismor.runtime.inventory.ids import record_id, scope_key_endpoint
from prismor.runtime.inventory.schema import InventoryRecord, RunInfo, diagnostic

Collector = Callable[[ScanContext], Iterable[InventoryRecord]]

_COLLECTORS: Dict[str, Collector] = {
    endpoint_core.SURFACE: endpoint_core.collect,
    endpoint_jetbrains.SURFACE: endpoint_jetbrains.collect,
    ide_extensions.SURFACE: ide_extensions.collect,
    endpoint_wsl.SURFACE: endpoint_wsl.collect,
}

SURFACES = {
    "endpoint": [
        endpoint_core.SURFACE, endpoint_jetbrains.SURFACE,
        ide_extensions.SURFACE, endpoint_wsl.SURFACE,
    ],
    "jetbrains": [endpoint_jetbrains.SURFACE],
    "extensions": [ide_extensions.SURFACE],
    "wsl": [endpoint_wsl.SURFACE],
}

#: Entry-point group for collectors shipped outside this package. Each entry
#: point names a module with ``SURFACE`` and ``collect(ctx)``; the entry point
#: name is the alias ``prismor discover <alias>`` accepts.
PLUGIN_GROUP = "prismor.inventory_collectors"
_PLUGINS_LOADED = False


def _load_plugins() -> None:
    """Register installed plugin collectors once. A broken plugin is skipped."""
    global _PLUGINS_LOADED
    if _PLUGINS_LOADED:
        return
    _PLUGINS_LOADED = True
    from importlib.metadata import entry_points
    try:
        found = entry_points(group=PLUGIN_GROUP)
    except Exception:
        return
    for ep in found:
        try:
            module = ep.load()
            surface = str(module.SURFACE)
            _COLLECTORS.setdefault(surface, module.collect)
            SURFACES.setdefault(ep.name, [surface])
        except Exception:
            continue


def known_surfaces() -> List[str]:
    _load_plugins()
    return sorted(set(SURFACES) | set(_COLLECTORS))


def surface_names(name: str, settings: Optional[dict] = None) -> List[str]:
    _load_plugins()
    if name == "inventory":
        configured = list((settings or {}).get("surfaces") or ["endpoint"])
        out: List[str] = []
        for item in configured:
            out.extend(SURFACES.get(str(item), [str(item)]))
        return out
    if name in SURFACES:
        return list(SURFACES[name])
    if name in _COLLECTORS:
        return [name]
    return []


def _seal(ctx: ScanContext, record: InventoryRecord) -> InventoryRecord:
    record.location.host_id = record.location.host_id or ctx.host_id
    record.location.hostname = record.location.hostname or ctx.hostname
    record.location.os = record.location.os or ctx.os_name
    if record.username:
        record.location.user = ctx.user_token(record.username)
    record.username = ""
    record.observed_at = record.observed_at or ctx.observed_at
    record.run = RunInfo(
        run_id=ctx.run_id,
        scanner="prismor",
        scanner_version=ctx.scanner_version(),
        collector_version=1,
    )
    if record.entity_key:
        if record.entity_key in ctx.deny:
            record.governance.approved = False
        elif record.entity_key in ctx.allow:
            record.governance.approved = True
    scope = scope_key_endpoint(record.location.host_id, record.location.user)
    if record.location.environment_id:
        scope = f"{record.location.tenant_id or ''}/{record.location.environment_id}"
    natural = record.entity_key or record.name
    # Path keeps two files that declare the same server as two rows.
    natural = natural + "|" + (record.location.path or "")
    record.record_id = record_id(record.source, record.kind, scope, natural)
    risk.apply(record)
    return record


def _dedupe(records: List[InventoryRecord]) -> List[InventoryRecord]:
    """Prefer a more specific collector when two rows describe one file."""
    rank = {
        "endpoint.jetbrains": 3,
        "endpoint.extensions": 3,
        "endpoint.wsl": 2,
        "endpoint.core": 1,
    }
    best: Dict[tuple, InventoryRecord] = {}
    for record in records:
        if record.kind == "diagnostic":
            best[(record.record_id, id(record))] = record
            continue
        key = (record.kind, record.entity_key, record.location.path or "", record.location.user)
        current = best.get(key)
        # Plugin sources are tenant-side and never overlap an endpoint row.
        if current is None or rank.get(record.source, 3) > rank.get(current.source, 3):
            best[key] = record
    return list(best.values())


def run(names: Sequence[str], ctx: ScanContext) -> List[InventoryRecord]:
    """Run ``names`` (surface ids or aliases) and return sealed records."""
    _load_plugins()
    chosen: List[str] = []
    for name in names:
        if name == "inventory":
            configured = ctx.surfaces or ["endpoint"]
            for item in configured:
                for surface in surface_names(str(item)):
                    if surface not in chosen:
                        chosen.append(surface)
            continue
        for surface in surface_names(name):
            if surface not in chosen:
                chosen.append(surface)
    records: List[InventoryRecord] = []
    for surface in chosen:
        fn = _COLLECTORS.get(surface)
        if fn is None:
            records.append(diagnostic(surface, error_code="unsupported",
                                      hint=f"no collector for {surface}", surface="endpoint"))
            continue
        produced: List[InventoryRecord] = []
        try:
            for record in fn(ctx):
                produced.append(record)
                if len(produced) >= ctx.record_cap:
                    break
        except Exception:
            produced.append(diagnostic(surface, error_code="collector_error",
                                       hint="collector failed", surface="endpoint"))
        for record in produced:
            records.append(_seal(ctx, record))
    records = _dedupe(records)
    return correlate.correlate(records)


def load_settings(path: Optional[Path] = None) -> dict:
    """Fleet inventory settings. Missing file → empty dict, not an error."""
    import yaml
    candidates = []
    if path is not None:
        candidates.append(Path(path))
    override = os.environ.get("PRISMOR_INVENTORY_SETTINGS", "").strip()
    if override:
        candidates.append(Path(override))
    try:
        from prismor.runtime.system_install import system_dir
        candidates.append(system_dir() / "inventory.yaml")
    except Exception:
        pass
    try:
        from prismor.runtime.store import prismor_home
        candidates.append(prismor_home() / "inventory.yaml")
    except Exception:
        pass
    for candidate in candidates:
        try:
            if candidate.is_file():
                data = yaml.safe_load(candidate.read_text(encoding="utf-8")) or {}
                return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            continue
    return {}


def context_from_env(workspace: Path, *, all_users: bool = False, dry_run: bool = False,
                     settings: Optional[dict] = None) -> ScanContext:
    """Build a context, honoring demo/lab environment overrides."""
    settings = settings if settings is not None else load_settings()
    profiles = os.environ.get("PRISMOR_INVENTORY_PROFILES", "").strip()
    wsl = os.environ.get("PRISMOR_INVENTORY_WSL", "").strip()
    salt = os.environ.get("PRISMOR_INVENTORY_SALT", "").strip() or str(settings.get("org_salt") or "prismor")
    hostname = os.environ.get("PRISMOR_INVENTORY_HOSTNAME", "").strip()
    ctx = ScanContext(
        os_name=os_name_default(),
        workspace=workspace,
        all_users=all_users or bool(settings.get("all_users")),
        hash_users=bool(settings.get("hash_users", True)),
        org_salt=salt,
        hostname=hostname,
        machine_id=machine_id_default(),
        dry_run=dry_run,
        profiles_root=Path(profiles) if profiles else None,
        wsl_root=Path(wsl) if wsl else None,
        allow=list(settings.get("allow") or []),
        deny=list(settings.get("deny") or []),
        surfaces=[str(item) for item in (settings.get("surfaces") or [])],
        settings=dict(settings),
    )
    return ctx


def output_dir() -> Path:
    override = os.environ.get("PRISMOR_INVENTORY_DIR", "").strip()
    if override:
        return Path(override)
    from prismor.runtime.system_install import system_dir
    return system_dir() / "inventory"


def maybe_fleet_scan(now: Optional[float] = None) -> Dict[str, object]:
    """Run from ``system_install.sync`` when the configured interval has elapsed.

    The scan is skipped when inventory settings are absent. Jitter is 0–60
    minutes, stable per machine id. ``PRISMOR_INVENTORY_NO_JITTER=1`` disables
    it. ``PRISMOR_INVENTORY_INLINE=1`` runs in-process; otherwise a child
    process is capped at 10 minutes.
    """
    import hashlib
    import json
    import subprocess
    import sys
    import time
    from prismor.runtime.inventory.schema import to_ndjson

    settings = load_settings()
    if not settings or not settings.get("surfaces"):
        return {"skipped": "not configured"}
    directory = output_dir()
    try:
        directory.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return {"skipped": "unwritable", "error": exc.__class__.__name__}
    stamp_path = directory / "last_run.json"
    lock_path = directory / "scan.lock"
    current = time.time() if now is None else float(now)
    interval = float(settings.get("interval_hours") or 24) * 3600.0
    host = machine_id_default() or "host"
    if os.environ.get("PRISMOR_INVENTORY_NO_JITTER") == "1":
        jitter = 0
    else:
        jitter = int(hashlib.sha256(host.encode("utf-8")).hexdigest()[:8], 16) % 3600
    try:
        last = float(json.loads(stamp_path.read_text(encoding="utf-8")).get("last_run") or 0)
    except (OSError, ValueError, TypeError):
        last = 0.0
    if last and current - last < interval + jitter:
        return {"skipped": "interval", "last_run": last}
    if lock_path.exists():
        try:
            age = current - lock_path.stat().st_mtime
        except OSError:
            age = 0
        if age < 600:
            return {"skipped": "locked"}
    try:
        lock_path.write_text(str(current), encoding="utf-8")
    except OSError:
        return {"skipped": "unwritable"}
    dest = directory / "last.ndjson"
    try:
        if os.environ.get("PRISMOR_INVENTORY_INLINE") == "1":
            ctx = context_from_env(Path.cwd(), settings=settings)
            records = run(["inventory"], ctx)
            dest.write_text(to_ndjson(records), encoding="utf-8")
            count = len(records)
        else:
            proc = subprocess.run(
                [sys.executable, "-m", "prismor.runtime.cli", "discover", "inventory",
                 "--format", "ndjson", "--out", str(dest), "--all-users"],
                timeout=600, check=False, capture_output=True,
            )
            count = proc.returncode
        stamp_path.write_text(json.dumps({"last_run": current}), encoding="utf-8")
        return {"wrote": str(dest), "count": count}
    except subprocess.TimeoutExpired:
        return {"skipped": "timeout"}
    except OSError as exc:
        return {"skipped": "failed", "error": exc.__class__.__name__}
    finally:
        try:
            lock_path.unlink()
        except OSError:
            pass
