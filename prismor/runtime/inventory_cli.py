"""Table / JSON / NDJSON rendering for ``prismor discover <surface>``."""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from prismor.runtime.inventory.runner import context_from_env, load_settings, run, surface_names
from prismor.runtime.inventory.schema import to_ndjson

_LEVELS = ["none", "low", "medium", "high", "critical"]
#: Matches the console's per-report batch cap (``MAX_BODY_FINDINGS``).
_REPORT_INVENTORY_CAP = 2000


def _rows(records) -> List[Dict[str, Any]]:
    from prismor.runtime.sinks import _scrub_obj
    return [_scrub_obj(record.to_dict()) for record in records]


def render_table(rows: Sequence[Dict[str, Any]]) -> str:
    header = f"{'RISK':<10} {'KIND':<16} {'NAME':<28} {'PRODUCT':<22} {'USER'}"
    lines = [header, "-" * len(header)]
    for row in rows:
        if row.get("kind") == "diagnostic":
            hint = (row.get("attributes") or {}).get("hint") or ""
            lines.append(f"{'diag':<10} {'diagnostic':<16} {str(row.get('name') or ''):<28} {hint[:40]}")
            continue
        risk = (row.get("risk") or {}).get("level") or "none"
        user = (row.get("location") or {}).get("user") or ""
        lines.append(
            f"{risk:<10} {str(row.get('kind') or ''):<16} "
            f"{str(row.get('name') or '')[:28]:<28} {str(row.get('product') or '')[:22]:<22} {user}"
        )
    lines.append(f"\n{len(rows)} record(s)")
    return "\n".join(lines) + "\n"


def _format_for(args, rows_text_is_tty: bool) -> str:
    explicit = getattr(args, "format", None)
    if explicit:
        return explicit
    if getattr(args, "json", False):
        return "json"
    return "table" if rows_text_is_tty else "ndjson"


def exit_code(rows: Sequence[Dict[str, Any]], *, fail_on: Optional[str], strict: bool) -> int:
    if fail_on and fail_on in _LEVELS and fail_on != "none":
        threshold = _LEVELS.index(fail_on)
        for row in rows:
            if row.get("kind") == "diagnostic":
                continue
            level = str((row.get("risk") or {}).get("level") or "none")
            if level in _LEVELS and _LEVELS.index(level) >= threshold:
                return 1
    auth_failed = any(
        row.get("kind") == "diagnostic" and (row.get("attributes") or {}).get("error_code") == "auth"
        for row in rows
    )
    real = any(row.get("kind") != "diagnostic" for row in rows)
    if auth_failed and not real:
        return 3
    if strict and any(row.get("kind") == "diagnostic" for row in rows):
        return 4
    return 0


def execute(args, workspace: Path) -> int:
    """Run one inventory surface. Returns a process exit code."""
    section = getattr(args, "section", "endpoint") or "endpoint"
    settings = load_settings()
    ctx = context_from_env(
        workspace,
        all_users=bool(getattr(args, "all_users", False) or settings.get("all_users")),
        dry_run=bool(getattr(args, "dry_run", False)),
        settings=settings,
    )
    if section != "inventory" and not surface_names(section):
        sys.stderr.write(f"Unknown inventory surface {section!r}\n")
        return 2
    records = run([section], ctx)
    rows = _rows(records)
    fmt = _format_for(args, sys.stdout.isatty())
    if fmt == "json":
        text = json.dumps(rows, indent=2) + "\n"
    elif fmt == "table":
        text = render_table(rows)
    else:
        text = to_ndjson([]) if not rows else ""
        # Re-serialise the scrubbed dicts so NDJSON matches what a sink sees.
        if rows:
            text = "".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in rows)
    out = getattr(args, "out", None)
    if out:
        Path(out).parent.mkdir(parents=True, exist_ok=True)
        Path(out).write_text(text, encoding="utf-8")
    elif not getattr(args, "quiet", False):
        sys.stdout.write(text)
    sink_names = [part.strip() for part in str(getattr(args, "sink", "") or "").split(",") if part.strip()]
    if sink_names or getattr(args, "report", False):
        _emit(rows, sink_names, settings, report=bool(getattr(args, "report", False)), workspace=workspace)
    return exit_code(rows, fail_on=getattr(args, "fail_on", None), strict=bool(getattr(args, "strict", False)))


def _emit(rows, sink_names, settings, *, report: bool, workspace: Path) -> None:
    from prismor.runtime.sinks import dispatch_inventory
    configured = list(settings.get("sinks") or [])
    chosen = []
    if sink_names:
        by_name = {str(item.get("name") or item.get("type")): item for item in configured if isinstance(item, dict)}
        for name in sink_names:
            if name in by_name:
                chosen.append(by_name[name])
            else:
                sys.stderr.write(f"[prismor] inventory sink {name!r} is not configured\n")
    else:
        chosen = configured
    if chosen:
        dispatch_inventory(rows, chosen)
    if report:
        # The console treats every report as the device's full shadow inventory
        # and deletes findings that are absent, so the legacy sections must ride
        # along; an inventory-only report would wipe the device's Shadow AI view.
        # One report per scan; rows past the console's batch cap are dropped.
        from prismor.runtime.discover import build_report, send_report
        legacy = build_report(workspace)
        legacy["inventory"] = rows[:_REPORT_INVENTORY_CAP]
        send_report(legacy)
