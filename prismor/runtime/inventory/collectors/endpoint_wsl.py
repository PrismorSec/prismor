"""WSL homes. Only running distros are listed, and only their files are read."""
from __future__ import annotations

from typing import Iterable

from prismor.runtime.inventory.collectors import endpoint_core, endpoint_jetbrains, ide_extensions
from prismor.runtime.inventory.context import ScanContext
from prismor.runtime.inventory.homes import wsl_homes
from prismor.runtime.inventory.schema import InventoryRecord, diagnostic

SURFACE = "endpoint.wsl"
REQUIRES = {"os": ["windows"], "auth": None, "extras": []}


def collect(ctx: ScanContext) -> Iterable[InventoryRecord]:
    if ctx.os_name != "windows" and ctx.wsl_root is None:
        return []
    try:
        homes = wsl_homes(ctx)
    except OSError:
        yield diagnostic(SURFACE, error_code="permission", hint="could not list WSL distros", surface="endpoint")
        return
    if ctx.dry_run:
        yield diagnostic(SURFACE, error_code="dry_run",
                         hint="would list running WSL distros and read their home directories",
                         surface="endpoint")
        return
    for home in homes:
        try:
            yield from endpoint_jetbrains.scan_home(ctx, home, source=SURFACE)
            yield from ide_extensions.scan_home(ctx, home, source=SURFACE)
            yield from endpoint_core.mcp_on_home(ctx, home, source=SURFACE, include_workspace=False)
            yield from endpoint_core.credentials_on_home(ctx, home, include_process=False)
        except OSError:
            yield diagnostic(SURFACE, error_code="permission", hint="WSL home not readable",
                             surface="endpoint", name=home.wsl_distro or home.username)
