"""Prismor adapter for AG2.

Preferred import path::

    from prismor.ag2 import prismor_middleware

Aliases the ``prismor_ag2`` implementation module so both import
paths resolve to the same module object.
"""
import sys as _sys

# See PrismorSec/prismor#173 -- mirrors the other adapters' shims' defense
# against the 'prismor' package directory leaking onto sys.path and
# shadowing a real top-level import.
if __name__ != "prismor.ag2":
    raise ImportError(
        f"prismor.ag2 was imported as {__name__!r}, not "
        "'prismor.ag2' — the 'prismor' package directory is on "
        "sys.path and may be shadowing another package. Remove it from "
        "sys.path (see PrismorSec/prismor#173)."
    )

import prismor_ag2 as _impl

_sys.modules[__name__] = _impl
