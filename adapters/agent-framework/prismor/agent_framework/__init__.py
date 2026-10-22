"""Prismor adapter for Microsoft Agent Framework.

Preferred import path::

    from prismor.agent_framework import PrismorMiddleware

Aliases the ``prismor_agent_framework`` implementation module so both import
paths resolve to the same module object.
"""
import sys as _sys

# See PrismorSec/prismor#173 -- mirrors the other adapters' shims' defense
# against the 'prismor' package directory leaking onto sys.path and
# shadowing a real top-level import.
if __name__ != "prismor.agent_framework":
    raise ImportError(
        f"prismor.agent_framework was imported as {__name__!r}, not "
        "'prismor.agent_framework' — the 'prismor' package directory is on "
        "sys.path and may be shadowing another package. Remove it from "
        "sys.path (see PrismorSec/prismor#173)."
    )

import prismor_agent_framework as _impl

_sys.modules[__name__] = _impl
