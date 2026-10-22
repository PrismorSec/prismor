"""Prismor adapter for Hugging Face smolagents.

Preferred import path::

    from prismor.smolagents import guard_agent

Aliases the ``prismor_smolagents`` implementation module so both import
paths resolve to the same module object.
"""
import sys as _sys

# See PrismorSec/prismor#173 -- mirrors the other adapters' shims' defense
# against the 'prismor' package directory leaking onto sys.path and
# shadowing a real top-level import.
if __name__ != "prismor.smolagents":
    raise ImportError(
        f"prismor.smolagents was imported as {__name__!r}, not "
        "'prismor.smolagents' — the 'prismor' package directory is on "
        "sys.path and may be shadowing another package. Remove it from "
        "sys.path (see PrismorSec/prismor#173)."
    )

import prismor_smolagents as _impl

_sys.modules[__name__] = _impl
