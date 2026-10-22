"""Adapter shim import guard.

Each ``prismor.<framework>`` shim aliases its implementation module into
``sys.modules``. That alias must fire ONLY when the shim is imported under its
intended dotted name. If the ``prismor`` package directory ever leaks onto
``sys.path`` (the root cause fixed in PrismorSec/prismor#173), Python can resolve
e.g. ``prismor/openai`` as a *top-level* ``openai`` module — and a blind alias
would then replace the real SDK with the adapter, breaking every downstream
``import openai``. The shim must fail loudly instead. This is defense in depth.
"""
import importlib.util
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
SHIMS = {
    "openai": _ROOT / "adapters/openai-agents/prismor/openai/__init__.py",
    "crewai": _ROOT / "adapters/crewai/prismor/crewai/__init__.py",
    "langchain": _ROOT / "adapters/langchain/prismor/langchain/__init__.py",
    "browser_use": _ROOT / "adapters/browser-use/prismor/browser_use/__init__.py",
    "agent_framework": _ROOT / "adapters/agent-framework/prismor/agent_framework/__init__.py",
}


@pytest.mark.parametrize("toplevel,path", list(SHIMS.items()))
def test_shim_refuses_toplevel_import(toplevel, path):
    # Load the shim under the bare top-level name it would receive if the prismor
    # package dir were on sys.path. It must raise before aliasing sys.modules.
    spec = importlib.util.spec_from_file_location(toplevel, str(path))
    module = importlib.util.module_from_spec(spec)
    with pytest.raises(ImportError, match="sys.path"):
        spec.loader.exec_module(module)
