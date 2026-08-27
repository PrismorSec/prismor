"""Suite-wide isolation so a leak in one test cannot rewrite another's verdict.

Also wires the bundled framework adapters so they are importable from a
source checkout without separate package installation.

Two classes of cross-test state used to make ``pytest tests/`` red in ways that
depended on which files ran before which — so the same test passed alone and
failed in the suite, and CI signal degraded to "count the failures and hope".

**1. Module-attribute leaks.** Several tests replaced a module function by plain
assignment (``approvals._identity.load_identity = lambda: ...``) instead of
``monkeypatch.setattr``, so the stub outlived the test for the rest of the
process. Two of those compounded into the headline symptom: one left the device
looking permanently enrolled to a fake org, another left a signed org policy
that denied ``Bash`` — after which every shell event evaluated as ``block``,
``ls -la`` included. ``_no_module_state_leaks`` snapshots every function and
method reachable from the imported ``prismor`` package, restores anything a test
replaced, and fails that test — so a leak is loud at its source instead of
silent three files later.

The snapshot walks module *objects*, not ``sys.modules`` names, because several
tests drop a module from ``sys.modules`` to force a fresh import (to reset a
module-level cache). Every module already holding ``from ... import identity as
_identity`` keeps the *old* object, so two live copies of one module exist and a
name-keyed guard would watch the wrong one.

**2. Ambient $HOME / $PRISMOR_HOME.** The enrollment, identity, signing and
ledger tests assume a not-enrolled machine with an empty event store. They
passed on CI and failed on any enrolled developer laptop, and inside a run they
leaked homes into each other — the shared sqlite ledger lives in $PRISMOR_HOME
(``store.get_data_dir`` ignores its workspace argument), so a file's tests
accumulated each other's rows. ``_isolated_prismor_home`` gives every test a
fresh $HOME and $PRISMOR_HOME and restores the whole environment afterwards.

Modules that deliberately provision their own vault at import time (the cloaking
tests build a $PRISMOR_HOME with registered secrets and hand ``os.environ``
straight to hook subprocesses) must keep it. Their import-time writes are
recorded per module by ``pytest_make_collect_report`` and replayed for that
module's tests, so declaring a home still works — it just no longer escapes into
the modules collected after it.
"""
from __future__ import annotations

import inspect
import os
import sys
import types
from pathlib import Path
from typing import Any, Dict, List, Tuple

import pytest

# Framework adapter imports
_ADAPTERS = Path(__file__).resolve().parent.parent / "adapters"


def _wire_adapters() -> None:
    import prismor

    for adapter in sorted(_ADAPTERS.iterdir()):
        shim_root = adapter / "prismor"
        if not shim_root.is_dir():
            continue  # non-Python adapter (vercel-ai, mastra)
        if str(adapter) not in sys.path:
            sys.path.insert(0, str(adapter))
        if str(shim_root) not in prismor.__path__:
            prismor.__path__.append(str(shim_root))


_wire_adapters()


# Environment keys this file owns: the agent's home plus every Prismor knob.
# Restored around every test, so nothing a test sets can reach the next one.
_ENV_PREFIX = "PRISMOR_"
_ENV_EXTRA = ("HOME",)


def _tracked_env(env: Dict[str, str]) -> Dict[str, str]:
    return {k: v for k, v in env.items() if k.startswith(_ENV_PREFIX) or k in _ENV_EXTRA}


# Environment as pytest started, captured before any test module is imported.
_PRISTINE_ENV: Dict[str, str] = {}
# nodeid -> {env key: value or None} written while that module was imported.
_MODULE_ENV: Dict[str, Dict[str, Any]] = {}


def pytest_configure(config: pytest.Config) -> None:
    _PRISTINE_ENV.update(_tracked_env(os.environ))


@pytest.hookimpl(hookwrapper=True)
def pytest_make_collect_report(collector: pytest.Collector):
    """Record the env a test module writes while being imported.

    Wraps ``collector.collect()``, which is where a Module is imported, so the
    before/after diff is exactly that module's import-time declaration.
    """
    if not isinstance(collector, pytest.Module):
        yield
        return
    before = _tracked_env(os.environ)
    yield
    after = _tracked_env(os.environ)
    declared = {k: v for k, v in after.items() if before.get(k) != v}
    declared.update({k: None for k in before if k not in after})
    if declared:
        _MODULE_ENV[collector.nodeid] = declared


@pytest.fixture(scope="session")
def _sandbox_home(tmp_path_factory) -> Any:
    """One throwaway $HOME for the whole run, standing in for the developer's.

    Session-scoped on purpose. A per-test $HOME would be more thorough, but
    some modules freeze the home directory into a module-level constant at
    import time (``corpus._HOME_RE`` compiles ``expanduser("~")`` once), and a
    $HOME that moves underneath them makes their behaviour depend on which test
    happened to import them first. $PRISMOR_HOME — which is what the runtime
    actually reads, and where the shared sqlite ledger lives — is per test.
    """
    return tmp_path_factory.mktemp("home")


@pytest.fixture(autouse=True)
def _isolated_prismor_home(request: pytest.FixtureRequest, tmp_path_factory,
                           _sandbox_home) -> Any:
    """Run every test against a fresh, not-enrolled $PRISMOR_HOME.

    The full environment is restored afterwards, so a test that sets a variable
    without cleaning up (a bare ``os.environ[...] = ...`` in ``setUp``) cannot
    change what the next test sees.
    """
    saved = dict(os.environ)

    for key in _tracked_env(os.environ):
        if key not in _PRISTINE_ENV:
            del os.environ[key]
    os.environ.update(_PRISTINE_ENV)

    os.environ["HOME"] = str(_sandbox_home)
    os.environ["PRISMOR_HOME"] = str(tmp_path_factory.mktemp("prismor-home"))

    # A module that provisioned its own home at import time keeps it.
    module = getattr(request.node, "parent", None)
    while module is not None and not isinstance(module, pytest.Module):
        module = getattr(module, "parent", None)
    if module is not None:
        for key, value in _MODULE_ENV.get(module.nodeid, {}).items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(saved)


# module-attribute leak guard

def _live_prismor_modules() -> List[types.ModuleType]:
    """Every live ``prismor`` module object, including copies orphaned from
    ``sys.modules`` by a test that popped the name to force a re-import but
    that other modules still hold a reference to."""
    import sys

    seen: set = set()
    found: List[types.ModuleType] = []
    stack = [
        m for name, m in list(sys.modules.items())
        if name.startswith("prismor") and isinstance(m, types.ModuleType)
    ]
    while stack:
        mod = stack.pop()
        if id(mod) in seen:
            continue
        seen.add(id(mod))
        found.append(mod)
        try:
            values = list(vars(mod).values())
        except Exception:      # a module mid-teardown has no usable __dict__
            continue
        for value in values:
            if (isinstance(value, types.ModuleType)
                    and getattr(value, "__name__", "").startswith("prismor")
                    and id(value) not in seen):
                stack.append(value)
    return found


# key -> (module name, attribute path, current value). Functions and methods
# only: module-level caches are dicts mutated in place, so their identity never
# changes and they are never mistaken for a patch.
_SnapKey = Tuple[int, str, str, Any]


def _snapshot_callables() -> Dict[_SnapKey, Any]:
    snap: Dict[_SnapKey, Any] = {}
    for mod in _live_prismor_modules():
        name = getattr(mod, "__name__", "?")
        try:
            items = list(vars(mod).items())
        except Exception:
            continue
        for attr, value in items:
            if isinstance(value, (types.FunctionType, types.BuiltinFunctionType)):
                snap[(id(mod), name, attr, None)] = value
            elif inspect.isclass(value) and getattr(value, "__module__", "").startswith("prismor"):
                try:
                    class_items = list(vars(value).items())
                except Exception:
                    continue
                for cattr, cvalue in class_items:
                    if isinstance(cvalue, (types.FunctionType, staticmethod, classmethod)):
                        snap[(id(mod), name, attr, cattr)] = cvalue
    return snap


def _restore(key: _SnapKey, original: Any) -> str:
    import sys

    _mod_id, mod_name, attr, cattr = key
    target = next((m for m in _live_prismor_modules() if id(m) == _mod_id), None)
    if target is None:
        target = sys.modules.get(mod_name)
    label = f"{mod_name}.{attr}" + (f".{cattr}" if cattr else "")
    if target is None:
        return label
    try:
        if cattr is None:
            setattr(target, attr, original)
        else:
            setattr(getattr(target, attr), cattr, original)
    except Exception:
        pass
    return label


def _snapshot_sys_modules() -> Dict[str, types.ModuleType]:
    import sys

    return {n: m for n, m in list(sys.modules.items()) if n.startswith("prismor")}


def _restore_sys_modules(before: Dict[str, types.ModuleType]) -> None:
    """Undo a test's re-import of a ``prismor`` module.

    Several tests drop a module from ``sys.modules`` to reset a module-level
    cache. When that name is imported again a *second* module object appears,
    and every module that already did ``from ... import identity as _identity``
    keeps the first — so the process runs two live copies of one module and a
    ``monkeypatch.setattr`` lands on whichever copy the test happened to bind,
    which is not necessarily the one the runtime calls.

    Putting the original object back (on ``sys.modules`` and on its parent
    package, which is what ``from pkg import sub`` actually reads) keeps one
    canonical object per name, so patching a module means patching the module.
    """
    import sys

    for name, original in before.items():
        if sys.modules.get(name) is original:
            continue
        sys.modules[name] = original
        parent_name, _, leaf = name.rpartition(".")
        parent = sys.modules.get(parent_name) if parent_name else None
        if parent is not None and getattr(parent, leaf, None) is not original:
            try:
                setattr(parent, leaf, original)
            except Exception:
                pass


# Pristine value of every callable, taken once collection has imported all the
# test modules (and with them the runtime they exercise). The per-test snapshot
# below is the primary reference; this one covers a module a test imports for
# the first time inside its own body, which has no per-test baseline.
_BASELINE: Dict[_SnapKey, Any] = {}


def pytest_collection_finish(session: pytest.Session) -> None:
    _BASELINE.update(_snapshot_callables())


@pytest.fixture(autouse=True)
def _no_module_state_leaks() -> Any:
    """Fail the test that leaves a patched ``prismor`` function behind.

    ``monkeypatch.setattr`` / ``mock.patch`` undo themselves and never trip this;
    a bare ``module.func = lambda: ...`` does. The original is put back either
    way, so one offender cannot cascade into the rest of the run.
    """
    modules_before = _snapshot_sys_modules()
    before = _snapshot_callables()
    try:
        yield
    finally:
        _restore_sys_modules(modules_before)
        after = _snapshot_callables()
        leaked = []
        for key, current in after.items():
            pristine = before.get(key, _BASELINE.get(key, current))
            if current is not pristine:
                leaked.append(_restore(key, pristine))
        leaked = sorted(leaked)
    if leaked:
        pytest.fail(
            "test leaked patched module state (restored, but fix the test): "
            + ", ".join(leaked)
            + "\nUse monkeypatch.setattr / mock.patch instead of assigning to a "
              "module attribute, so the patch is undone when the test ends.",
            pytrace=False,
        )

