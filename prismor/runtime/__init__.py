"""Prismor local session-security utility."""

__version__ = "1.55.1"

__all__ = [
    "__version__",
    "SemanticGuard",
    "SemanticGuardV2",
    "SemanticRisk",
    "HybridRisk",
]

# The semantic guards are exported lazily. This package is imported by every
# hook call (and, via the wheel's .pth file, by every Python start-up on the
# machine), and pulling the guards in eagerly cost ~50ms each time for classes
# the hook path never touches.
_LAZY = {
    "SemanticGuard": "prismor.runtime.semantic_guard",
    "SemanticRisk": "prismor.runtime.semantic_guard",
    "SemanticGuardV2": "prismor.runtime.semantic_guard_v2",
    "HybridRisk": "prismor.runtime.semantic_guard_v2",
}


def __getattr__(name):
    module = _LAZY.get(name)
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    import importlib

    value = getattr(importlib.import_module(module), name)
    globals()[name] = value
    return value
