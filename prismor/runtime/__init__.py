"""Prismor local session-security utility."""

__version__ = "1.80.4"

# Loaded on first use: every hook process imports this package, and the two
# guard modules cost ~25ms there before any work starts.
_LAZY = {"SemanticGuard": "semantic_guard", "SemanticRisk": "semantic_guard",
         "SemanticGuardV2": "semantic_guard_v2", "HybridRisk": "semantic_guard_v2"}


def __getattr__(name):
    if name in _LAZY:
        import importlib
        return getattr(importlib.import_module(f"{__name__}.{_LAZY[name]}"), name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = [
    "__version__",
    "SemanticGuard",
    "SemanticGuardV2",
    "SemanticRisk",
    "HybridRisk",
]
