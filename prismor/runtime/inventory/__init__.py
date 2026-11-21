"""Shadow-agent inventory (``prismor.inventory.v1``).

Collectors are read-only. They record that something exists — a product, a
path, an environment variable name — and never a secret value. See
``docs/shadow-discovery.md``.
"""
from prismor.runtime.inventory.schema import SCHEMA

__all__ = ["SCHEMA"]
