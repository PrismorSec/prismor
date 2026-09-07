"""Locate bundled runtime data (advisory feed, signing key, templates).

The same files live in two layouts depending on how Prismor is installed:

* **Git checkout / editable install** — data sits at the repo root as
  ``advisories/``, ``keys/`` and ``templates/`` (the layout the signing
  pipeline and ``verify_feed.sh`` write to and read from).
* **Installed wheel** — the build bundles those directories under this
  package as ``prismor/runtime/data/advisories``, ``prismor/runtime/data/keys`` and
  ``prismor/runtime/data/templates`` (see ``pyproject.toml`` ``force-include``).

Both layouts share the same suffix (``advisories/immunity-feed.json`` …),
so a single resolver can serve either. Resolution order:

1. ``$PRISMOR_HOME`` — explicit override (the git-clone install model).
2. A repo checkout discovered by walking up from this file.
3. The bundled ``prismor/runtime/data`` directory shipped inside the wheel.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Iterator, Union

# Bundled location inside an installed wheel.
_BUNDLED_DATA = Path(__file__).resolve().parent / "data"

# Sentinel file used to recognise a data root in any layout.
_FEED_REL = ("advisories", "immunity-feed.json")


def _candidate_roots() -> Iterator[Path]:
    """Yield possible data roots in priority order."""
    home = os.environ.get("PRISMOR_HOME")
    if home:
        yield Path(home).expanduser()

    # Walk up from this file looking for a checkout whose root holds the feed.
    for parent in Path(__file__).resolve().parents:
        if parent.joinpath(*_FEED_REL).exists():
            yield parent
            break

    yield _BUNDLED_DATA


def _resolve(*relparts: str) -> Path:
    """Return the first existing path for ``relparts`` across candidate roots.

    Falls back to the bundled location (which may not exist) so callers get a
    stable, sensible path to report in error messages.
    """
    for root in _candidate_roots():
        candidate = root.joinpath(*relparts)
        if candidate.exists():
            return candidate
    return _BUNDLED_DATA.joinpath(*relparts)


def data_root() -> Path:
    """Best-guess root that contains ``advisories/``, ``keys/`` and ``templates/``."""
    feed = feed_path()
    # feed == <root>/advisories/immunity-feed.json → root is two levels up.
    return feed.parent.parent


def feed_path() -> Path:
    return _resolve("advisories", "immunity-feed.json")


def feed_sig_path() -> Path:
    return _resolve("advisories", "immunity-feed.json.sig")


def public_key_path() -> Path:
    return _resolve("keys", "public.pub")


def template_path(name: str) -> Path:
    return _resolve("templates", name)


def skill_manifest_path() -> Path:
    """Locate the bundled immunity-agent Claude skill manifest (SKILL.md).

    Git checkout: ``<root>/SKILL.md``. Installed wheel: ``prismor/runtime/data/SKILL.md``.
    """
    return _resolve("SKILL.md")


def skill_docs_dir() -> Path:
    """Locate the skill's ``docs/`` directory (reference material it links to)."""
    return _resolve("docs")


def is_within(inner: Union[str, Path, None], outer: Union[str, Path, None]) -> bool:
    """Whether ``inner`` resolves to ``outer`` or somewhere underneath it.

    Both sides are resolved, so a symlink pointing out of ``outer`` correctly
    reads as outside it. Comparing parent components rather than string
    prefixes is what keeps ``/srv/apple`` from reading as inside ``/srv/app``.
    Anything unresolvable is *not* within — callers decide what that means.
    """
    if not inner or not outer:
        return False
    try:
        a, b = Path(inner).resolve(), Path(outer).resolve()
    except (OSError, ValueError):
        return False
    return a == b or b in a.parents
