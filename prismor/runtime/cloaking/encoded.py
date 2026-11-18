"""Encoded forms of a secret value, so the scrubbers also catch it re-encoded.

Exact-match scrubbing let ``printf %s @@SECRET:X@@ | base64`` (or ``| xxd -p``,
``| rev``) print the value in a form the scrubber did not recognise. Each
registered value is also matched as:

  - base64 and base64url at all three byte offsets, so the value is caught
    when it sits inside a longer encoded string (``Bearer <value>`` encoded),
  - lower- and upper-case hex,
  - URL (percent) encoding,
  - reversed.

This raises the bar, it does not close the door: a custom encoding (XOR, a
character split, a split across two commands) still gets past any scrubber.
Binding a secret to its hosts (``bindings.py``) is what stops a deliberate
leak.

Stdlib only: ``scrub-stream.sh`` runs this file as a script to write its
variant cache, without importing the prismor package.

    python3 encoded.py <secrets_dir>   # (re)write <secrets_dir>/.meta/encoded
"""
from __future__ import annotations

import base64
import os
import sys
from functools import lru_cache
from pathlib import Path
from typing import List, Tuple
from urllib.parse import quote

# Below this a variant collides with ordinary output (a 6-char hex run is
# everywhere). Base64 of an 8-char value at offset 2 keeps only ~9 chars.
_MIN_VARIANT = 10


def _b64_cores(raw: bytes) -> List[str]:
    """The base64 chars that depend only on ``raw``, at each byte offset."""
    out = []
    for k in range(3):
        enc = base64.b64encode(b"\0" * k + raw).decode("ascii").rstrip("=")
        start = -(-4 * k // 3)                 # ceil(4k/3): first char fully inside raw
        end = (8 * (k + len(raw))) // 6         # chars wholly made of raw's bits
        out.append(enc[start:end])
    return out


@lru_cache(maxsize=512)
def variants(value: str) -> Tuple[str, ...]:
    """Encoded forms of ``value`` worth scrubbing, longest first, value excluded."""
    raw = value.encode("utf-8")
    found = set()
    for core in _b64_cores(raw):
        found.add(core)
        found.add(core.replace("+", "-").replace("/", "_"))
    hx = raw.hex()
    found.update({hx, hx.upper(), quote(value, safe=""), value[::-1]})
    found.discard(value)
    keep = (v for v in found if len(v) >= _MIN_VARIANT and "\n" not in v and "\t" not in v)
    return tuple(sorted(keep, key=len, reverse=True))


def _scrubbable(v: str) -> bool:
    # Mirrors runtime.is_scrubbable_secret; kept here so this file stays
    # importable without the package. tests/test_cloak_bindings.py pins them equal.
    import re
    n = len(v)
    if n < 8 or re.fullmatch(r"[A-Za-z][A-Za-z0-9+.-]*://[A-Za-z0-9.-]+(?::[0-9]+)?/?", v):
        return False
    if n >= 16:
        return True
    return (any(c.isdigit() for c in v) or any(not c.isalnum() for c in v)
            or (any(c.isupper() for c in v) and any(c.islower() for c in v)))


def write_cache(secrets_dir: str) -> Path:
    """Write ``name<TAB>variant`` lines for every secret file, mode 0600.

    The first line lists the secret names, so the shell scrubber can tell a
    removed secret from an unchanged vault without forking. The cache sits in
    a dot-directory inside the vault: secret scans skip it (not a top-level
    file, not matched by ``*``) and the vault's read guard covers it.
    """
    sdir = Path(secrets_dir)
    names = sorted(e.name for e in os.scandir(sdir) if e.is_file())
    lines = ["#names " + " ".join(names)]
    for name in names:
        try:
            value = (sdir / name).read_text(encoding="utf-8")
        except OSError:
            continue
        if _scrubbable(value):
            lines.extend(f"{name}\t{v}" for v in variants(value))
    cache_dir = sdir / ".meta"
    cache_dir.mkdir(mode=0o700, exist_ok=True)
    tmp = cache_dir / f"encoded.{os.getpid()}"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    final = cache_dir / "encoded"
    os.replace(tmp, final)
    return final


if __name__ == "__main__":
    write_cache(sys.argv[1])
