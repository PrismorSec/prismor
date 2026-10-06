"""The secret-map cache must never serve a stale map.

Masking reads the map once per string; caching it is what keeps a proxied voice
turn fast. The invariant that matters is freshness: a secret added, rewritten
or removed is masked (or not) on the very next read. Placeholder values only.
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from prismor.runtime.cloaking import runtime as cloak  # noqa: E402


@pytest.fixture
def sdir(tmp_path, monkeypatch):
    d = tmp_path / "secrets"
    d.mkdir()
    monkeypatch.setattr(cloak, "secrets_dir", lambda: d)
    cloak._SECRET_MAP_CACHE.clear()
    yield d
    cloak._SECRET_MAP_CACHE.clear()


def _bump(path: Path) -> None:
    # Same-size rewrites inside one mtime tick are what a cache keyed on
    # (mtime, size) could miss; force a distinct mtime the way a real edit has.
    st = path.stat()
    os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000))


def test_hit_returns_the_same_map(sdir):
    (sdir / "api_token").write_text("placeholder-value-one-1234567890", encoding="utf-8")
    first = cloak._read_secret_map()
    assert cloak._read_secret_map() == first == {"api_token": "placeholder-value-one-1234567890"}


def test_added_secret_is_seen_immediately(sdir):
    (sdir / "a").write_text("placeholder-value-aaaaaaaaaaaaaaaa", encoding="utf-8")
    cloak._read_secret_map()
    (sdir / "b").write_text("placeholder-value-bbbbbbbbbbbbbbbb", encoding="utf-8")
    assert set(cloak._read_secret_map()) == {"a", "b"}


def test_rewritten_secret_is_seen_immediately(sdir):
    f = sdir / "a"
    f.write_text("placeholder-value-aaaaaaaaaaaaaaaa", encoding="utf-8")
    cloak._read_secret_map()
    f.write_text("placeholder-value-cccccccccccccccc", encoding="utf-8")   # same size
    _bump(f)
    assert cloak._read_secret_map()["a"] == "placeholder-value-cccccccccccccccc"


def test_removed_secret_is_gone_immediately(sdir):
    (sdir / "a").write_text("placeholder-value-aaaaaaaaaaaaaaaa", encoding="utf-8")
    cloak._read_secret_map()
    (sdir / "a").unlink()
    assert cloak._read_secret_map() == {}


def test_returned_map_cannot_poison_the_cache(sdir):
    (sdir / "a").write_text("placeholder-value-aaaaaaaaaaaaaaaa", encoding="utf-8")
    cloak._read_secret_map()["a"] = "tampered"
    assert cloak._read_secret_map()["a"] == "placeholder-value-aaaaaaaaaaaaaaaa"


def test_scrub_uses_a_secret_added_mid_session(sdir):
    assert cloak.scrub_text("token placeholder-value-zzzzzzzzzzzzzzzz") == \
        "token placeholder-value-zzzzzzzzzzzzzzzz"
    (sdir / "late").write_text("placeholder-value-zzzzzzzzzzzzzzzz", encoding="utf-8")
    assert cloak.scrub_text("token placeholder-value-zzzzzzzzzzzzzzzz") == "token @@SECRET:late@@"
