"""Version-level age and not-found handling in the supply-chain scorer."""
from __future__ import annotations

import io
import json
import urllib.error
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from supplychain.ecosystems import metadata as md
from supplychain.ecosystems.detector import InstallEvent, PackageSpec
from supplychain.ecosystems.metadata import PackageMetadata
from supplychain.scoring.engine import RiskScorer


def _iso(days_ago: float) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat()


def _meta(**kw) -> PackageMetadata:
    base = dict(name="pkg", ecosystem="npm", version="2.0.1", age_days=2000,
                maintainer_count=3, has_install_script=False, source="registry")
    base.update(kw)
    return PackageMetadata(**base)


def _score(meta, custom_registry=None):
    spec = PackageSpec(raw="pkg", name="pkg", source="registry")
    event = InstallEvent(ecosystem="npm", argv=[], packages=[spec], custom_registry=custom_registry)
    with patch("supplychain.scoring.engine.fetch_vulns", return_value=[]):
        return RiskScorer().score(spec, meta, event)


def _ids(v):
    return {s.id for s in v.signals}


def test_fresh_release_of_old_package_warns():
    v = _score(_meta(version_age_days=0))
    assert "very_new_version" in _ids(v)
    assert v.verdict == "warn"


def test_fresh_release_with_install_script_single_maintainer_blocks():
    # The hijacked-maintainer pattern: old package, new version, new postinstall.
    v = _score(_meta(version_age_days=0, has_install_script=True, maintainer_count=1))
    assert v.verdict == "block"


def test_old_release_of_old_package_is_clean():
    v = _score(_meta(version_age_days=400))
    assert not _ids(v) & {"very_new_version", "new_version"}
    assert v.verdict == "allow"


def test_new_package_not_double_counted():
    v = _score(_meta(age_days=1, version_age_days=1))
    assert "very_new_version" not in _ids(v)
    assert "extreme_new_package" in _ids(v)


def test_not_found_warns_unless_custom_registry():
    nf = _meta(version=None, age_days=None, maintainer_count=None, not_found=True)
    assert _score(nf).verdict == "warn"
    assert "package_not_found" in _ids(_score(nf))
    assert "package_not_found" not in _ids(_score(nf, custom_registry="https://npm.corp"))


NPM_DOC = {
    "time": {"created": _iso(2000), "1.0.0": _iso(2000), "2.0.0": _iso(300), "2.0.1": _iso(0.5)},
    "maintainers": [{"name": "a"}],
    "dist-tags": {"latest": "2.0.1", "next": "2.0.0"},
    "versions": {
        "1.0.0": {"scripts": {"postinstall": "node evil.js"}},
        "2.0.0": {},
        "2.0.1": {},
    },
}


def test_npm_fetch_uses_requested_version():
    with patch.object(md, "_http_get", return_value=NPM_DOC):
        latest = md._fetch_npm("pkg", "npm")
        pinned = md._fetch_npm("pkg", "npm", "1.0.0")
        tagged = md._fetch_npm("pkg", "npm", "next")
    assert latest.version == "2.0.1" and latest.version_age_days == 0
    assert latest.age_days >= 1999 and not latest.has_install_script
    # Scripts come from the pinned version, not from latest.
    assert pinned.version == "1.0.0" and pinned.has_install_script
    assert tagged.version == "2.0.0" and tagged.version_age_days >= 299


def test_pypi_fetch_uses_requested_version():
    doc = {"info": {"version": "3.0", "author": "x"},
           "releases": {"1.0": [{"upload_time_iso_8601": _iso(900)}],
                        "3.0": [{"upload_time_iso_8601": _iso(0.2)}]}}
    with patch.object(md, "_http_get", return_value=doc):
        latest = md._fetch_pypi("pkg", "pip")
        pinned = md._fetch_pypi("pkg", "pip", "1.0")
    assert latest.version_age_days == 0 and latest.age_days >= 899
    assert pinned.version == "1.0" and pinned.version_age_days >= 899


def test_http_404_is_distinguished_from_unreachable():
    err404 = urllib.error.HTTPError("u", 404, "nf", {}, io.BytesIO(b""))
    err500 = urllib.error.HTTPError("u", 500, "x", {}, io.BytesIO(b""))
    with patch("urllib.request.urlopen", side_effect=err404):
        assert md._fetch_npm("no-such-pkg-xyz", "npm").not_found
    with patch("urllib.request.urlopen", side_effect=err500):
        m = md._fetch_npm("pkg", "npm")
        assert not m.not_found and m.fetch_error == "registry unreachable"
    with patch("urllib.request.urlopen", side_effect=err404):
        assert md._http_get("u") is None  # default callers unchanged
