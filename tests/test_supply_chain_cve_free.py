"""The install check lets a package through only when OSV confirms the exact
version has no known vulnerability; anything it cannot verify blocks."""
from unittest.mock import patch

import pytest

from prismor.runtime.policy_engine import PolicyEngine
from supplychain.ecosystems import metadata as md
from supplychain.ecosystems.detector import InstallEvent, PackageSpec, detect_install
from supplychain.ecosystems.metadata import PackageMetadata
from supplychain.scoring import osv_lookup
from supplychain.scoring.engine import RiskScorer

LOW = {"id": "GHSA-low", "severity": "low", "title": "GHSA-low: minor", "malicious": False}


def _meta(version="1.0.0", source="registry", eco="npm"):
    return PackageMetadata(name="pkg", ecosystem=eco, version=version, age_days=900,
                           maintainer_count=4, has_install_script=False, source=source)


def _score(raw, vulns, *, version="", meta=None, name="pkg", **kw):
    spec = PackageSpec(raw=raw, name=name, source=(meta or _meta()).source, version=version)
    with patch("supplychain.scoring.engine.fetch_vulns", return_value=vulns):
        return RiskScorer(**kw).score(
            spec, meta or _meta(), InstallEvent(ecosystem="npm", argv=[], packages=[]))


def _ids(verdict):
    return {s.id for s in verdict.signals}


# ── scorer ────────────────────────────────────────────────────────────────

def test_clean_pinned_version_installs():
    assert _score("pkg@1.0.0", [], version="1.0.0").verdict == "allow"


def test_any_cve_blocks():
    v = _score("pkg@1.0.0", [LOW], version="1.0.0")
    assert v.verdict == "block" and "osv_low" in _ids(v)


def test_osv_unreachable_blocks():
    v = _score("pkg@1.0.0", None, version="1.0.0")
    assert v.verdict == "block" and "unverified_osv" in _ids(v)


def test_unpinned_checks_the_registry_latest():
    assert _score("pkg", [], meta=_meta(version="2.0.0")).verdict == "allow"


@pytest.mark.parametrize("raw, meta", [
    ("pkg", _meta(version=None)),       # registry gave no version
    ("pkg@^4", _meta(version="5.0.0")),  # npm picks within ^4, not latest
    ("pkg>=2", _meta(version="5.0.0")),
])
def test_unresolved_version_blocks(raw, meta):
    v = _score(raw, [], meta=meta)
    assert v.verdict == "block" and "unverified_version" in _ids(v)


@pytest.mark.parametrize("source", ["git", "tarball"])
def test_git_and_tarball_sources_block(source):
    assert _score("github:a/pkg", [], meta=_meta(source=source)).verdict == "block"


def test_local_path_installs():
    assert _score(".", [], meta=_meta(source="local")).verdict == "allow"


def test_allowlist_lets_a_named_package_through():
    assert _score("pkg@1.0.0", [LOW], version="1.0.0", allowlist={"pkg"}).verdict == "warn"


# ── OSV lookup ────────────────────────────────────────────────────────────

def test_fetch_vulns_tells_failure_from_clean():
    osv_lookup._CACHE.clear()
    with patch.object(osv_lookup, "_post_json", return_value=None) as post:
        assert osv_lookup.fetch_vulns("a", "npm", "1.0.0") is None
        assert osv_lookup.fetch_vulns("a", "npm", "1.0.0") is None
        assert post.call_count == 2, "a failed lookup is not cached as clean"
    with patch.object(osv_lookup, "_post_json", return_value={}):
        assert osv_lookup.fetch_vulns("b", "npm", "1.0.0") == []
    osv_lookup._CACHE.clear()


# ── parsing and metadata ──────────────────────────────────────────────────

@pytest.mark.parametrize("arg, name, version", [
    ("github.com/gin-gonic/gin@v1.9.0", "github.com/gin-gonic/gin", "1.9.0"),
    ("golang.org/x/net@latest", "golang.org/x/net", ""),
    ("golang.org/x/net", "golang.org/x/net", ""),
])
def test_go_module_version_is_split_from_the_name(arg, name, version):
    (spec,) = detect_install(["go", "get", arg]).packages
    assert (spec.name, spec.version) == (name, version)


@pytest.mark.parametrize("argv", [["pip", "install", "."], ["pip", "install", "-e", "."]])
def test_installing_the_current_project_is_local(argv):
    (spec,) = detect_install(argv).packages
    assert spec.source == "local"


def test_gem_inexact_version_flag_reads_as_a_range():
    (spec,) = detect_install(["gem", "install", "rails", "-v", "~> 7.1"]).packages
    v = _score(spec.raw, [], meta=_meta(version="8.0.0", eco="gem"), name=spec.name)
    assert spec.raw == "rails:~> 7.1" and "unverified_version" in _ids(v)


def test_npm_scripts_come_from_the_pinned_version():
    doc = {"dist-tags": {"latest": "2.0.0"}, "time": {}, "maintainers": [{}],
           "versions": {"1.0.0": {"scripts": {"postinstall": "node x.js"}}, "2.0.0": {}}}
    with patch.object(md, "_http_get", return_value=doc):
        assert md._fetch_npm("p", "npm", "1.0.0").has_install_script
        assert not md._fetch_npm("p", "npm").has_install_script


def test_pypi_sdist_only_release_counts_as_install_code():
    doc = {"info": {"version": "2.0"}, "releases": {
        "1.0": [{"packagetype": "sdist"}],
        "2.0": [{"packagetype": "sdist"}, {"packagetype": "bdist_wheel"}]}}
    with patch.object(md, "_http_get", return_value=doc):
        assert md._fetch_pypi("p", "pip", "1.0").has_install_script
        assert not md._fetch_pypi("p", "pip").has_install_script


# ── hook path ─────────────────────────────────────────────────────────────

@pytest.fixture
def engine():
    e = PolicyEngine()
    e.default_mode, e.device_mode = "enforce", None
    return e


def _dep(findings):
    return [f for f in findings if f["ruleId"] == "pkg-install-vulnerable-version"]


def _offline(vulns):
    meta = patch("supplychain.ecosystems.metadata.fetch_metadata", return_value=_meta())
    osv = patch("supplychain.scoring.engine.fetch_vulns", return_value=vulns)
    safe = patch("supplychain.scoring.safe_version.recommend_safe_version", return_value=None)
    return meta, osv, safe


@pytest.mark.parametrize("mode", ["enforce", "observe"])
def test_hook_blocks_cve_in_the_policy_mode(engine, mode):
    engine.default_mode = mode
    meta, osv, safe = _offline([LOW])
    with meta, osv, safe:
        (f,) = _dep(engine.check_command("npm install pkg@1.0.0"))
    assert f["action"] == "block" and f["mode"] == mode


def test_hook_fails_closed_when_the_check_errors(engine):
    with patch("supplychain.ecosystems.metadata.fetch_metadata", side_effect=RuntimeError("boom")):
        (f,) = _dep(engine.check_command("npm install pkg@1.0.0"))
    assert f["action"] == "block" and "boom" in f["evidence"]


def test_hook_refuses_packages_past_the_cap(engine):
    pkgs = " ".join(f"p{i}@1.0.0" for i in range(10))
    meta, osv, safe = _offline([])
    with meta, osv, safe:
        found = _dep(engine.check_command(f"npm install {pkgs}"))
    assert [f["evidence"].split(" ")[0] for f in found] == ["p8@1.0.0", "p9@1.0.0"]
    assert all(f["action"] == "block" for f in found)
