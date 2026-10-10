"""Tests for the browser WebMCP inventory (runtime/discover.py).

WebMCP lets a page register tools that an agent in the same tab calls, with no
config file and no child process anywhere in the exchange. What a sweep can see
is the precondition — the experiment enabled, and an extension that speaks the
API — and these tests pin both, plus the two judgement calls the feature rests
on: an extension that cannot reach page context is not a WebMCP consumer, and
none of these findings are allowed to move the coverage score.

Isolated with a fake home laid out for the running platform; no real browser
profile is read.
Run: python3 -m pytest tests/test_discover_webmcp.py
"""
from __future__ import annotations

import json
import os
import platform
import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO))

_INSPECTOR_ID = "gbpdfapgefenggkahomfgkhfehlcenpd"


@pytest.fixture()
def fake_host(tmp_path, monkeypatch):
    """A fake $HOME with no browsers, plus a workspace."""
    home = tmp_path / "home"
    home.mkdir()
    ws = tmp_path / "ws"
    ws.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    monkeypatch.setenv("PRISMOR_HOME", str(home / ".prismor"))
    monkeypatch.setenv("PRISMOR_SECRETS_DIR", str(home / ".prismor" / "secrets"))
    # Windows resolves its user-data dirs from LOCALAPPDATA, not from home.
    monkeypatch.setenv("LOCALAPPDATA", str(home / "AppData" / "Local"))
    for mod in ("prismor.runtime.discover", "prismor.runtime.scanner",
                "prismor.runtime.enterprise.discovery"):
        sys.modules.pop(mod, None)
    from prismor.runtime import discover
    monkeypatch.setattr(discover, "_gateway_servers", lambda: {})
    return discover, home, ws


def _chrome_user_data(home: Path) -> Path:
    """Where Chrome keeps its profiles on the platform this test is running on.

    Mirrors ``discover._browser_user_data_dirs`` so the enumeration itself is
    under test rather than stubbed out.
    """
    system = platform.system()
    if system == "Darwin":
        return home / "Library" / "Application Support" / "Google" / "Chrome"
    if system == "Windows":
        return Path(os.environ["LOCALAPPDATA"]) / "Google" / "Chrome" / "User Data"
    return home / ".config" / "google-chrome"


def _write(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = payload if isinstance(payload, str) else json.dumps(payload)
    path.write_text(text, encoding="utf-8")


def _install_extension(home: Path, ext_id: str, manifest: dict, *,
                       sources: dict = None, version: str = "1.0.0",
                       profile: str = "Default", locales: dict = None) -> Path:
    """Lay down one extension bundle the way Chromium does on disk."""
    bundle = _chrome_user_data(home) / profile / "Extensions" / ext_id / version
    _write(bundle / "manifest.json", manifest)
    for name, body in (sources or {}).items():
        _write(bundle / name, body)
    for locale, messages in (locales or {}).items():
        _write(bundle / "_locales" / locale / "messages.json", messages)
    return bundle


def _enable_flags(home: Path, flags: list) -> None:
    _write(_chrome_user_data(home) / "Local State",
           {"browser": {"enabled_labs_experiments": flags}})


# ── nothing installed ────────────────────────────────────────────────────────

def test_machine_with_no_browsers_reports_nothing(fake_host):
    discover, _, ws = fake_host
    assert discover.discover_webmcp(ws) == []


def test_browser_with_no_local_state_does_not_raise(fake_host):
    """A user-data dir exists but the browser has never been run."""
    discover, home, ws = fake_host
    _chrome_user_data(home).mkdir(parents=True)
    assert discover.discover_webmcp(ws) == []


def test_unreadable_local_state_does_not_raise(fake_host):
    discover, home, ws = fake_host
    _write(_chrome_user_data(home) / "Local State", "{not json")
    assert discover.discover_webmcp(ws) == []


# ── the experiment flag ──────────────────────────────────────────────────────

def test_enabled_flag_is_reported(fake_host):
    discover, home, ws = fake_host
    _enable_flags(home, ["webmcp-for-testing@1"])

    records = discover.discover_webmcp(ws)
    assert len(records) == 1
    flag = records[0]
    assert flag.kind == "flag"
    assert flag.browser == "chrome"
    # The "@1" selects an option of a multi-choice flag; it is not the name.
    assert flag.name == "webmcp-for-testing"
    assert flag.location.endswith("Local State")


@pytest.mark.parametrize("flag", ["enable-webmcp-testing", "devtools-webmcp-support"])
def test_the_flags_chrome_actually_ships_are_matched(fake_host, flag):
    """Both WebMCP entries present in the Chrome 152 binary. Verified against
    /Applications/Google Chrome.app — enabling `WebMCP` there takes
    `document.modelContext` from undefined to a live object that accepts
    registerTool(). If a future Chrome renames these, this is the canary."""
    discover, home, ws = fake_host
    _enable_flags(home, [flag, "enable-quic@1"])
    assert [r.name for r in discover.discover_webmcp(ws)] == [flag]


def test_flag_matching_survives_a_rename(fake_host):
    """Matched on substrings because the flag gets renamed between milestones
    while the capability it gates stays the same."""
    discover, home, ws = fake_host
    _enable_flags(home, ["enable-web-mcp-api@1"])
    assert [r.name for r in discover.discover_webmcp(ws)] == ["enable-web-mcp-api"]


def test_unrelated_flags_are_ignored(fake_host):
    discover, home, ws = fake_host
    _enable_flags(home, ["enable-quic@1", "dark-mode@2"])
    assert discover.discover_webmcp(ws) == []


# ── extensions ───────────────────────────────────────────────────────────────

def test_known_inspector_is_reported_by_id(fake_host):
    """The known-id map names it without needing to read a line of its code."""
    discover, home, ws = fake_host
    _install_extension(home, _INSPECTOR_ID, {"name": "whatever", "version": "1.0.0"})

    records = discover.discover_webmcp(ws)
    assert len(records) == 1
    assert records[0].kind == "extension"
    assert records[0].name == "Model Context Tool Inspector"
    assert records[0].extension_id == _INSPECTOR_ID
    assert records[0].profile == "Default"


def test_unknown_extension_naming_the_api_is_reported(fake_host):
    """The signal that actually matters — an id allowlist would miss this."""
    discover, home, ws = fake_host
    _install_extension(
        home, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        {"name": "Some Agent", "content_scripts": [{"js": ["content.js"]}]},
        sources={"content.js": "const tools = await document.modelContext.getTools();"},
    )

    records = discover.discover_webmcp(ws)
    assert len(records) == 1
    assert records[0].name == "Some Agent"
    assert "WebMCP API" in records[0].findings[0]


def test_ordinary_extension_is_not_reported(fake_host):
    discover, home, ws = fake_host
    _install_extension(
        home, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        {"name": "Ad Blocker", "content_scripts": [{"js": ["content.js"]}]},
        sources={"content.js": "document.querySelectorAll('.ad').forEach(e => e.remove());"},
    )
    assert discover.discover_webmcp(ws) == []


def test_extension_that_cannot_reach_a_page_is_skipped(fake_host):
    """WebMCP is exposed to page context. An extension that never gets there
    cannot be calling it, however its own code happens to read."""
    discover, home, ws = fake_host
    _install_extension(
        home, "cccccccccccccccccccccccccccccccc",
        {"name": "Notes", "permissions": ["storage"]},
        sources={"bg.js": "// modelContext is only mentioned in a comment"},
    )
    assert discover.discover_webmcp(ws) == []


def test_page_access_via_scripting_permission_counts(fake_host):
    """A modern extension reaches pages with `scripting`, not content_scripts."""
    discover, home, ws = fake_host
    _install_extension(
        home, "dddddddddddddddddddddddddddddddd",
        {"name": "Injector", "permissions": ["scripting", "activeTab"]},
        sources={"bg.js": "chrome.scripting.executeScript(() => document.modelContext)"},
    )
    assert len(discover.discover_webmcp(ws)) == 1


def test_localised_name_is_resolved(fake_host):
    discover, home, ws = fake_host
    _install_extension(
        home, "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        {"name": "__MSG_appName__", "default_locale": "fr",
         "content_scripts": [{"js": ["c.js"]}]},
        sources={"c.js": "document.modelContext.getTools()"},
        locales={"fr": {"appName": {"message": "Agent Navigateur"}}},
    )
    assert discover.discover_webmcp(ws)[0].name == "Agent Navigateur"


def test_unresolvable_localised_name_falls_back_to_the_id(fake_host):
    discover, home, ws = fake_host
    ext_id = "ffffffffffffffffffffffffffffffff"
    _install_extension(
        home, ext_id,
        {"name": "__MSG_missing__", "content_scripts": [{"js": ["c.js"]}]},
        sources={"c.js": "document.modelContext.getTools()"},
    )
    assert discover.discover_webmcp(ws)[0].name == ext_id


def test_only_the_newest_installed_version_is_reported(fake_host):
    """Chromium keeps the previous version after an update; reporting both
    would show one extension twice."""
    discover, home, ws = fake_host
    ext_id = "11111111111111111111111111111111"
    manifest = {"name": "Agent", "content_scripts": [{"js": ["c.js"]}]}
    _install_extension(home, ext_id, manifest, version="1.0.0",
                       sources={"c.js": "// nothing yet"})
    _install_extension(home, ext_id, manifest, version="2.0.0",
                       sources={"c.js": "document.modelContext.getTools()"})

    records = discover.discover_webmcp(ws)
    assert len(records) == 1
    assert records[0].location.endswith(os.path.join("2.0.0"))


def test_same_extension_in_two_profiles_reports_once(fake_host):
    discover, home, ws = fake_host
    for profile in ("Default", "Profile 1"):
        _install_extension(
            home, _INSPECTOR_ID, {"name": "Inspector"}, profile=profile)
    assert len(discover.discover_webmcp(ws)) == 1


# ── the report ───────────────────────────────────────────────────────────────

def test_report_carries_the_section_and_its_count(fake_host):
    discover, home, ws = fake_host
    _enable_flags(home, ["webmcp@1"])
    _install_extension(home, _INSPECTOR_ID, {"name": "Inspector"})

    report = discover.build_report(ws, scan_files=False)
    assert len(report["webmcp"]) == 2
    assert report["summary"]["webmcp_total"] == 2


def test_browser_findings_do_not_move_coverage(fake_host):
    """The whole point of keeping this out of the ratio: nothing can govern a
    browser tab, so these findings must not read as skipped coverage."""
    discover, home, ws = fake_host
    before = discover.build_report(ws, scan_files=False)["summary"]

    _enable_flags(home, ["webmcp@1"])
    _install_extension(home, _INSPECTOR_ID, {"name": "Inspector"})
    after = discover.build_report(ws, scan_files=False)["summary"]

    assert after["webmcp_total"] == 2
    assert after["coverage"] == before["coverage"]
    # Nor smuggled into the shadow counts, which feed that ratio.
    for key in ("agents_shadow", "mcp_shadow", "credentials_shadow"):
        assert after[key] == before[key]


def test_payload_reports_browser_findings_as_uncoverable(fake_host):
    """`coverable: false` is the flag the console already reads as "not a
    gap" — the same treatment an agent with no hook surface gets."""
    discover, home, ws = fake_host
    _install_extension(home, _INSPECTOR_ID, {"name": "Inspector"})

    payload = discover.report_payload(discover.build_report(ws, scan_files=False))
    browser = [f for f in payload["findings"] if f["kind"] == "browser"]
    assert len(browser) == 1
    assert browser[0]["managed"] is False
    assert browser[0]["coverable"] is False
    assert browser[0]["fixable"] is False
    assert browser[0]["name"] == "Model Context Tool Inspector"


def test_report_is_json_serialisable(fake_host):
    discover, home, ws = fake_host
    _enable_flags(home, ["webmcp@1"])
    report = discover.build_report(ws, scan_files=False)
    assert json.loads(json.dumps(report))["webmcp"][0]["kind"] == "flag"


# ── bounds ───────────────────────────────────────────────────────────────────

def test_source_scan_is_bounded(fake_host, monkeypatch):
    """A bundle's size is chosen by whoever published it, and this runs on a
    schedule — the scan gives up rather than reading an unbounded tree.

    Also pins the ordering: the walk is sorted, so the two files scanned here
    are the two that sort first on every platform. Unsorted, os.walk hands back
    filesystem order — arbitrary on ext4 — and whether the marker in the last
    file was reached would differ between a developer's Mac and CI.
    """
    discover, home, ws = fake_host
    monkeypatch.setattr(discover, "_MAX_EXT_SCAN_FILES", 2)
    sources = {f"chunk{i}.js": "// filler" for i in range(5)}
    sources["zzz_last.js"] = "document.modelContext.getTools()"
    _install_extension(
        home, "22222222222222222222222222222222",
        {"name": "Big", "content_scripts": [{"js": ["chunk0.js"]}]},
        sources=sources,
    )
    assert discover.discover_webmcp(ws) == []
