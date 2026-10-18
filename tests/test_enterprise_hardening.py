"""Tests for enterprise-link hardening:

  * Offline telemetry spool — bounded, at-least-once drain semantics.
  * Revocation marker — 401/403 from the control plane pauses uploads/pulls
    and surfaces in enroll-status; re-enrollment clears it.
  * block_categories clamp — an override layer cannot drop core categories
    from blocking.
"""
from __future__ import annotations

import json
import time

import pytest


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / ".prismor"))
    yield


# ── telemetry spool ─────────────────────────────────────────────────────


def test_spool_append_and_drain_fifo():
    from prismor.runtime.enterprise import telemetry_spool as spool

    spool.append([{"n": 1}, {"n": 2}])
    spool.append([{"n": 3}])
    assert spool.pending_count() == 3

    taken = spool.drain(limit=2)
    assert [r["n"] for r in taken] == [1, 2]
    assert spool.pending_count() == 1

    rest = spool.drain(limit=10)
    assert [r["n"] for r in rest] == [3]
    assert spool.pending_count() == 0
    assert spool.drain(limit=5) == []


def test_spool_is_bounded_drops_oldest():
    from prismor.runtime.enterprise import telemetry_spool as spool

    spool.append([{"n": i} for i in range(spool.SPOOL_MAX_RECORDS + 50)])
    assert spool.pending_count() == spool.SPOOL_MAX_RECORDS
    first = spool.drain(limit=1)[0]
    assert first["n"] == 50  # oldest 50 were dropped


def test_spool_survives_corrupt_lines(tmp_path):
    from prismor.runtime.enterprise import telemetry_spool as spool

    spool.append([{"n": 1}])
    with open(spool.spool_path(), "a", encoding="utf-8") as f:
        f.write("not json\n")
    spool.append([{"n": 2}])
    assert [r["n"] for r in spool.drain(limit=10)] == [1, 2]


# ── revocation marker ───────────────────────────────────────────────────


def test_revocation_marker_roundtrip():
    from prismor.runtime.enterprise import identity

    assert identity.revoked_info() is None
    assert not identity.revoked_backoff_active()

    identity.mark_revoked("telemetry upload rejected (401)")
    info = identity.revoked_info()
    assert info and "401" in info["reason"]
    assert identity.revoked_backoff_active()

    identity.clear_revoked()
    assert identity.revoked_info() is None


def test_revocation_backoff_expires(monkeypatch):
    from prismor.runtime.enterprise import identity

    identity.mark_revoked("rejected")
    # Age the marker past the retry window.
    marker = identity._revoked_marker_path()
    data = json.loads(marker.read_text(encoding="utf-8"))
    data["at"] = time.time() - identity.REVOKED_RETRY_SECONDS - 1
    marker.write_text(json.dumps(data), encoding="utf-8")
    assert not identity.revoked_backoff_active()


def test_policy_check_skipped_while_revoked(monkeypatch):
    from prismor.runtime.enterprise import identity, remote_policy

    identity.save_identity({
        "device_id": "d1", "org_id": "o1", "user_id": "u1",
        "device_key": "prism_dev_x", "api_base": "http://127.0.0.1:1",
    })
    identity.mark_revoked("rejected")

    def _boom(*a, **k):  # any network call would be a bug
        raise AssertionError("network call attempted while revoked")

    import urllib.request
    monkeypatch.setattr(urllib.request, "urlopen", _boom)
    assert remote_policy.check_and_refresh(interval=0) is False
    assert remote_policy.fetch(force=True) is False


@pytest.mark.parametrize("revoked", [False, True])
def test_enroll_status_reports_before_remote_check(tmp_path, monkeypatch, capsys, revoked):
    from prismor.runtime import cli, hooks
    from prismor.runtime.enterprise import identity

    identity.save_identity({"device_id": "d1", "org_id": "o1",
                            "device_key": "prism_dev_test", "api_base": "https://example.test"})
    if revoked:
        identity.mark_revoked("rejected (401)")

    def verify():
        assert not revoked, "a locally revoked device should report without a network call"
        assert "Checking enrollment" in capsys.readouterr().out
        return {"ok": False, "error": "unreachable (URLError)"}

    monkeypatch.setattr(identity, "verify_remote", verify)
    monkeypatch.setattr(hooks, "coverage", lambda _workspace: {})
    cli.main(["--workspace", str(tmp_path), "enroll-status"])
    output = capsys.readouterr().out
    assert ("REJECTED" if revoked else "control plane unreachable") in output


# ── control plane unreachable: one shared backoff ───────────────────────


def _enroll():
    from prismor.runtime.enterprise import identity

    identity.save_identity({
        "device_id": "d1", "org_id": "o1", "user_id": "u1",
        "device_key": "prism_dev_x", "api_base": "http://127.0.0.1:1",
    })


def test_policy_check_network_failure_starts_backoff(monkeypatch):
    """On a network that drops packets every hot-path check waited the full
    timeout; a failed check must back off the next ones instead."""
    import urllib.error
    import urllib.request
    from prismor.runtime.enterprise import remote_policy, telemetry_spool as spool

    _enroll()
    calls = []

    def _timeout(*a, **k):
        calls.append(1)
        raise urllib.error.URLError(TimeoutError("timed out"))

    monkeypatch.setattr(urllib.request, "urlopen", _timeout)
    monkeypatch.setattr(remote_policy, "_refresh_interval", lambda: 0.0)
    assert remote_policy.check_and_refresh() is False
    assert spool.backoff_active(time.time())
    assert remote_policy.check_and_refresh() is False  # hot path: skipped
    assert len(calls) == 1
    remote_policy.check_and_refresh(interval=0)  # explicit: still tries
    assert len(calls) == 2


def test_policy_check_success_clears_backoff(monkeypatch):
    import io
    import urllib.request
    from prismor.runtime.enterprise import remote_policy, telemetry_spool as spool

    _enroll()
    spool.note_upload_failure(time.time())
    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: io.BytesIO(b'{"version": null}'))
    remote_policy.check_and_refresh(interval=0)
    assert not spool.backoff_active(time.time())


def test_extensions_report_respects_backoff(tmp_path, monkeypatch):
    import urllib.request
    from prismor.runtime import extensions
    from prismor.runtime.enterprise import telemetry_spool as spool

    _enroll()
    spool.note_upload_failure(time.time())
    calls = []

    def _refused(*a, **k):  # send_report swallows exceptions, so count instead
        calls.append(1)
        raise OSError("refused")

    monkeypatch.setattr(urllib.request, "urlopen", _refused)
    assert extensions.send_report(tmp_path) is False
    assert calls == []
    extensions.send_report(tmp_path, force=True)  # `prismor extensions report`
    assert calls == [1]


# ── block_categories clamp ──────────────────────────────────────────────


def test_override_cannot_drop_core_block_categories(tmp_path):
    from prismor.runtime.policy_engine import PolicyEngine, _CORE_BLOCK_CATEGORIES

    ws = tmp_path / "ws"
    (ws / ".prismor").mkdir(parents=True)
    (ws / ".prismor" / "policy.yaml").write_text(
        "settings:\n  block_categories: [prompt_injection]\n",
        encoding="utf-8",
    )
    engine = PolicyEngine(workspace=ws)
    assert "prompt_injection" in engine.block_categories  # tightening kept
    for cat in _CORE_BLOCK_CATEGORIES:
        assert cat in engine.block_categories  # core restored


# ── device-level mode override propagation ──────────────────────────────


def test_current_device_mode_parses_cached_policy(monkeypatch):
    """_current_device_mode mirrors the server's deviceMode field: the cached
    policy's settings.device_mode normalized to observe/enforce, else ""."""
    from prismor.runtime.enterprise import remote_policy

    monkeypatch.setattr(remote_policy, "verify_and_load", lambda: {"settings": {"device_mode": "Enforce"}})
    assert remote_policy._current_device_mode() == "enforce"

    monkeypatch.setattr(remote_policy, "verify_and_load", lambda: {"settings": {"device_mode": "observe"}})
    assert remote_policy._current_device_mode() == "observe"

    monkeypatch.setattr(remote_policy, "verify_and_load", lambda: {"settings": {}})
    assert remote_policy._current_device_mode() == ""

    # An unknown value must read as "no override", matching the engine's
    # own validation — never a stuck re-pull loop on a junk value.
    monkeypatch.setattr(remote_policy, "verify_and_load", lambda: {"settings": {"device_mode": "paused"}})
    assert remote_policy._current_device_mode() == ""

    monkeypatch.setattr(remote_policy, "verify_and_load", lambda: None)
    assert remote_policy._current_device_mode() == ""
