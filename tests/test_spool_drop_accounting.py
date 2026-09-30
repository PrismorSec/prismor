"""Records the offline spool drops are counted and reported, not lost silently.

  * filling past the cap bumps a persisted drop counter (with the ts window);
  * the next successful upload emits exactly one chained `telemetry_dropped`
    record and resets the counter;
  * a network failure starts a capped backoff that non-blocked uploads respect.
"""
import json

import prismor.runtime.sinks as sinks
import prismor.runtime.enterprise.identity as ident
import prismor.runtime.enterprise.telemetry_spool as spool


class _Resp:
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self, n=-1):
        return b"{}"


def _setup(monkeypatch, tmp_path):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path))
    ident.save_identity({
        "device_id": "d", "org_id": "o", "user_id": "u",
        "device_key": "prism_dev_x", "api_base": "http://127.0.0.1:1",
    })
    monkeypatch.setattr(spool, "SPOOL_MAX_RECORDS", 5)
    posts = []

    def fake_urlopen(req, timeout=None):
        posts.append(json.loads(req.data)["events"])
        return _Resp()

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    return posts


def _rec(i):
    return {"ts": f"2099-01-01T00:00:{i:02d}Z", "verdict": "observed", "n": i}


def test_cap_eviction_is_counted_then_reported_once(monkeypatch, tmp_path):
    posts = _setup(monkeypatch, tmp_path)

    spool.append([_rec(i) for i in range(8)])
    assert spool.pending_count() == 5
    state = json.loads(spool.drops_path().read_text())
    assert state == {"count": 3, "first_ts": "2099-01-01T00:00:00Z", "last_ts": "2099-01-01T00:00:02Z"}

    sinks.upload_telemetry([])

    assert len(posts) == 2
    assert [r["n"] for r in posts[0]] == [3, 4, 5, 6, 7]
    assert len(posts[1]) == 1
    dropped = posts[1][0]
    assert dropped["type"] == "telemetry_dropped" and dropped["count"] == 3
    assert "chain_seq" in dropped and "hash" in dropped
    assert not spool.drops_path().exists()

    sinks.upload_telemetry([_rec(9)])
    assert len(posts) == 3 and posts[2][0]["n"] == 9  # no second report


def test_network_failure_backs_off_but_blocked_still_attempts(monkeypatch, tmp_path):
    posts = _setup(monkeypatch, tmp_path)
    import urllib.error

    def down(req, timeout=None):
        posts.append("attempt")
        raise urllib.error.URLError("offline")

    monkeypatch.setattr("urllib.request.urlopen", down)

    try:
        sinks.upload_telemetry([_rec(0)])
    except urllib.error.URLError:
        pass
    assert posts == ["attempt"]

    sinks.upload_telemetry([_rec(1)])  # inside backoff: spooled, no network
    assert posts == ["attempt"] and spool.pending_count() == 2

    try:
        sinks.upload_telemetry([{**_rec(2), "verdict": "blocked"}])
    except urllib.error.URLError:
        pass
    assert posts == ["attempt", "attempt"]
