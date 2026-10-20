"""Pinned (safety-floor) rules turned off with the unlock password (floor_off.py)."""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from prismor.runtime import floor_off, unlock
from prismor.runtime.policy_engine import PolicyEngine


def _ids(tmp_path):
    return {r.id for r in PolicyEngine(workspace=tmp_path).rules}


def test_floor_rule_off_only_with_a_valid_record(tmp_path):
    assert "destructive-command" in _ids(tmp_path)
    with pytest.raises(ValueError):  # no password set yet: nothing to sign with
        floor_off.turn_off("destructive-command")
    unlock.set_password("correct horse battery staple")
    floor_off.turn_off("destructive-command", by="tester")
    assert "destructive-command" not in _ids(tmp_path)

    # A record edited without the credential is ignored, so the rule is back.
    rec = json.loads(floor_off.path().read_text())
    rec["rules"]["secret-exfiltration"] = {"at": "", "by": "agent"}
    floor_off.path().write_text(json.dumps(rec))
    assert {"destructive-command", "secret-exfiltration"} <= _ids(tmp_path)


def test_self_protection_and_turn_on(tmp_path):
    unlock.set_password("correct horse battery staple")
    with pytest.raises(ValueError):
        floor_off.turn_off("prismor-self-edit")
    floor_off.turn_off("privilege-escalation")
    assert "privilege-escalation" not in _ids(tmp_path)
    floor_off.turn_on("privilege-escalation")
    assert "privilege-escalation" in _ids(tmp_path)


def test_dashboard_endpoint_needs_the_password(tmp_path, monkeypatch):
    import http.client
    import threading
    from http.server import ThreadingHTTPServer
    from prismor.runtime import server as srv

    monkeypatch.setattr(srv, "_SERVER_WORKSPACE", tmp_path)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), srv.PrismorRequestHandler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()

    def post(body):
        conn = http.client.HTTPConnection("127.0.0.1", httpd.server_address[1], timeout=10)
        conn.request("POST", "/api/policy/floor-off", body=json.dumps(body), headers={"Content-Type": "application/json"})
        r = conn.getresponse(); data = json.loads(r.read() or b"{}"); conn.close()
        return r.status, data

    try:
        unlock.set_password("correct horse battery staple")
        assert post({"rule": "destructive-command", "off": True, "password": "nope"})[0] == 401
        assert post({"rule": "prismor-self-edit", "off": True, "password": "correct horse battery staple"})[0] == 403
        assert post({"rule": "prompt-injection", "off": True, "password": "correct horse battery staple"})[0] == 400
        assert floor_off.active_ids() == set()
        assert post({"rule": "destructive-command", "off": True, "password": "correct horse battery staple"})[0] == 200
        assert floor_off.active_ids() == {"destructive-command"}
        assert post({"rule": "destructive-command", "off": False})[0] == 200  # back on: no password
        assert floor_off.active_ids() == set()
    finally:
        httpd.shutdown(); httpd.server_close()
