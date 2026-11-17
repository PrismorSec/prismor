"""Authority changes after the allow (#942): commit-time re-check, cancel in flight.

Run: python3 -m pytest tests/test_inflight.py
"""
from __future__ import annotations

import asyncio
import sys
import threading
import time
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO))

from prismor.runtime import inflight  # noqa: E402
from prismor.runtime.runtime import Decision  # noqa: E402

POLICY = (
    'version: "1.0"\nrules:\n'
    "  - id: t-restricted\n    title: restricted account\n    severity: CRITICAL\n"
    "    category: custom-authz\n    event_types: [shell]\n"
    "    when: \"resource.attr.status == 'restricted'\"\n    action: block\n    mode: enforce\n"
)


@pytest.fixture(autouse=True)
def _quiet(monkeypatch):
    from prismor.runtime.enterprise import remote_policy
    monkeypatch.setattr(remote_policy, "check_and_refresh", lambda interval=None: False)
    recorded = []
    from prismor.runtime.enterprise import audit_trail
    monkeypatch.setattr(audit_trail, "enabled", lambda: True)
    monkeypatch.setattr(audit_trail, "append_approval_record", lambda **kw: recorded.append(kw))
    return recorded


def _decide(ws, status):
    from prismor.runtime.runtime import evaluate_tool_call
    event = {"type": "shell", "command": "freeze_account account=ACC-1",
             "agent": "python-sdk", "agent_event": "PreToolUse",
             "metadata": {"tool_name": "freeze_account", "framework": "python-sdk"}}
    return evaluate_tool_call(event=event, workspace=ws, agent="python-sdk", session_id="s1",
                              resource={"kind": "account", "id": "ACC-1", "attr": {"status": status}},
                              register_agent=False, flush_at_exit=False)


@pytest.fixture()
def ws(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / "home"))
    w = tmp_path / "ws"
    (w / ".prismor").mkdir(parents=True)
    (w / ".prismor" / "policy.yaml").write_text(POLICY)
    return w


def _gate(state):
    """A Decision whose re-check reads ``state['allow']`` / ``state['rule']``."""
    def recheck(resource=None):
        if state["allow"]:
            return Decision(allow=True)
        return Decision(allow=False, blocking={"action": "block", "ruleId": state["rule"]},
                        reason=f"{state['rule']} fired")
    return Decision(allow=True, recheck=recheck)


# ── commit-time re-check ─────────────────────────────────────────────────────

def test_allowed_decision_carries_a_recheck(ws):
    d = _decide(ws, "active")
    assert d.allow and d.recheck is not None


def test_restriction_after_allow_refuses_at_commit(ws, _quiet):
    d = _decide(ws, "active")
    inflight.recheck_before_commit(d, resource={"kind": "account", "id": "ACC-1",
                                                "attr": {"status": "active"}})  # unchanged: passes
    account = {"status": "active"}
    account["status"] = "restricted"  # set by ops while the tool did its lookups
    with pytest.raises(inflight.Refused) as exc:
        inflight.recheck_before_commit(
            d, resource=lambda: {"kind": "account", "id": "ACC-1", "attr": dict(account)},
            tool="freeze_account", session_id="s1")
    assert exc.value.status == "revoked_before_commit" and exc.value.rule == "t-restricted"
    assert _quiet[-1]["status"] == "revoked_before_commit"
    assert _quiet[-1]["rules"] == ["t-restricted"]
    assert _quiet[-1]["resource"]["attr"]["status"] == "restricted"


def test_approved_step_up_is_not_refused_by_its_own_rule():
    d = Decision(allow=False, blocking={"action": "step_up", "ruleId": "needs-human"},
                 recheck=lambda r=None: Decision(allow=False, blocking={"action": "step_up",
                                                                       "ruleId": "needs-human"}))
    inflight.recheck_before_commit(d)  # no raise


def test_recheck_error_fails_closed():
    def boom(r=None):
        raise RuntimeError("engine down")
    with pytest.raises(inflight.Refused):
        inflight.recheck_before_commit(Decision(allow=True, recheck=boom))


# ── cancel in flight ─────────────────────────────────────────────────────────

def test_async_tool_cancelled_after_pause(_quiet):
    state = {"allow": True, "rule": "org-paused"}
    cancelled = []

    async def long_tool():
        try:
            await asyncio.sleep(5)
        except asyncio.CancelledError:
            cancelled.append(True)
            raise

    async def main():
        loop = asyncio.get_running_loop()
        loop.call_later(0.1, lambda: state.update(allow=False))  # pause lands mid-call
        t0 = time.monotonic()
        with pytest.raises(inflight.Refused) as exc:
            await inflight.run_cancellable(_gate(state), long_tool(), every=0.05, tool="t")
        return exc.value, time.monotonic() - t0

    err, took = asyncio.run(main())
    assert err.status == "cancelled_in_flight" and err.rule == "org-paused"
    assert cancelled and took < 1.0
    assert _quiet[-1]["status"] == "cancelled_in_flight"


def test_async_tool_that_stays_allowed_returns():
    async def quick():
        await asyncio.sleep(0.12)
        return 42
    state = {"allow": True, "rule": "x"}
    assert asyncio.run(inflight.run_cancellable(_gate(state), quick(), every=0.03)) == 42


def test_blocking_call_stops_waiting_and_cancels():
    state = {"allow": True, "rule": "subject-paused"}
    release = threading.Event()
    sent = []
    threading.Timer(0.1, lambda: state.update(allow=False)).start()
    with pytest.raises(inflight.Refused):
        inflight.wait_cancellable(_gate(state), lambda: release.wait(5), every=0.05,
                                  on_cancel=lambda: sent.append("cancel"))
    release.set()
    assert sent == ["cancel"]


def test_blocking_call_errors_propagate():
    def bad():
        raise ValueError("upstream down")
    with pytest.raises(ValueError):
        inflight.wait_cancellable(_gate({"allow": True, "rule": "x"}), bad, every=0.05)


# ── MCP gateway ──────────────────────────────────────────────────────────────

def test_gateway_cancels_inflight_call_on_revoke(tmp_path, monkeypatch):
    from prismor.runtime import mcp_gateway as gw_mod
    from tests.test_mcp_gateway import FakeUpstream, UpstreamSpec, list_tools, make_gateway

    release = threading.Event()

    class Slow(FakeUpstream):
        def request(self, method, params, timeout=30.0):
            if method == "tools/call":
                gw_mod._note_call_id("gw-7")
                release.wait(5)
            return super().request(method, params, timeout)

    up = Slow(UpstreamSpec(name="bank", command=["true"], transport="stdio"))
    gateway, sent = make_gateway(tmp_path, monkeypatch, [up])
    monkeypatch.setattr("prismor.runtime.runtime.evaluate_tool_call", lambda **k: Decision(allow=True))
    list_tools(gateway, sent)
    state = {"allow": True, "rule": "org-paused"}
    monkeypatch.setattr("prismor.runtime.runtime.evaluate_tool_call", lambda **k: _gate(state))
    monkeypatch.setattr(inflight, "interval", lambda: 0.05)
    threading.Timer(0.1, lambda: state.update(allow=False)).start()
    gateway._handle_tools_call_safe("C1", {"name": "bank__echo", "arguments": {}})
    release.set()
    text = sent[-1]["result"]["content"][0]["text"]
    assert "cancelled_in_flight" in text and "org-paused" in text
    assert ("notifications/cancelled", {"requestId": "gw-7", "reason": "authority revoked by Prismor"}) in up.requests
