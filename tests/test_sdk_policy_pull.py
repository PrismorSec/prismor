"""An SDK adapter / eval-server never runs `prismor enroll`, so evaluate_tool_call
itself must keep the org policy fresh — otherwise an agent-key workload gets no
telemetry sink, no org mode and no console tool denies."""
from __future__ import annotations

from prismor.runtime.enterprise import remote_policy
from prismor.runtime.runtime import evaluate_tool_call


def test_evaluate_tool_call_refreshes_org_policy(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / "home"))
    calls = []
    monkeypatch.setattr(remote_policy, "check_and_refresh", lambda *a, **k: calls.append(1) or False)
    evaluate_tool_call(
        event={"type": "shell", "command": "echo hi", "agent_event": "PreToolUse",
               "metadata": {"tool_name": "run_shell"}},
        workspace=tmp_path, agent="openai-agents", session_id="s1",
        mode="observe", persist=False, register_agent=False,
    )
    assert calls == [1]


def test_first_check_pulls_when_nothing_cached(tmp_path, monkeypatch):
    """No cached version + server has one -> the check triggers a full fetch."""
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / "home"))
    monkeypatch.setattr(remote_policy._identity, "load_identity", lambda: {
        "device_id": "d", "org_id": "o", "device_key": "k", "api_base": "http://cp"})
    monkeypatch.setattr(remote_policy._identity, "revoked_backoff_active", lambda: False)

    class _Resp:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self): return b'{"version": 3}'

    monkeypatch.setattr("urllib.request.urlopen", lambda *a, **k: _Resp())
    fetched = []
    monkeypatch.setattr(remote_policy, "fetch", lambda **k: fetched.append(k) or True)
    assert remote_policy.check_and_refresh() is True
    assert fetched == [{"force": True}]
