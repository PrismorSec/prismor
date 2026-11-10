"""Sliding-window admissions: atomic across processes, persistent, bounded."""
from __future__ import annotations

import json
import multiprocessing
import sqlite3
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import pytest
import yaml

from prismor.runtime import ratelimit, store
from prismor.runtime.policy_engine import PolicyEngine, validate_policy
from prismor.runtime.principal import Subject
from prismor.runtime.runtime import evaluate_tool_call


def policy(workspace, limit=2, burst=0, mode="enforce"):
    path = workspace / ".prismor" / "policy.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump({
        "version": "1.0", "settings": {"rate_limit": {
            "requests_per_minute": limit, "max_burst": burst}},
        "rules": [{"id": name, "mode": mode} for name in
                  ("rate-limit-exceeded", "rate-limit-unavailable")],
    }))
    return path


def decide(workspace, **kwargs):
    event = kwargs.pop("event", {"type": "shell", "command": "echo harmless",
                                  "agent_event": "PreToolUse"})
    return evaluate_tool_call(event=event, workspace=workspace, agent="test",
                              persist=False, record=False, register_agent=False,
                              flush_at_exit=False, **kwargs)


def reserve(workspace, *, limit=2, burst=0, **kwargs):
    identity = kwargs.pop("identity", "agent-a")
    return ratelimit.admit(workspace, identity,
                           {"requests_per_minute": limit, "max_burst": burst}, **kwargs)


def rows():
    with sqlite3.connect(store.existing_db_path()) as db:
        return db.execute("SELECT COUNT(*) FROM rate_limit_admissions").fetchone()[0]


def _race_admit(args):
    home, workspace = args
    import os
    os.environ["PRISMOR_HOME"] = home
    return reserve(Path(workspace), limit=4, now=100)


def test_exact_window_and_additive_burst(tmp_path):
    for i in range(3):
        result = reserve(tmp_path, burst=1, now=100)
        assert result["count"] == i + 1
        assert result["error"] is None
    assert reserve(tmp_path, burst=1, now=159.999)["count"] == 4
    assert rows() == 3
    assert reserve(tmp_path, burst=1, now=160)["used"] == 1
    assert rows() == 1


def test_denials_bounded_and_pruning_inactive_identities(tmp_path):
    reserve(tmp_path, identity="inactive", now=100)
    reserve(tmp_path, limit=1, now=100)
    for _ in range(20):
        assert reserve(tmp_path, limit=1, now=100)["count"] == 2
    assert rows() == 2
    reserve(tmp_path, now=160)
    assert rows() == 1


def test_scope_restart_and_clock_rollback(tmp_path):
    first = tmp_path / "one"
    first.mkdir()
    assert reserve(first, limit=1, now=100)["used"] == 1
    assert reserve(first, limit=1, now=50)["count"] == 2
    assert reserve(first, limit=1, identity="other", now=50)["count"] == 1
    assert reserve(tmp_path / "two", limit=1, now=50)["count"] == 1
    assert reserve(first, limit=1, now=1000)["count"] == 1


def test_workspace_symlink_cannot_reset_quota(tmp_path):
    first = tmp_path / "one"
    first.mkdir()
    alias = tmp_path / "alias"
    try:
        alias.symlink_to(first, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are unavailable on this host")
    reserve(first, limit=1, now=100)
    assert reserve(alias, limit=1, now=100)["count"] == 2


def test_real_process_restart_and_atomic_concurrency(tmp_path):
    # Initialize the schema before racing admissions, not the reservations.
    store.initialize_database(tmp_path)
    args = (str(store.prismor_home()), str(tmp_path))
    with ProcessPoolExecutor(max_workers=6, mp_context=multiprocessing.get_context("spawn")) as pool:
        results = list(pool.map(_race_admit, [args] * 20))
    admitted = sum(r["error"] is None and r["count"] <= 4 for r in results)
    assert admitted <= 4
    assert all(r["error"] in (None, "OperationalError") for r in results)
    assert rows() == admitted
    # A busy timeout is a fail-closed result, not an admission. Once the
    # competing processes exit, remaining capacity is still usable and the
    # next fresh connection sees the persisted full quota.
    for _ in range(4 - admitted):
        assert reserve(tmp_path, limit=4, now=100)["error"] is None
    assert reserve(tmp_path, limit=4, now=100)["count"] == 5
    assert rows() == 4


def test_trusted_duplicate_and_policy_tightening(tmp_path):
    assert reserve(tmp_path, call_id="host-1", now=100)["used"] == 1
    assert reserve(tmp_path, call_id="host-1", now=101)["used"] == 1
    assert reserve(tmp_path, call_id="host-2", now=101)["used"] == 2
    assert reserve(tmp_path, limit=1, call_id="host-1", now=101)["count"] > 1
    assert reserve(tmp_path, call_id="host-1", now=161)["used"] == 1


def test_identity_only_trusted_principals_partition_quota():
    assert ratelimit.identity_key(Subject(user_id="a"), "sdk") == ratelimit.identity_key(
        Subject(user_id="b"), "sdk")
    assert ratelimit.identity_key(Subject(user_id="a", verified=True), "sdk") != ratelimit.identity_key(
        Subject(user_id="b", verified=True), "sdk")
    assert ratelimit.identity_key(Subject(), "a") != ratelimit.identity_key(Subject(), "b")


@pytest.mark.parametrize("bad", [None, {}, [], {"requests_per_minute": True},
    {"requests_per_minute": 0}, {"requests_per_minute": 2.5},
    {"requests_per_minute": 1, "max_burst": -1},
    {"requests_per_minute": 1, "max_burst": False},
    {"requests_per_minute": 1, "unknown": 1}])
def test_validate_bad_configuration(tmp_path, bad):
    path = policy(tmp_path)
    raw = yaml.safe_load(path.read_text())
    raw["settings"]["rate_limit"] = bad
    path.write_text(yaml.safe_dump(raw))
    assert any("rate_limit" in error for error in validate_policy(path))


def test_last_good_configuration_survives_invalid_edit(tmp_path):
    path = policy(tmp_path, limit=1)
    assert decide(tmp_path).allow
    raw = yaml.safe_load(path.read_text())
    raw["settings"]["rate_limit"]["requests_per_minute"] = False
    path.write_text(yaml.safe_dump(raw))
    engine = PolicyEngine(workspace=tmp_path)
    assert engine.project_policy_fallback
    assert engine.rate_limit["requests_per_minute"] == 1
    assert not decide(tmp_path).allow


def test_live_gate_sessions_and_incoming_context_cannot_waive_quota(tmp_path):
    policy(tmp_path, limit=1)
    assert decide(tmp_path, session_id="first").allow
    second = decide(tmp_path, session_id="new", event={"type": "shell", "command": "echo ok",
        "agent_event": "PreToolUse", "metadata": {"rate": {"count": 0}, "tool_use_id": "fake"}})
    assert not second.allow
    assert second.blocking["ruleId"] == "rate-limit-exceeded"
    assert second.blocking["category"] == "rate_limit"
    assert second.blocking["rateLimit"]["retry_after"] > 0
    # Pure engine evaluations cannot mint trusted context from event metadata.
    assert not PolicyEngine(workspace=tmp_path).evaluate(
        {"type": "rate_limit", "metadata": {"rate": {"count": 999, "limit": 1}}}, 0)


@pytest.mark.parametrize("event", [
    {"type": "shell", "agent_event": "PostToolUse", "command": "echo ok"},
    {"type": "shell", "agent_event": "PreCheck", "command": "echo ok"},
    {"type": "prompt", "agent_event": "UserPromptSubmit", "prompt": "hello"},
    {"type": "memory", "agent_event": "PreToolUse", "content": "hello"},
    {"type": "skill_manifest", "agent_event": "PreToolUse", "content": "hello"},
])
def test_non_tool_events_do_not_reserve(tmp_path, event):
    policy(tmp_path, limit=1)
    decide(tmp_path, event=event)
    assert ratelimit.status(tmp_path, {"requests_per_minute": 1})["identities"] == []


def test_explicit_replay_and_probes_do_not_reserve(tmp_path):
    policy(tmp_path, limit=1)
    for _ in range(3):
        assert decide(tmp_path, rate_accounting=False).allow
    assert decide(tmp_path).allow
    assert not decide(tmp_path).allow


def test_duplicate_hook_still_evaluates_other_policy(tmp_path):
    policy(tmp_path, limit=1)
    scope = ratelimit.Scope(tmp_path, "claude", "host-call")
    assert decide(tmp_path, rate_scope=scope).allow
    assert decide(tmp_path, rate_scope=scope).allow
    event = {"type": "shell", "command": "echo deny-marker", "agent_event": "PreToolUse"}
    path = tmp_path / ".prismor" / "policy.yaml"
    raw = yaml.safe_load(path.read_text())
    raw["rules"].append({"id": "deny-marker", "severity": "high", "category": "custom",
        "title": "Marker denied", "event_types": ["shell"], "patterns": ["deny-marker"],
        "action": "block", "mode": "enforce"})
    path.write_text(yaml.safe_dump(raw))
    assert not decide(tmp_path, event=event, rate_scope=scope).allow
    assert rows() == 1


def test_policy_observation_and_local_observe_override(tmp_path):
    policy(tmp_path, limit=1, mode="observe")
    assert decide(tmp_path).allow
    second = decide(tmp_path)
    assert second.allow and any(f["category"] == "rate_limit" for f in second.findings)
    policy(tmp_path, limit=1)
    assert decide(tmp_path, mode="observe").allow


def test_server_scope_cannot_be_changed_by_request_workspace_or_phase(tmp_path):
    server_ws = tmp_path / "server"
    policy(server_ws, limit=1)
    scope = ratelimit.Scope(server_ws, "eval-server", authoritative=True)
    assert decide(tmp_path / "client-one", rate_scope=scope).allow
    result = decide(tmp_path / "client-two", agent_name="new-label", subject=Subject(user_id="fake"),
                    mode="observe", rate_scope=scope,
                    event={"type": "prompt", "agent_event": "PostToolUse", "prompt": "hello"})
    assert not result.allow
    assert result.blocking["authoritative"]


def test_unavailable_fails_closed_and_observes_when_requested(tmp_path, monkeypatch):
    policy(tmp_path)
    monkeypatch.setattr(store, "get_db_path", lambda w: tmp_path / "missing" / "bad.db")
    (tmp_path / "missing").write_text("not a directory")
    result = decide(tmp_path)
    assert not result.allow
    assert result.blocking["ruleId"] == "rate-limit-unavailable"
    assert decide(tmp_path, mode="observe").allow


def test_locked_and_corrupt_database_are_unavailable(tmp_path):
    reserve(tmp_path, now=100)
    path = store.existing_db_path()
    with sqlite3.connect(path) as db:
        db.execute("BEGIN IMMEDIATE")
        assert reserve(tmp_path, now=100)["error"] == "OperationalError"
        db.rollback()
    path.write_bytes(b"not sqlite")
    assert reserve(tmp_path, now=100)["error"] == "DatabaseError"


def test_status_read_only_and_database_migration_preserves_sessions(tmp_path):
    settings = {"requests_per_minute": 2}
    assert ratelimit.status(tmp_path, settings)["identities"] == []
    assert store.existing_db_path() is None
    reserve(tmp_path, now=100)
    before = store.existing_db_path().read_bytes()
    report = ratelimit.status(tmp_path, settings, now=101)
    assert report["identities"][0]["used"] == 1
    assert store.existing_db_path().read_bytes() == before
    path = store.initialize_database(tmp_path)
    with sqlite3.connect(path) as db:
        db.execute("INSERT INTO sessions(session_id) VALUES ('existing')")
    store.initialize_database(tmp_path)
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT session_id FROM sessions").fetchone()[0] == "existing"
    assert rows() == 1


def test_cli_status_and_disabled_default_are_read_only(tmp_path, capsys):
    from prismor.runtime.cli import main
    main(["rate", "status", "--workspace", str(tmp_path), "--json"])
    assert not json.loads(capsys.readouterr().out)["configured"]
    assert store.existing_db_path() is None
    policy(tmp_path, limit=1)
    main(["rate", "status", "--workspace", str(tmp_path), "--json"])
    assert json.loads(capsys.readouterr().out)["limit"] == 1
    assert store.existing_db_path() is None
    decide(tmp_path)
    main(["rate", "status", "--workspace", str(tmp_path)])
    assert "1 used, 0 remaining" in capsys.readouterr().out


def test_real_sdk_wrapper_stops_fake_tool_execution(tmp_path):
    from prismor.langchain import prismor_guard_tool
    policy(tmp_path, limit=2)
    ran = []
    class Tool:
        name = "run_shell"
        def __init__(self):
            self.func = lambda command: ran.append(command) or "executed"
    tool = prismor_guard_tool(Tool(), workspace=tmp_path, mode="enforce")
    assert tool.func(command="echo one") == "executed"
    assert tool.func(command="echo two") == "executed"
    assert "blocked" in tool.func(command="echo three").lower()
    assert len(ran) == 2


def test_retry_time_after_limit_is_lowered(tmp_path):
    reserve(tmp_path, limit=3, now=100)
    reserve(tmp_path, limit=3, now=110)
    reserve(tmp_path, limit=3, now=120)
    result = reserve(tmp_path, limit=1, now=130)
    assert result["retry_after"] == 50
    report = ratelimit.status(tmp_path, {"requests_per_minute": 1}, now=130)
    assert report["identities"][0]["retry_after"] == 50


def test_normal_hook_delivery_key_binds_input_and_session():
    payload = {"tool_use_id": "one", "tool_name": "Bash", "tool_input": {"command": "echo one"}}
    original = ratelimit.hook_call_id(payload, "claude", "session")
    assert original == ratelimit.hook_call_id(dict(payload), "claude", "session")
    assert original != ratelimit.hook_call_id(payload, "claude", "new-session")
    payload["tool_input"] = {"command": "echo two"}
    assert original != ratelimit.hook_call_id(payload, "claude", "session")


def test_policy_layers_and_remote_authority(tmp_path, monkeypatch):
    from prismor.runtime.enterprise import remote_policy, workspace_scope
    policy(tmp_path, limit=3)
    monkeypatch.setattr(workspace_scope, "is_managed", lambda w: True)
    monkeypatch.setattr(remote_policy, "check_and_refresh", lambda: False)
    monkeypatch.setattr(remote_policy, "verify_and_load", lambda: {
        "settings": {"rate_limit": {"requests_per_minute": 1}},
        "rules": [{"id": "rate-limit-exceeded", "mode": "enforce"},
                  {"id": "rate-limit-unavailable", "mode": "enforce"}]})
    assert decide(tmp_path, mode="observe").allow
    blocked = decide(tmp_path, mode="observe")
    assert not blocked.allow and blocked.blocking["authoritative"]
    assert blocked.engine.rate_limit_source == "remote"


def test_invalid_remote_layer_does_not_disable_existing_enforcement(tmp_path, monkeypatch):
    from prismor.runtime.enterprise import remote_policy, workspace_scope
    policy(tmp_path, limit=1)
    monkeypatch.setattr(workspace_scope, "is_managed", lambda w: True)
    monkeypatch.setattr(remote_policy, "verify_and_load", lambda: {
        "settings": {"rate_limit": {"requests_per_minute": False}},
        "rules": [{"id": "rate-limit-unavailable", "enabled": False}]})
    engine = PolicyEngine(workspace=tmp_path)
    assert engine.rate_limit_error
    assert engine.rate_limit["requests_per_minute"] == 1
    assert next(r for r in engine.rules if r.id == "rate-limit-unavailable").enabled


def test_default_rules_conform_to_published_schema():
    jsonschema = pytest.importorskip("jsonschema")
    from prismor.runtime import policy_engine
    schema = json.loads(Path(policy_engine.__file__).with_name("policy_schema.json").read_text())
    raw = yaml.safe_load(Path(policy_engine.__file__).with_name("default_policy.yaml").read_text())
    rules = [r for r in raw["rules"] if r["category"] == "rate_limit"]
    jsonschema.validate({"version": "1.0", "rules": rules,
                         "settings": {"rate_limit": {"requests_per_minute": 2}}}, schema)


def test_patch_paths_and_reanalysis_do_not_reserve_more(tmp_path):
    policy(tmp_path, limit=1)
    event = {"type": "file_write", "agent_event": "PreToolUse", "path": "one.py",
             "content": "pass", "metadata": {"patch_paths": ["one.py", "two.py", "three.py"]}}
    assert decide(tmp_path, event=event).allow
    engine = PolicyEngine(workspace=tmp_path)
    for _ in range(3):
        engine.evaluate(event, 0)
    assert rows() == 1
    assert not decide(tmp_path).allow


def test_http_eval_scope_and_forged_request_ids(tmp_path, monkeypatch):
    import threading
    import urllib.request
    from prismor.runtime.eval_server import EvalHandler, _ThreadingHTTPServer
    policy(tmp_path, limit=1)
    monkeypatch.setattr(EvalHandler, "workspace", tmp_path)
    monkeypatch.setattr(EvalHandler, "api_key", None)
    server = _ThreadingHTTPServer(("127.0.0.1", 0), EvalHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        def post(body, path="/v1/evaluate"):
            req = urllib.request.Request(
                f"http://127.0.0.1:{server.server_address[1]}{path}",
                data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=10) as response:
                return json.loads(response.read())
        assert post({"tool_name": "Bash", "arguments": {"command": "echo ok"},
                     "subject": "user:a", "agent_name": "a"})["allow"]
        result = post({"tool_name": "Bash", "arguments": {"command": "echo ok"},
                       "subject": "user:b", "agent_name": "b", "session_id": "new",
                       "mode": "observe", "workspace": str(tmp_path / "unconfigured")})
        assert not result["allow"] and result["rule_id"] == "rate-limit-exceeded"
        result = post({"event": {"type": "prompt", "agent_event": "PostToolUse",
                        "prompt": "hello", "metadata": {"tool_use_id": "fake"}},
                       "workspace": str(tmp_path / "another"), "agent": "new", "mode": "observe"},
                      "/v1/evaluate")
        assert not result["allow"]
        authzen = post({"subject": {"type": "user", "id": "changed"},
                        "resource": {"type": "doc", "id": "one"},
                        "action": {"name": "read"}}, "/access/v1/evaluation")
        assert not authzen["decision"]  # changing protocol does not create another quota
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_proxy_live_calls_and_findings_survive_snapshot(tmp_path):
    from prismor.runtime.proxy import Screen
    policy(tmp_path, limit=1)
    screen = Screen(tmp_path, "enforce", "rate-proxy")
    try:
        first = screen.evaluate(screen.tool_event("Bash", {"command": "echo one"}, "anthropic", "test", None))
        second = screen.evaluate(screen.tool_event("Bash", {"command": "echo two"}, "anthropic", "test", None))
        assert first.allow and not second.allow
        screen.snapshot()
        with sqlite3.connect(store.existing_db_path()) as db:
            row = db.execute("SELECT category, evidence, enrichment_json FROM findings "
                             "WHERE session_id='rate-proxy' AND category='rate_limit'").fetchone()
        assert row is not None
        assert json.loads(row[1])["used"] == 1
        assert json.loads(row[2])["ruleId"] == "rate-limit-exceeded"
    finally:
        screen._writer_stop.set()
        screen._writer.join(timeout=2)
        Screen._all.remove(screen)


def test_mcp_discovery_does_not_count_and_excess_call_is_not_forwarded(tmp_path, monkeypatch):
    from prismor.runtime.mcp_gateway import Gateway, Upstream, UpstreamSpec
    policy(tmp_path, limit=1)
    spec = UpstreamSpec(name="local-test", command=["true"], transport="stdio")
    class FakeUpstream(Upstream):
        def __init__(self):
            super().__init__(spec)
            self.calls = 0
        def request(self, method, params, timeout=30):
            if method == "tools/list":
                return {"tools": [{"name": "echo", "description": "Echo", "inputSchema": {"type": "object"}}]}
            if method == "tools/call":
                self.calls += 1
                return {"content": [{"type": "text", "text": "ok"}]}
            return {"capabilities": {"tools": {}}, "serverInfo": {"name": "local-test", "version": "1"}}
        def notify(self, method, params):
            pass
    upstream = FakeUpstream()
    gateway = Gateway([spec], workspace=tmp_path, mode="enforce")
    gateway.upstreams = [upstream]
    sent = []
    monkeypatch.setattr(gateway, "_send", sent.append)
    try:
        gateway._handle_tools_list("list", {})
        name = sent[-1]["result"]["tools"][0]["name"]
        assert ratelimit.status(tmp_path, {"requests_per_minute": 1})["identities"] == []
        gateway._handle_tools_call_safe("one", {"name": name, "arguments": {}})
        gateway._handle_tools_call_safe("two", {"name": name, "arguments": {}})
        assert upstream.calls == 1
        assert sent[-1]["result"]["isError"]
        assert "rate-limit-exceeded" in json.dumps(sent[-1])
    finally:
        gateway.close()


def test_rate_blocks_reach_standard_file_sink(tmp_path):
    from prismor.runtime.runtime import evaluate_tool_call
    path = policy(tmp_path, limit=1)
    raw = yaml.safe_load(path.read_text())
    log = tmp_path / "sink.jsonl"
    raw["settings"]["outputs"] = [{"type": "file", "path": str(log)}]
    path.write_text(yaml.safe_dump(raw))
    for _ in range(2):
        evaluate_tool_call(event={"type": "shell", "agent_event": "PreToolUse", "command": "echo ok"},
                          workspace=tmp_path, agent="sink-test", session_id="rate-sink",
                          persist=False, register_agent=False, flush_at_exit=False)
    events = [json.loads(line) for line in log.read_text().splitlines()]
    assert any(e.get("category") == "rate_limit" for e in events)


def test_inference_replay_does_not_count_prior_tool_events(tmp_path):
    from prismor.runtime.inference_hook import ChannelConfig, evaluate_turn
    policy(tmp_path, limit=1)
    transcript = {"messages": [
        {"role": "assistant", "content": [{"type": "tool_use", "id": "old",
         "name": "Bash", "input": {"command": "echo prior"}}]},
        {"role": "user", "content": "continue"}]}
    for _ in range(2):
        evaluate_turn(transcript, config=ChannelConfig(), workspace=tmp_path, session_id="replay")
    assert ratelimit.status(tmp_path, {"requests_per_minute": 1})["identities"] == []


def test_invalid_remote_refresh_preserves_last_signed_policy(tmp_path, monkeypatch):
    import urllib.request
    from prismor.runtime.enterprise import remote_policy
    previous = "settings: {rate_limit: {requests_per_minute: 1}}\nrules: []\n"
    cache = remote_policy.cached_policy_path()
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text(previous)
    sig_path = remote_policy._cached_sig_path()
    sig_path.write_text("previous-signature")
    monkeypatch.setattr(remote_policy._identity, "load_identity", lambda: {
        "device_key": "fixture", "api_base": "https://example.test"})
    monkeypatch.setattr(remote_policy, "_verify_signature", lambda *a: True)
    class Response:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def read(self):
            return json.dumps({"yaml": "settings: {rate_limit: {requests_per_minute: false}}",
                               "signature": "fixture"}).encode()
    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: Response())
    assert not remote_policy.fetch(force=True)
    assert cache.read_text() == previous
    assert sig_path.read_text() == "previous-signature"


def test_read_only_store_fails_closed_without_consuming_slot(tmp_path, monkeypatch):
    reserve(tmp_path, now=100)
    original_connect = sqlite3.connect
    def readonly(path, **kwargs):
        return original_connect(Path(path).as_uri() + "?mode=ro", uri=True, **kwargs)
    monkeypatch.setattr(ratelimit.sqlite3, "connect", readonly)
    assert reserve(tmp_path, now=101)["error"] == "OperationalError"
    monkeypatch.undo()
    assert rows() == 1


def test_admission_ledger_never_stores_tool_input(tmp_path):
    payload = {"tool_use_id": "host-one", "tool_input": {"command": "echo fixture-marker"}}
    reserve(tmp_path, call_id=ratelimit.hook_call_id(payload, "claude", "session"), now=100)
    with sqlite3.connect(store.existing_db_path()) as db:
        data = db.execute("SELECT * FROM rate_limit_admissions").fetchall()
    assert "fixture-marker" not in repr(data)
    assert "host-one" not in repr(data)


def test_real_hook_dispatch_duplicate_and_excess_call(tmp_path):
    import os
    import subprocess
    import sys
    policy(tmp_path, limit=1)
    payload = {"session_id": "rate-hook", "tool_use_id": "one", "hook_event_name": "PreToolUse",
               "tool_name": "Bash", "tool_input": {"command": "echo harmless"}, "cwd": str(tmp_path)}
    argv = [sys.executable, "-m", "prismor.runtime.cli", "hook-dispatch",
            "--agent", "claude", "--mode", "enforce", "--workspace", str(tmp_path)]
    def dispatch():
        return subprocess.run(argv, input=json.dumps(payload), text=True, capture_output=True,
                              env=dict(os.environ), timeout=30)
    assert dispatch().returncode == 0
    assert dispatch().returncode == 0  # global/project deliveries share the reservation
    payload["tool_use_id"] = "two"
    result = dispatch()
    assert result.returncode == 2, result.stdout + result.stderr
    assert "rate-limit-exceeded" in result.stdout + result.stderr
    assert rows() == 1


def test_failed_commit_rolls_back_reservation(tmp_path, monkeypatch):
    reserve(tmp_path, now=100)
    original_connect = sqlite3.connect
    class FailingCommit(sqlite3.Connection):
        def commit(self):
            raise sqlite3.OperationalError("simulated commit failure")
    def connect(*args, **kwargs):
        return original_connect(*args, factory=FailingCommit, **kwargs)
    monkeypatch.setattr(ratelimit.sqlite3, "connect", connect)
    assert reserve(tmp_path, now=110)["error"] == "OperationalError"
    monkeypatch.undo()
    assert rows() == 1
    assert reserve(tmp_path, now=101)["used"] == 2


def test_caller_workspace_exemption_cannot_waive_server_quota(tmp_path):
    server_ws = tmp_path / "server"
    client_ws = tmp_path / "client"
    policy(server_ws, limit=1)
    path = policy(client_ws, limit=10)
    raw = yaml.safe_load(path.read_text())
    raw["settings"]["rule_exemptions"] = [
        {"ruleId": "rate-limit-exceeded", "scope": "org", "action": "allow"}]
    path.write_text(yaml.safe_dump(raw))
    scope = ratelimit.Scope(server_ws, "eval-server", authoritative=True)
    assert decide(client_ws, rate_scope=scope).allow
    assert not decide(client_ws, rate_scope=scope).allow


def test_session_logging_failure_does_not_skip_rate_enforcement(tmp_path, monkeypatch):
    from prismor.runtime import runtime
    policy(tmp_path, limit=1)
    assert decide(tmp_path).allow
    def failed_append(*args, **kwargs):
        raise OSError("simulated session logging failure")
    monkeypatch.setattr(runtime, "append_session_event", failed_append)
    decision = evaluate_tool_call(
        event={"type": "shell", "command": "echo harmless", "agent_event": "PreToolUse"},
        workspace=tmp_path, agent="test", session_id="logging-failure",
        register_agent=False, flush_at_exit=False)
    assert not decision.allow
    assert decision.blocking["ruleId"] == "rate-limit-exceeded"


def test_unavailable_state_directory_still_returns_block_decision(tmp_path, monkeypatch):
    policy(tmp_path, limit=1)
    broken_home = tmp_path / "not-a-directory"
    broken_home.write_text("fixture")
    monkeypatch.setenv("PRISMOR_HOME", str(broken_home))
    decision = evaluate_tool_call(
        event={"type": "shell", "command": "echo harmless", "agent_event": "PreToolUse"},
        workspace=tmp_path, agent="test", session_id="broken-store",
        register_agent=False, flush_at_exit=False)
    assert not decision.allow
    assert decision.blocking["ruleId"] == "rate-limit-unavailable"


@pytest.mark.parametrize("exemption_scope", ["user", "session", "agent"])
def test_request_labels_cannot_select_server_quota_exemptions(tmp_path, exemption_scope):
    path = policy(tmp_path, limit=1)
    raw = yaml.safe_load(path.read_text())
    raw["settings"]["rule_exemptions"] = [{
        "ruleId": "rate-limit-exceeded", "scope": exemption_scope,
        "scopeId": "privileged", "action": "allow"}]
    path.write_text(yaml.safe_dump(raw))
    scope = ratelimit.Scope(tmp_path, "eval-server", authoritative=True)
    assert decide(tmp_path, rate_scope=scope).allow
    decision = decide(tmp_path, rate_scope=scope, subject=Subject(user_id="privileged"),
                      agent_name="privileged", session_id="privileged")
    assert not decision.allow


def test_quota_owner_can_grant_an_explicit_exception(tmp_path):
    server = tmp_path / "server"
    path = policy(server, limit=1)
    raw = yaml.safe_load(path.read_text())
    raw["settings"]["rule_exemptions"] = [{
        "ruleId": "rate-limit-exceeded", "scope": "org", "action": "allow"}]
    path.write_text(yaml.safe_dump(raw))
    scope = ratelimit.Scope(server, "eval-server", authoritative=True)
    assert decide(tmp_path / "client", rate_scope=scope).allow
    assert decide(tmp_path / "client", rate_scope=scope).allow


def test_server_quota_uses_host_identity_requirements(tmp_path, monkeypatch):
    from prismor.runtime.enterprise import remote_policy, workspace_scope
    server = tmp_path / "server"
    server.mkdir()
    monkeypatch.setattr(workspace_scope, "is_managed", lambda w: w == server)
    monkeypatch.setattr(remote_policy, "check_and_refresh", lambda: False)
    monkeypatch.setattr(remote_policy, "verify_and_load", lambda: {
        "settings": {"rate_limit": {"requests_per_minute": 2},
                     "identity": {"mode": "require", "issuer": "https://example.test", "audience": "fixture"}},
        "rules": [{"id": "rate-limit-exceeded", "mode": "enforce"},
                  {"id": "rate-limit-unavailable", "mode": "enforce"}]})
    decision = decide(tmp_path / "client", rate_scope=ratelimit.Scope(
        server, "eval-server", authoritative=True),
        event={"type": "prompt", "agent_event": "PostToolUse", "prompt": "hello"})
    assert not decision.allow
    assert decision.blocking["ruleId"] == "identity-unverified"


@pytest.mark.parametrize("failure", ["rollback", "close"])
def test_database_cleanup_errors_return_unavailable(tmp_path, monkeypatch, failure):
    original_connect = sqlite3.connect
    class FailingCleanup(sqlite3.Connection):
        def commit(self):
            if failure == "rollback":
                raise sqlite3.OperationalError("simulated commit failure")
            return super().commit()
        def rollback(self):
            raise sqlite3.OperationalError("simulated rollback failure")
        def close(self):
            super().close()
            if failure == "close":
                raise sqlite3.OperationalError("simulated close failure")
    with monkeypatch.context() as patch:
        patch.setattr(ratelimit.sqlite3, "connect", lambda *a, **k: original_connect(
            *a, factory=FailingCleanup, **k))
        assert reserve(tmp_path, now=100)["error"] == "OperationalError"


def test_nonfinite_persisted_clock_fails_closed(tmp_path):
    reserve(tmp_path, limit=1, now=100)
    with sqlite3.connect(store.existing_db_path()) as db:
        db.execute("UPDATE rate_limit_clock SET ts=?", (float("inf"),))
    assert reserve(tmp_path, limit=1, now=101)["error"] == "ValueError"
    assert ratelimit.status(tmp_path, {"requests_per_minute": 1}, now=101)["error"] == "ValueError"


def test_client_issuer_cannot_create_verified_host_quota_identities(tmp_path, monkeypatch):
    from prismor.runtime import identity_token, runtime
    server = tmp_path / "server"
    client = tmp_path / "client"
    policy(server, limit=1)
    original_engine = runtime.PolicyEngine
    def engine(*, workspace):
        result = original_engine(workspace=workspace)
        result.identity = {"mode": "observe", "issuer": "host" if workspace == server else "client"}
        return result
    def verify(token, cfg):
        if cfg["issuer"] != "client":
            raise identity_token.IdentityError("wrong issuer for quota owner")
        return Subject(user_id=token, source="jwt", verified=True, claims={"iss": "client"})
    monkeypatch.setattr(runtime, "PolicyEngine", engine)
    monkeypatch.setattr(identity_token, "verify", verify)
    scope = ratelimit.Scope(server, "eval-server", authoritative=True)
    assert decide(client, rate_scope=scope, identity_token="fixture-one").allow
    assert not decide(client, rate_scope=scope, identity_token="fixture-two").allow


@pytest.mark.parametrize("shared_sink", [False, True])
def test_server_quota_reports_to_owner_sink_without_client_payload(tmp_path, shared_sink):
    server = tmp_path / "server"
    client = tmp_path / "client"
    path = policy(server, limit=1)
    raw = yaml.safe_load(path.read_text())
    audit = tmp_path / "owner-audit.jsonl"
    raw["settings"]["outputs"] = [{"type": "file", "path": str(audit)}]
    path.write_text(yaml.safe_dump(raw))
    if shared_sink:
        client_policy = policy(client, limit=10)
        client_raw = yaml.safe_load(client_policy.read_text())
        client_raw["settings"]["outputs"] = raw["settings"]["outputs"]
        client_policy.write_text(yaml.safe_dump(client_raw))
    for _ in range(2):
        evaluate_tool_call(
            event={"type": "shell", "agent_event": "PreToolUse", "command": "echo private-fixture-marker"},
            workspace=client, agent="test", rate_scope=ratelimit.Scope(
                server, "eval-server", authoritative=True), session_id="private-session-fixture-marker",
            persist=False, register_agent=False, flush_at_exit=False)
    events = [json.loads(line) for line in audit.read_text().splitlines()]
    assert sum(e["category"] == "rate_limit" for e in events) == 1
    if not shared_sink:
        assert "private-fixture-marker" not in audit.read_text()
        assert "private-session-fixture-marker" not in audit.read_text()


def test_status_reports_unreadable_store_directory(tmp_path, monkeypatch):
    def denied():
        raise PermissionError("simulated unreadable store directory")
    monkeypatch.setattr(store, "existing_db_path", denied)
    assert ratelimit.status(tmp_path, {"requests_per_minute": 1})["error"] == "PermissionError"
