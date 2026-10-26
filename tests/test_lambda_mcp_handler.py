"""Hosted MCP endpoints on Lambda: the handler in front of the real `prismor mcp-gateway`.

The control plane is faked (resolve returns a stub config); the gateway is the real
runtime CLI, and the upstream is a stdio stub server, so nothing leaves the machine.
"""
import base64
import importlib
import io
import json
import os
import sys
import tarfile
from pathlib import Path

import pytest

STUB = str(Path(__file__).parent / "fixtures" / "stub_mcp_server.py")
KEY = "prism_agent_" + "a" * 40
OTHER = "prism_agent_" + "b" * 40


@pytest.fixture
def h(monkeypatch, tmp_path):
    monkeypatch.setenv("HOSTED_MCP_ROOT", str(tmp_path / "root"))
    monkeypatch.setenv("PRISMOR_ORG_ID", "org1")
    monkeypatch.setenv("PRISMOR_WEB_URL", "http://127.0.0.1:9")  # nothing listens: telemetry/policy pulls fail fast
    monkeypatch.delenv("HOSTED_MCP_STATE_BUCKET", raising=False)
    import prismor.runtime.lambda_mcp_handler as mod
    mod = importlib.reload(mod)
    configs = {KEY: config("inst1")}
    calls = []

    def fake_fetch(key):
        calls.append(key)
        if key in configs:
            return configs[key]() if callable(configs[key]) else (200, configs[key])
        return 403, None

    monkeypatch.setattr(mod, "_fetch_config", fake_fetch)
    mod._test_configs, mod._test_calls = configs, calls
    yield mod
    for k in list(mod._gateways):
        mod._stop(k)


def config(instance_id, org="org1", servers=None, subject=None):
    return {"instance_id": instance_id, "org_id": org, "subject": subject,
            "mcpServers": servers or {"stub": {"command": sys.executable, "args": [STUB]}}}


def event(method, path, body=None, b64=False):
    raw = json.dumps(body) if body is not None else ""
    if b64:
        raw = base64.b64encode(raw.encode()).decode()
    return {"rawPath": path, "requestContext": {"http": {"method": method}}, "body": raw, "isBase64Encoded": b64}


def rpc(h, msg, key=KEY, b64=False):
    out = h.handler(event("POST", f"/mcp/{key}", msg, b64))
    return out["statusCode"], (json.loads(out["body"]) if out["body"] else None)


def init(h, key=KEY):
    st, body = rpc(h, {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                       "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}}, key)
    assert st == 200, body
    assert rpc(h, {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}, key) == (202, None)
    return body


# ── routing ──────────────────────────────────────────────────────────────────

def test_health_reports_the_runtime_version(h):
    out = h.handler(event("GET", "/health"))
    assert out["statusCode"] == 200 and json.loads(out["body"])["ok"] is True


@pytest.mark.parametrize("method,path,status", [
    ("POST", "/", 404), ("POST", "/mcp", 404), ("POST", "/mcp/a/b", 404), ("GET", f"/mcp/{KEY}", 405),
    ("DELETE", f"/mcp/{KEY}", 204),
])
def test_routes(h, method, path, status):
    assert h.handler(event(method, path))["statusCode"] == status


def test_bad_json_is_a_parse_error(h):
    out = h.handler({"rawPath": f"/mcp/{KEY}", "requestContext": {"http": {"method": "POST"}}, "body": "{nope"})
    assert out["statusCode"] == 400 and json.loads(out["body"])["error"]["code"] == -32700


# ── auth ─────────────────────────────────────────────────────────────────────

def test_unknown_or_revoked_key_is_refused_and_never_starts_a_gateway(h):
    st, body = rpc(h, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, key=OTHER)
    assert st == 403 and body == {"error": "invalid or revoked instance key"}
    assert OTHER not in h._gateways


def test_a_key_from_another_org_is_refused(h):
    h._test_configs[OTHER] = config("instX", org="org2")
    st, _ = rpc(h, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, key=OTHER)
    assert st == 403


def test_control_plane_down_fails_closed_for_a_key_never_seen(h):
    h._test_configs[OTHER] = lambda: (0, None)
    st, body = rpc(h, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, key=OTHER)
    assert st == 503 and body == {"error": "control plane unreachable"}


def test_resolve_cache_ttl_and_stale_on_outage(h):
    assert h.resolve(KEY, now=1000)[0] == 200
    assert h.resolve(KEY, now=1010)[0] == 200 and len(h._test_calls) == 1  # cached
    h._test_configs[KEY] = lambda: (0, None)  # control plane goes down
    assert h.resolve(KEY, now=2000)[0] == 200  # stale entry keeps a known key working
    h._test_configs.pop(KEY)  # now revoked
    assert h.resolve(KEY, now=3000) == (403, None)
    assert KEY not in h._resolved


# ── the real gateway ─────────────────────────────────────────────────────────

def test_initialize_list_call_through_the_real_gateway(h):
    info = init(h)
    assert info["result"]["serverInfo"]["name"] == "prismor-gateway"
    st, tools = rpc(h, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    names = [t["name"] for t in tools["result"]["tools"]]
    assert "stub__echo" in names and "stub__poisoned" in names
    st, res = rpc(h, {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                      "params": {"name": "stub__echo", "arguments": {"text": "hello from lambda"}}}, b64=True)
    assert st == 200 and res["result"]["content"][0]["text"] == "hello from lambda"
    assert not res["result"].get("isError")


def test_a_poisoned_tool_result_is_withheld_from_the_model(h):
    init(h)
    rpc(h, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})  # clients list before calling
    st, res = rpc(h, {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "stub__poisoned", "arguments": {}}})
    assert st == 200 and res["result"]["isError"] is True
    text = res["result"]["content"][0]["text"]
    assert "withheld" in text and "system prompt" not in text


def test_batches_get_a_batch_back(h):
    init(h)
    st, out = rpc(h, [{"jsonrpc": "2.0", "id": 10, "method": "tools/list"},
                      {"jsonrpc": "2.0", "method": "notifications/initialized"},
                      {"jsonrpc": "2.0", "id": 11, "method": "tools/call", "params": {"name": "stub__echo", "arguments": {"text": "x"}}}])
    assert st == 200 and [m["id"] for m in out] == [10, 11]


def test_the_gateway_is_reused_while_warm_and_restarted_when_the_endpoint_changes(h):
    init(h)
    pid = h._gateways[KEY].proc.pid
    rpc(h, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    assert h._gateways[KEY].proc.pid == pid
    # An admin adds a server to the endpoint: the next call (after the cache) runs the new config.
    h._test_configs[KEY] = config("inst1", servers={"stub": {"command": sys.executable, "args": [STUB]},
                                                     "stub2": {"command": sys.executable, "args": [STUB]}})
    h._resolved.clear()
    st, tools = rpc(h, {"jsonrpc": "2.0", "id": 3, "method": "tools/list"})
    assert h._gateways[KEY].proc.pid != pid
    assert "stub2__echo" in [t["name"] for t in tools["result"]["tools"]]


def test_revoking_the_key_stops_its_gateway(h):
    init(h)
    gw = h._gateways[KEY]
    h._test_configs.pop(KEY)
    h._resolved.clear()
    st, _ = rpc(h, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    assert st == 403 and KEY not in h._gateways and not gw.alive()


def test_two_keys_get_separate_gateways_and_homes(h):
    h._test_configs[OTHER] = config("inst2")
    init(h)
    init(h, key=OTHER)
    a, b = h._gateways[KEY], h._gateways[OTHER]
    assert a.proc.pid != b.proc.pid and a.paths["base"] != b.paths["base"]


# ── what each gateway runs as ────────────────────────────────────────────────

def test_browser_servers_are_left_to_a_local_gateway(h):
    cfg = config("i", servers={"pw": {"command": "npx", "args": ["-y", "@playwright/mcp@latest"]},
                               "gh": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"]},
                               "docs": {"type": "http", "url": "https://docs.example/mcp"}})
    assert sorted(h.hosted_servers(cfg)) == ["docs", "gh"]


def test_gateway_env_carries_the_key_and_subject_but_not_function_secrets(h, monkeypatch):
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "s3cr3t")
    monkeypatch.setenv("HOSTED_MCP_STATE_BUCKET", "bucket")
    env = h.gateway_env(KEY, config("i", subject="user:u1"), h._paths(KEY))
    assert env["PRISMOR_AGENT_KEY"] == KEY and env["PRISMOR_SUBJECT"] == "user:u1"
    assert env["PRISMOR_API_BASE"] == "http://127.0.0.1:9"
    assert "AWS_SECRET_ACCESS_KEY" not in env and "HOSTED_MCP_STATE_BUCKET" not in env
    assert env["PRISMOR_HOME"].startswith(os.environ["HOSTED_MCP_ROOT"])


def test_the_server_config_file_is_private(h):
    init(h)
    mode = os.stat(h._gateways[KEY].paths["config"]).st_mode & 0o777
    assert mode == 0o600


# ── state snapshots ──────────────────────────────────────────────────────────

def test_snapshot_keeps_state_but_never_a_workspace_policy(h):
    p = h._paths(KEY)
    os.makedirs(os.path.join(p["workspace"], ".prismor"), exist_ok=True)
    os.makedirs(p["prismor_home"], exist_ok=True)
    Path(p["workspace"], ".prismor", "trifecta.json").write_text("{}")
    Path(p["workspace"], ".prismor", "policy.yaml").write_text("settings: {}")
    with tarfile.open(fileobj=io.BytesIO(h.snapshot(p)), mode="r:gz") as tar:
        names = tar.getnames()
    assert any(n.endswith("trifecta.json") for n in names)
    assert not any(n.endswith("policy.yaml") for n in names)


def test_restore_drops_a_policy_and_anything_outside_the_keys_tree(h, tmp_path):
    p = h._paths(KEY)
    base = p["base"].lstrip("/")
    evil = tmp_path / "escaped.txt"
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data in [(f"{base}/workspace/.prismor/trifecta.json", b"{}"),
                           (f"{base}/workspace/.prismor/policy.yaml", b"settings: {}"),
                           (str(evil).lstrip("/"), b"x"),
                           (f"{base}/../../escape.txt", b"x")]:
            info = tarfile.TarInfo(name); info.size = len(data); tar.addfile(info, io.BytesIO(data))
    h.restore(p, buf.getvalue())
    assert Path(p["workspace"], ".prismor", "trifecta.json").exists()
    assert not Path(p["workspace"], ".prismor", "policy.yaml").exists()
    assert not evil.exists()
