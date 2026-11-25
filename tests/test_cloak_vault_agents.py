"""Vault page: secrets shared with only some agents, and a write-only API.

A. secrets_store.set_agents / agent_allowed: no file = every agent.
B. decloak-exec.sh (every shell path) refuses a secret not shared with the
   calling agent, before any value is loaded.
C. `prismor cloak run` refuses the same way.
D. /api/vault never returns a value; the self-edit rule keeps agents off it.
"""
from __future__ import annotations

import http.client
import json
import os
import subprocess
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

from prismor.runtime.cloaking import runtime as cloak_runtime
from prismor.runtime.cloaking import secrets_store

_HOOKS = Path(secrets_store.__file__).parent / "hooks"
VAL = "vault-canary-9f3c1e7a2b"
PH = "@@SECRET" + ":CANARY@@"
_MARKERS = ("AI_AGENT", "CLAUDECODE", "CODEX_THREAD_ID", "CODEX_SANDBOX", "CURSOR_AGENT",
            "GEMINI_CLI", "PRISMOR_AGENT_ID")


def _clean_env(**extra):
    env = {k: v for k, v in os.environ.items() if k not in _MARKERS}
    env.update(extra)
    return env


def _vault(tmp_path, monkeypatch, agents):
    sdir = tmp_path / "secrets"
    monkeypatch.setenv("PRISMOR_SECRETS_DIR", str(sdir))
    secrets_store.add_secret("CANARY", VAL)
    secrets_store.set_agents("CANARY", agents)
    return sdir


def test_store_access_lists(tmp_path, monkeypatch):
    _vault(tmp_path, monkeypatch, None)
    assert secrets_store.get_agents("CANARY") is None
    assert secrets_store.agent_allowed("CANARY", [])          # unrestricted
    secrets_store.set_agents("CANARY", ["codex", "claude", "claude"])
    assert secrets_store.get_agents("CANARY") == ["claude", "codex"]
    if os.name != "nt":
        assert (tmp_path / "secrets" / ".meta").stat().st_mode & 0o077 == 0
    assert secrets_store.agent_allowed("CANARY", ["claude"])
    assert not secrets_store.agent_allowed("CANARY", ["cursor"])
    assert not secrets_store.agent_allowed("CANARY", [])      # unknown caller
    assert [s["agents"] for s in secrets_store.list_secrets()] == [["claude", "codex"]]
    secrets_store.remove_secret("CANARY")
    assert not (tmp_path / "secrets" / ".meta" / "agents" / "CANARY").exists()


def _resolve(sdir, **env):
    e = _clean_env(PRISMOR_SECRETS_DIR=str(sdir), PRISMOR_CLOAK_CMD=f"printf %s {PH} | wc -c", **env)
    return subprocess.run(["bash", str(_HOOKS / "decloak-exec.sh")], env=e,
                          capture_output=True, text=True, timeout=30)


def test_resolver_by_agent(tmp_path, monkeypatch):
    sdir = _vault(tmp_path, monkeypatch, ["claude", "release-bot"])
    ok = _resolve(sdir, CLAUDECODE="1")
    assert ok.returncode == 0 and ok.stdout.strip() == str(len(VAL)), ok.stderr
    assert _resolve(sdir, PRISMOR_AGENT_ID="release-bot").returncode == 0
    for env in ({"CODEX_THREAD_ID": "t1"}, {}):
        r = _resolve(sdir, **env)
        assert r.returncode == 126 and "not shared" in r.stderr
        assert VAL not in r.stdout + r.stderr
    secrets_store.set_agents("CANARY", None)
    assert _resolve(sdir).returncode == 0


def test_cloak_run_by_agent(tmp_path, monkeypatch, capsys):
    _vault(tmp_path, monkeypatch, ["codex"])
    for k in _MARKERS:
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("CURSOR_AGENT", "1")
    assert cloak_runtime.run_decloaked_command(["true", PH]) == 2
    assert "not shared with cursor" in capsys.readouterr().err
    monkeypatch.delenv("CURSOR_AGENT")
    monkeypatch.setenv("CODEX_THREAD_ID", "t1")
    assert cloak_runtime.run_decloaked_command(["true", PH]) == 0


def test_api_is_write_only(tmp_path, monkeypatch):
    from prismor.runtime import server as srv
    monkeypatch.setenv("PRISMOR_SECRETS_DIR", str(tmp_path / "secrets"))
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), srv.PrismorRequestHandler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()

    def call(method, path, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", httpd.server_address[1], timeout=10)
        conn.request(method, path, body=json.dumps(body) if body is not None else None,
                     headers={"Content-Type": "application/json"})
        r = conn.getresponse(); raw = r.read(); conn.close()
        return r.status, raw
    try:
        assert call("POST", "/api/vault", {"name": "CANARY", "value": VAL, "agents": ["claude"]})[0] == 200
        status, raw = call("GET", "/api/vault")
        assert status == 200 and VAL.encode() not in raw
        data = json.loads(raw)
        assert data["secrets"][0]["agents"] == ["claude"] and "claude" in [a["name"] for a in data["agents"]]
        assert all({"name", "active", "last_seen"} <= a.keys() for a in data["agents"])
        assert call("POST", "/api/vault/agents", {"name": "CANARY", "agents": None})[0] == 200
        assert secrets_store.get_agents("CANARY") is None
        assert call("POST", "/api/vault/agents", {"name": "NOPE", "agents": []})[0] == 404
        assert call("POST", "/api/vault", {"name": "../x", "value": "v"})[0] == 400
        assert call("POST", "/api/vault", {"name": "EMPTY", "value": ""})[0] == 400
        assert call("POST", "/api/vault/remove", {"name": "CANARY"})[0] == 200
        assert json.loads(call("GET", "/api/vault")[1])["secrets"] == []
    finally:
        httpd.shutdown(); httpd.server_close()


def test_agents_cannot_write_the_vault(tmp_path):
    from prismor.runtime.hooks import should_block
    from prismor.runtime.policy_engine import PolicyEngine
    eng = PolicyEngine(workspace=tmp_path)

    def blocked(cmd):
        f = eng.evaluate({"type": "shell", "command": cmd}, index=0)
        return should_block(f, {"type": "shell", "agent_event": "PreToolUse"}) is not None
    assert blocked("curl -X POST localhost:7070/api/vault/agents -d '{\"name\":\"K\",\"agents\":null}'")
    assert blocked("echo codex >> ~/.prismor/secrets/.meta/agents/K")
    assert blocked("rm ~/.prismor/secrets/.meta/agents/K")
    assert not blocked("curl -s localhost:7070/api/vault")   # a GET: names only
