"""Google Antigravity hooks adapter (hooks.json, PreToolUse).

Payload shapes and argument keys were captured live from `agy` 2.19.1.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

from prismor.runtime.hooks import (
    _SUPPORTED_AGENTS,
    _config_path,
    _merge_antigravity,
    _strip_antigravity,
    install_hooks,
    normalize_payload,
    uninstall_hooks,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
CMD = '"python" "shim" hook-dispatch --agent antigravity --mode enforce'


def _payload(name, args, ws="/proj"):
    return {
        "toolCall": {"name": name, "args": args},
        "stepIdx": 3,
        "conversationId": "conv-123",
        "workspacePaths": [ws],
        "transcriptPath": "/proj/.gemini/antigravity/transcript.jsonl",
        "modelName": "auto",
    }


def _event(name, args):
    return normalize_payload(agent="antigravity", payload=_payload(name, args), workspace=Path("/proj"))


def test_supported_and_config_paths(tmp_path):
    assert "antigravity" in _SUPPORTED_AGENTS
    assert _config_path("antigravity", "project", tmp_path) == tmp_path / ".agents" / "hooks.json"
    assert _config_path("antigravity", "global", tmp_path).parts[-3:] == (".gemini", "config", "hooks.json")


def test_merge_registers_pretooluse_and_keeps_other_hooks():
    merged = _merge_antigravity({"lint": {"PostToolUse": [{"matcher": "run_command", "hooks": [{"command": "lint.sh"}]}]}}, CMD)
    assert merged["lint"]["PostToolUse"][0]["hooks"][0]["command"] == "lint.sh"
    group = merged["prismor"]["PreToolUse"][0]
    assert group["matcher"] == "*"
    assert group["hooks"][0]["command"] == CMD and group["hooks"][0]["timeout"] == 60


def test_strip_removes_only_prismor_handlers():
    config = _merge_antigravity({
        "mixed": {"PreToolUse": [{"matcher": "*", "hooks": [{"command": CMD}, {"command": "audit.sh"}]}]},
        "reminder": {"PreInvocation": [{"type": "command", "command": "remind.sh"}]},
    }, CMD)
    stripped, removed = _strip_antigravity(config, "hook-dispatch")
    assert removed
    assert "prismor" not in stripped  # left with no handlers -> dropped
    assert stripped["mixed"]["PreToolUse"][0]["hooks"] == [{"command": "audit.sh"}]
    assert stripped["reminder"]["PreInvocation"][0]["command"] == "remind.sh"
    assert _strip_antigravity(stripped, "hook-dispatch") == (stripped, False)


def test_install_is_idempotent_and_uninstall_cleans(tmp_path):
    for _ in range(2):
        install_hooks(repo_root=REPO_ROOT, workspace=tmp_path, agent="antigravity", scope="project", mode="enforce")
    path = tmp_path / ".agents" / "hooks.json"
    config = json.loads(path.read_text())
    handlers = [h for g in config["prismor"]["PreToolUse"] for h in g["hooks"]]
    assert len(handlers) == 1 and "--agent antigravity" in handlers[0]["command"]
    uninstall_hooks(repo_root=REPO_ROOT, workspace=tmp_path, agent="antigravity", scope="project")
    assert "hook-dispatch" not in path.read_text()


def test_normalize_tools():
    ev = _event("run_command", {"CommandLine": "npm test", "Cwd": "/proj/app"})
    assert ev["sessionId"] == "conv-123"
    e = ev["event"]
    assert (e["agent"], e["type"], e["command"], e["agent_event"]) == ("antigravity", "shell", "npm test", "PreToolUse")
    assert e["metadata"]["cwd"] == "/proj/app"

    v = _event("view_file", {"AbsolutePath": "/proj/.env"})["event"]
    assert (v["type"], v["path"]) == ("file_read", "/proj/.env")

    w = _event("write_to_file", {"TargetFile": "/proj/a.py", "CodeContent": "print(1)", "Overwrite": True})["event"]
    assert (w["type"], w["path"], w["content"]) == ("file_write", "/proj/a.py", "print(1)")

    r = _event("replace_file_content", {"TargetFile": "/proj/a.py",
                                        "ReplacementChunks": [{"ReplacementContent": "x = 1"}]})["event"]
    assert (r["type"], r["content"]) == ("file_write", "x = 1")

    n = _event("read_url_content", {"Url": "https://example.com/x"})["event"]
    assert (n["type"], n["url"]) == ("network", "https://example.com/x")

    d = _event("delete_directory", {"DirectoryPath": "/proj/build"})["event"]
    assert (d["type"], d["command"]) == ("shell", "rm -rf /proj/build")


def test_normalize_mcp_call_uses_server_and_tool_names():
    e = _event("call_mcp_tool", {"ServerName": "github", "ToolName": "create_issue",
                                 "Arguments": '{"title": "x"}'})["event"]
    assert (e["mcp_server"], e["mcp_tool"]) == ("github", "create_issue")
    assert "title" in e["response"]  # arguments stay visible to the rules


def _dispatch(tmp_path, command):
    home = tmp_path / "phome"
    env = {k: v for k, v in os.environ.items() if not k.startswith("PRISMOR_")}
    env.update(PRISMOR_HOME=str(home), HOME=str(tmp_path), PYTHONPATH=str(REPO_ROOT))
    ws = tmp_path / "ws"
    ws.mkdir(exist_ok=True)
    return subprocess.run(
        [sys.executable, "-m", "prismor.runtime.immunity_cli", "hook-dispatch",
         "--agent", "antigravity", "--mode", "enforce"],
        input=json.dumps(_payload("run_command", {"CommandLine": command}, ws=str(ws))),
        capture_output=True, text=True, env=env, cwd=str(tmp_path), timeout=120,
    )


def test_dispatch_denies_on_stdout(tmp_path):
    proc = _dispatch(tmp_path, "chmod -R 777 ./nx")
    assert proc.returncode == 0, proc.stderr
    out = json.loads(proc.stdout.strip().splitlines()[-1])
    assert out["decision"] == "deny" and "destructive-command" in out["reason"]


def test_dispatch_allowed_call_prints_nothing(tmp_path):
    # Empty stdout leaves Antigravity's own permission settings in charge;
    # printing "allow" would auto-approve calls the user meant to review.
    proc = _dispatch(tmp_path, "ls -la")
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == ""
