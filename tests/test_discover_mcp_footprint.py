"""`discover mcp` footprint: live copies, memory and 7-day usage per server.

Fake ps rows and a fake usage count; no real machine state is read.
Run: python3 -m pytest tests/test_discover_mcp_footprint.py
"""
from __future__ import annotations

import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO))

from prismor.runtime import discover  # noqa: E402
from prismor.runtime.discover import McpRecord, _process_needle, add_footprint  # noqa: E402


def test_needle_matches_npx_wrapper_and_child():
    assert _process_needle(["npx", "-y", "@microsoft/clarity-mcp-server", "--t=<redacted>"]) == "clarity-mcp-server"
    assert _process_needle(["npx", "-y", "get-an-expert-agent@latest"]) == "get-an-expert-agent"
    assert _process_needle(["node", "/opt/x/dist/index.js"]) == "/opt/x/dist/index.js"
    assert _process_needle(["/home/u/.local/bin/colab-mcp"]) == "/home/u/.local/bin/colab-mcp"
    assert _process_needle(["npx", "-y"]) == ""


def _fake(monkeypatch, used, total):
    rows = []
    for i in range(5):  # five sessions, each with an npm exec wrapper + node child
        rows.append((f"{i}0", f"s{i}", 2048, "npm exec get-an-expert-agent@latest"))
        rows.append((f"{i}1", f"{i}0", 1024, "node /u/.npm/_npx/ab/node_modules/.bin/get-an-expert-agent"))
    rows.append(("99", "1", 4096, "vim notes-about-something-else"))
    monkeypatch.setattr(discover, "_ps_rows", lambda: rows)
    monkeypatch.setattr(discover, "_session_usage", lambda names, days=7: ({"expert": used}, total))


def _record(**kw):
    return McpRecord(name="expert", agent="claude", source="~/.claude.json",
                     command=["npx", "-y", "get-an-expert-agent@latest"], **kw)


def test_counts_copies_not_processes_and_flags_unused(monkeypatch):
    _fake(monkeypatch, used=0, total=40)
    r = _record()
    add_footprint([r])
    assert (r.running, r.rss_mb, r.sessions_used, r.sessions_total) == (5, 15, 0, 40)
    assert r.rarely_used


def test_no_flag_when_server_is_used_or_project_scoped(monkeypatch):
    _fake(monkeypatch, used=10, total=40)
    used = _record()
    add_footprint([used])
    assert used.running == 5 and not used.rarely_used

    _fake(monkeypatch, used=0, total=40)
    scoped = _record(workspace_scoped=True)
    add_footprint([scoped])
    assert not scoped.rarely_used


def test_usage_only_for_claude_and_remote_not_matched(monkeypatch):
    _fake(monkeypatch, used=0, total=40)
    cursor = McpRecord(name="expert", agent="cursor", source="~/.cursor/mcp.json",
                       url="https://x.example/mcp", remote=True)
    add_footprint([cursor])
    assert cursor.sessions_used is None and cursor.running is None


def test_runs_matches_tokens_not_substrings():
    from prismor.runtime.discover import _runs
    assert _runs("get-an-expert-agent", "npm exec get-an-expert-agent@latest")
    assert _runs("get-an-expert-agent", "node /u/.npm/_npx/ab/node_modules/.bin/get-an-expert-agent")
    assert not _runs("/u/bin/colab-mcp", "vim /u/bin/colab-mcp.py")
    assert not _runs("clarity-mcp-server", "grep clarity-mcp-server-old log")


def test_fix_removes_rarely_used_server_and_keeps_backup(tmp_path):
    import json
    from prismor.runtime import remediate
    cfg = tmp_path / ".claude.json"
    cfg.write_text(json.dumps({"numStartups": 3, "mcpServers": {
        "unused": {"command": "npx", "args": ["-y", "x"]},
        "used": {"command": "npx", "args": ["-y", "y"]}}}))
    report = {"mcp": [
        {"name": "unused", "source": str(cfg), "rarely_used": True, "running": 9,
         "rss_mb": 400, "sessions_used": 0, "sessions_total": 50},
    ]}
    todo = remediate.plan(report, kinds=("mcp_unused",))
    assert [a.kind for a in todo.fixable] == ["mcp_unused"]
    results = remediate.apply(report, repo_root=tmp_path, workspace=tmp_path,
                              kinds=("mcp_unused",), plan_obj=todo)
    assert results[0].status == "fixed"
    data = json.loads(cfg.read_text())
    assert list(data["mcpServers"]) == ["used"] and data["numStartups"] == 3
    backups = list(tmp_path.glob(".claude.json.prismor-*.bak"))
    assert len(backups) == 1 and "unused" in backups[0].read_text()


def test_fix_skips_server_not_in_top_level_block(tmp_path):
    import json
    from prismor.runtime import remediate
    cfg = tmp_path / ".claude.json"
    cfg.write_text(json.dumps({"projects": {"/p": {"mcpServers": {"unused": {"command": "x"}}}}}))
    report = {"mcp": [{"name": "unused", "source": str(cfg), "rarely_used": True}]}
    results = remediate.apply(report, repo_root=tmp_path, workspace=tmp_path, kinds=("mcp_unused",))
    assert results[0].status == "skipped" and "projects" in cfg.read_text()


def test_stop_copies_ends_the_whole_tree_and_never_self():
    import os
    import subprocess
    import time
    from prismor.runtime.discover import _alive, stop_copies
    sess = subprocess.Popen([sys.executable, "-c",
                             "import subprocess,time; subprocess.Popen(['sleep','60']); time.sleep(60)"])
    time.sleep(0.5)
    child = [int(l.split()[0]) for l in subprocess.run(
        ["ps", "-axo", "pid=,ppid="], capture_output=True, text=True).stdout.splitlines()
        if l.split()[1] == str(sess.pid)]
    assert child
    assert stop_copies([sess.pid], grace=2)[0] == 1
    sess.wait(timeout=5)
    assert not any(_alive(c) for c in child)
    assert stop_copies([os.getpid()]) == (0, 0)


def test_plain_fix_does_not_remove_rarely_used_servers():
    from prismor.runtime import remediate
    report = {"mcp": [{"name": "unused", "source": "/nope/.claude.json", "rarely_used": True}]}
    assert all(a.kind == "mcp" for a in remediate.plan(report, kinds=("mcp",)).actions)


def test_prune_two_servers_backs_up_the_original_once(tmp_path):
    import json
    from prismor.runtime import remediate
    cfg = tmp_path / ".claude.json"
    cfg.write_text(json.dumps({"mcpServers": {"a": {"command": "x"}, "b": {"command": "y"},
                                              "keep": {"command": "z"}}}))
    old = tmp_path / ".claude.json.prismor-old.bak"
    old.write_text("earlier run")
    report = {"mcp": [{"name": n, "source": str(cfg), "rarely_used": True} for n in ("a", "b")]}
    results = remediate.apply(report, repo_root=tmp_path, workspace=tmp_path, kinds=("mcp_unused",))
    assert [r.status for r in results] == ["fixed", "fixed"]
    assert list(json.loads(cfg.read_text())["mcpServers"]) == ["keep"]
    backups = [b for b in tmp_path.glob(".claude.json.prismor-*.bak") if b != old]
    assert len(backups) == 1
    assert sorted(json.loads(backups[0].read_text())["mcpServers"]) == ["a", "b", "keep"]
    assert old.read_text() == "earlier run"


def test_needle_never_matches_shells_containers_or_bare_scripts():
    assert _process_needle(["bash", "-c", "node srv.js"]) == ""
    assert _process_needle(["docker", "run", "-i", "--rm", "mcp/github"]) == ""
    assert _process_needle(["/usr/bin/env", "node", "x.js"]) == ""
    assert _process_needle(["uv", "run", "--with", "mcp", "server.py"]) == ""
    assert _process_needle(["npm", "exec", "@s/pkg"]) == "pkg"
    assert _process_needle(["uvx", "mcp-server-fetch"]) == "mcp-server-fetch"
    from prismor.runtime.discover import _runs
    assert not _runs("", "/bin/bash -l")
    assert not _runs("/opt/srv/bin/run", "/usr/opt/srv/bin/run")


def test_usage_key_matches_claude_tool_names():
    from prismor.runtime.discover import _tool_server_key
    assert _tool_server_key("context7.io") == "context7_io"
    assert _tool_server_key("My Server") == "my_server"


def test_stop_copies_skips_a_pid_that_no_longer_runs_the_server():
    import subprocess
    from prismor.runtime.discover import stop_copies
    other = subprocess.Popen(["sleep", "30"])
    try:
        assert stop_copies([other.pid], needles={other.pid: "some-mcp-server"}) == (0, 0)
        assert other.poll() is None
    finally:
        other.kill()
        other.wait()


def test_prune_writes_through_a_symlink(tmp_path):
    import json
    from prismor.runtime import remediate
    real = tmp_path / "dotfiles" / "claude.json"
    real.parent.mkdir()
    real.write_text(json.dumps({"mcpServers": {"a": {"command": "x"}, "b": {"command": "y"}}}))
    link = tmp_path / ".claude.json"
    link.symlink_to(real)
    report = {"mcp": [{"name": "a", "source": str(link), "rarely_used": True}]}
    assert remediate.apply(report, repo_root=tmp_path, workspace=tmp_path,
                           kinds=("mcp_unused",))[0].status == "fixed"
    assert link.is_symlink() and list(json.loads(real.read_text())["mcpServers"]) == ["b"]
    assert not list(real.parent.glob("*.prismor-tmp"))


def test_fix_and_prune_run_as_one_plan(monkeypatch, tmp_path):
    from prismor.runtime import discover_cli
    calls = []
    monkeypatch.setattr(discover_cli._discover, "discover_mcp", lambda ws: [])
    monkeypatch.setattr(discover_cli._discover, "add_footprint", lambda r: None)
    monkeypatch.setattr(discover_cli, "run_fix", lambda rep, **kw: calls.append(kw["kinds"]))
    discover_cli.discover_mcp(tmp_path, fix=True, prune=True, repo_root=tmp_path)
    assert calls == [("mcp", "mcp_unused")]


def test_report_upload_carries_footprint(monkeypatch):
    from dataclasses import asdict
    _fake(monkeypatch, used=0, total=40)
    monkeypatch.setattr(discover, "_fix_index", lambda report: {})
    report = {"mcp": [asdict(_record())], "agents": [], "credentials": [], "summary": {}}
    payload = discover.report_payload(discover._with_footprint(report))
    f = payload["findings"][0]
    assert (f["running"], f["rss_mb"], f["sessions_used"], f["sessions_total"], f["rarely_used"]) == (5, 15, 0, 40, True)
    # An unmeasured report still uploads, with nulls.
    f = discover.report_payload(report)["findings"][0]
    assert f["rss_mb"] is None and f["rarely_used"] is False
