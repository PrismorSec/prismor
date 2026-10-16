"""The two runtime exits from a governing mirror — `prismor pause` and the
override (pass-through) switch — and the config exit, `prismor mirror on/off`.

Background: the first live deployment blocked the human's own work and neither
`prismor pause` (gateway ignored it) nor the dashboard switch (turned the mirror
into "unknown tool" for every call) got them out. These pin the fixed behaviour.
"""
import json
from pathlib import Path

import pytest

from prismor.runtime import mirror
from prismor.runtime.mcp_gateway import Gateway, UpstreamSpec
from prismor.runtime.runtime import Decision

#: built at import time so this file never contains a literal placeholder,
#: which Prismor's own decloak hook would try to resolve and fail closed on.
PLACEHOLDER = "@@" + "SECRET:" + "DEMO_TOKEN" + "@@"


@pytest.fixture()
def ws(tmp_path):
    (tmp_path / "f.txt").write_text("hello\n")
    return tmp_path


def _gateway(ws, mode="enforce"):
    gw = Gateway([UpstreamSpec(name="builtins", local=True)], workspace=ws, mode=mode)
    sent = []
    gw._send = lambda msg: sent.append(msg)
    gw._handle_tools_list(1, {})
    return gw, sent


_BLOCK = Decision(allow=False, blocking={"severity": "critical", "title": "rm -rf",
                                          "ruleId": "destructive-command"})


def test_enforce_blocks_and_tells_the_human_how_out(ws, monkeypatch):
    monkeypatch.setattr("prismor.runtime.pause.active_state", lambda: None)
    monkeypatch.setattr("prismor.runtime.runtime.evaluate_tool_call", lambda **k: _BLOCK)
    gw, sent = _gateway(ws)
    gw._handle_tools_call_safe(2, {"name": "Read", "arguments": {"file_path": str(ws / "f.txt")}})
    res = sent[-1]["result"]
    assert res["isError"] is True
    text = res["content"][0]["text"]
    assert "Blocked by Prismor" in text and "destructive-command" in text
    # The gateway used to stop at the block; now it says how to lift it.
    assert "prismor pause" in text and "prismor mirror off" in text
    gw.close()


def test_pause_passes_the_call_through(ws, monkeypatch):
    """`prismor pause` must mean the same thing to the gateway as to the hooks:
    enforcement off, screening on."""
    monkeypatch.setattr("prismor.runtime.pause.active_state",
                        lambda: {"paused": True, "until": None, "source": "local"})
    calls = []

    def _eval(**k):
        calls.append(k["event"]["agent_event"])
        return _BLOCK
    monkeypatch.setattr("prismor.runtime.runtime.evaluate_tool_call", _eval)
    gw, sent = _gateway(ws)
    gw._handle_tools_call_safe(2, {"name": "Read", "arguments": {"file_path": str(ws / "f.txt")}})
    res = sent[-1]["result"]
    assert not res.get("isError")
    assert "hello" in res["content"][0]["text"]
    # Still evaluated pre AND post — pass-through is observe, not blindness.
    assert calls == ["PreToolUse", "PostToolUse"]
    gw.close()


def test_pause_does_not_turn_off_secret_masking(ws, monkeypatch):
    """`prismor pause` suspends ENFORCEMENT, not Cloak.

    Corrects an earlier reading of pause as "stop interfering with everything".
    The hook-layer scrubber never consults the pause marker, so if the mirror
    did, the same command would leak a raw secret into the model's context over
    one transport and not the other — and pausing would quietly become a way to
    exfiltrate. Policy-driven data-boundary redaction does stop; cloak masking
    of registered values does not.
    """
    monkeypatch.setattr("prismor.runtime.pause.active_state",
                        lambda: {"paused": True, "until": None})
    monkeypatch.setattr("prismor.runtime.runtime.evaluate_tool_call",
                        lambda **k: Decision(allow=True))
    monkeypatch.setattr("prismor.runtime.cloaking.runtime._read_secret_map",
                        lambda: {"X": "hello-secret-value"})
    (ws / "f.txt").write_text("token=hello-secret-value\n")
    gw, sent = _gateway(ws)
    gw._handle_tools_call_safe(2, {"name": "Read", "arguments": {"file_path": str(ws / "f.txt")}})
    text = sent[-1]["result"]["content"][0]["text"]
    assert "hello-secret-value" not in text, "a paused mirror must still mask registered secrets"
    assert "SECRET" in text
    gw.close()


def test_mirrored_bash_decloaks_placeholders(ws, monkeypatch):
    """The cloak hook matches the exact tool name "Bash", so mirroring
    (mcp__prismor-tools__Bash) silently stopped substituting placeholders and
    the literal reached the shell."""
    monkeypatch.setattr("prismor.runtime.cloaking.runtime._read_secret_map",
                        lambda: {"DEMO_TOKEN": "s3cr3t-value-1234"})
    out = mirror.execute("Bash", {"command": "echo " + PLACEHOLDER}, ws)
    assert "s3cr3t-value-1234" in out


@pytest.mark.parametrize("template", ['echo "{}"', "echo {}", "echo '{}'"])
def test_mirrored_bash_secret_value_is_data_not_shell(ws, tmp_path, monkeypatch, template):
    """#616: a secret holding shell syntax must not run after policy passed the
    placeholder form — the value expands as an argument, never reparsed."""
    vault = tmp_path / "vault"
    vault.mkdir()
    marker = tmp_path / "pwned"
    payload = f'tok"; touch {marker}; echo "$(touch {marker})'
    (vault / "DEMO_TOKEN").write_text(payload)
    monkeypatch.setenv("PRISMOR_SECRETS_DIR", str(vault))
    out = mirror.execute("Bash", {"command": template.format(PLACEHOLDER)}, ws)
    assert not marker.exists(), "secret value was executed as shell code"
    assert out.strip() == payload


def test_unregistered_placeholder_fails_closed(ws, monkeypatch):
    monkeypatch.setattr("prismor.runtime.cloaking.runtime._read_secret_map", lambda: {})
    with pytest.raises(mirror.MirrorError, match="unregistered secret placeholder"):
        mirror.execute("Bash", {"command": "echo " + PLACEHOLDER}, ws)


def test_decloaked_value_never_reaches_policy_or_the_model(ws, monkeypatch):
    """The placeholder form is what gets screened and logged; the real value
    exists only in the subprocess, and the output is masked back."""
    monkeypatch.setattr("prismor.runtime.cloaking.runtime._read_secret_map",
                        lambda: {"DEMO_TOKEN": "s3cr3t-value-1234"})
    seen = []

    def _eval(**k):
        seen.append(json.dumps(k["event"]))
        return Decision(allow=True)
    monkeypatch.setattr("prismor.runtime.runtime.evaluate_tool_call", _eval)
    gw, sent = _gateway(ws)
    gw._handle_tools_call_safe(2, {"name": "Bash",
                                   "arguments": {"command": "echo " + PLACEHOLDER}})
    assert not any("s3cr3t-value-1234" in ev for ev in seen), "policy saw the real secret"
    assert "s3cr3t-value-1234" not in json.dumps(sent[-1]), "the model saw the real secret"
    gw.close()


def test_override_off_passes_through_but_keeps_serving(ws, monkeypatch):
    monkeypatch.setattr("prismor.runtime.pause.active_state", lambda: None)
    monkeypatch.setattr("prismor.runtime.runtime.evaluate_tool_call", lambda **k: _BLOCK)
    mirror.set_mirror_config(ws, override=False)
    gw, sent = _gateway(ws)
    names = [t["name"] for t in sent[0]["result"]["tools"]]
    assert "Read" in names, "pass-through must not un-list the tools"
    gw._handle_tools_call_safe(2, {"name": "Read", "arguments": {"file_path": str(ws / "f.txt")}})
    assert "hello" in sent[-1]["result"]["content"][0]["text"]
    gw.close()


def test_switching_back_to_governing_takes_effect_on_the_next_call(ws, monkeypatch):
    """No restart: the switch is read per call."""
    monkeypatch.setattr("prismor.runtime.pause.active_state", lambda: None)
    monkeypatch.setattr("prismor.runtime.runtime.evaluate_tool_call", lambda **k: _BLOCK)
    mirror.set_mirror_config(ws, override=False)
    gw, sent = _gateway(ws)
    gw._handle_tools_call_safe(2, {"name": "Read", "arguments": {"file_path": str(ws / "f.txt")}})
    assert not sent[-1]["result"].get("isError")
    mirror.set_mirror_config(ws, override=True)
    gw._handle_tools_call_safe(3, {"name": "Read", "arguments": {"file_path": str(ws / "f.txt")}})
    assert sent[-1]["result"]["isError"] is True
    gw.close()


def test_pause_applies_to_remote_upstreams_as_well(tmp_path, monkeypatch):
    """A remote MCP tool call is a hooked call by another transport; a pause
    the hooks honour and the gateway ignores is a lie to the person who ran it."""
    from tests.test_mcp_gateway import stub, make_gateway, list_tools
    a = stub("github")
    gateway, sent = make_gateway(tmp_path, monkeypatch, [a])
    list_tools(gateway, sent)
    monkeypatch.setattr("prismor.runtime.pause.active_state",
                        lambda: {"paused": True, "until": None})
    monkeypatch.setattr("prismor.runtime.runtime.evaluate_tool_call", lambda **k: _BLOCK)
    gateway._handle_tools_call_safe("C2", {"name": "github__echo", "arguments": {}})
    assert not sent[-1]["result"].get("isError")
    assert any(m == "tools/call" for m, _ in a.requests)


# ── prismor mirror on / off ──────────────────────────────────────────────────

def test_mirror_on_then_off_round_trips_claude_config(tmp_path, monkeypatch):
    from prismor.runtime import mirror_cli
    monkeypatch.setattr("prismor.runtime.pause.active_state", lambda: None)
    (tmp_path / ".mcp.json").write_text(json.dumps(
        {"mcpServers": {"prismor": {"type": "http", "url": "https://mcp.example/x"}}}))
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text(json.dumps(
        {"hooks": {"PreToolUse": []}, "permissions": {"deny": ["WebSearch"], "allow": ["Bash(ls:*)"]}}))

    assert mirror_cli.mirror_on(tmp_path, mode="enforce") == 0
    mcp = json.loads((tmp_path / ".mcp.json").read_text())
    entry = mcp["mcpServers"][mirror.MIRROR_SERVER_NAME]
    assert "--mirror" in entry["args"] and "--workspace" in entry["args"]
    assert "prismor" in mcp["mcpServers"], "the hosted connector must survive"
    settings = json.loads((tmp_path / ".claude" / "settings.json").read_text())
    deny = settings["permissions"]["deny"]
    assert "WebSearch" in deny and all(t in deny for t in mirror.NATIVE_TOOLS_TO_DISABLE)
    assert "MultiEdit" in deny, "an ungoverned native writer would bypass the mirror"
    assert settings["permissions"]["allow"] == ["Bash(ls:*)"]
    assert settings["hooks"] == {"PreToolUse": []}
    assert (tmp_path / ".mcp.json.pre-mirror.bak").exists()
    assert mirror.mirror_config(tmp_path)["override"] is True

    # A second `on` is idempotent (no duplicate deny entries).
    assert mirror_cli.mirror_on(tmp_path, mode="enforce") == 0
    deny = json.loads((tmp_path / ".claude" / "settings.json").read_text())["permissions"]["deny"]
    assert len(deny) == len(set(deny))

    assert mirror_cli.mirror_off(tmp_path) == 0
    mcp = json.loads((tmp_path / ".mcp.json").read_text())
    assert mirror.MIRROR_SERVER_NAME not in mcp["mcpServers"] and "prismor" in mcp["mcpServers"]
    settings = json.loads((tmp_path / ".claude" / "settings.json").read_text())
    # Only OUR entries went; the pre-existing deny and everything else stayed.
    assert settings["permissions"] == {"deny": ["WebSearch"], "allow": ["Bash(ls:*)"]}
    assert settings["hooks"] == {"PreToolUse": []}
    data = json.loads((tmp_path / ".prismor" / "mirror.json").read_text())
    assert "install" not in data


def test_mirror_on_creates_missing_files(tmp_path, monkeypatch):
    from prismor.runtime import mirror_cli
    monkeypatch.setattr("prismor.runtime.pause.active_state", lambda: None)
    assert mirror_cli.mirror_on(tmp_path) == 0
    assert mirror.MIRROR_SERVER_NAME in json.loads((tmp_path / ".mcp.json").read_text())["mcpServers"]
    settings = json.loads((tmp_path / ".claude" / "settings.json").read_text())
    assert set(settings["permissions"]["deny"]) == set(mirror.NATIVE_TOOLS_TO_DISABLE)
    assert mirror_cli.mirror_off(tmp_path) == 0
    # Files `on` created are removed again, not left behind as `{}`.
    assert not (tmp_path / ".claude" / "settings.json").exists()
    assert not (tmp_path / ".mcp.json").exists()


def test_mirror_off_when_never_on_is_a_noop(tmp_path, capsys):
    from prismor.runtime import mirror_cli
    assert mirror_cli.mirror_off(tmp_path) == 0
    assert "nothing to undo" in capsys.readouterr().out
    assert not (tmp_path / ".prismor" / "mirror.json").exists()


def test_mirror_status_names_the_state(tmp_path, monkeypatch, capsys):
    from prismor.runtime import mirror_cli
    monkeypatch.setattr("prismor.runtime.pause.active_state", lambda: None)
    mirror_cli.mirror_status(tmp_path)
    out = capsys.readouterr().out
    assert "not configured" in out and "governing" in out
    mirror.set_mirror_config(tmp_path, override=False)
    mirror_cli.mirror_status(tmp_path)
    assert "PASS-THROUGH" in capsys.readouterr().out
    monkeypatch.setattr("prismor.runtime.pause.active_state",
                        lambda: {"paused": True, "until": None})
    mirror_cli.mirror_status(tmp_path)
    assert "PAUSED" in capsys.readouterr().out


def test_relocated_prismor_home_is_pinned_into_the_server_entry(tmp_path, monkeypatch):
    """The host launches the gateway from its own environment. A $PRISMOR_HOME
    that only exists in the developer's shell would leave the gateway reading a
    different home than `prismor pause` writes to."""
    from prismor.runtime import mirror_cli
    monkeypatch.setattr("prismor.runtime.pause.active_state", lambda: None)
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / "home"))
    assert mirror_cli.mirror_on(tmp_path) == 0
    entry = json.loads((tmp_path / ".mcp.json").read_text())["mcpServers"][mirror.MIRROR_SERVER_NAME]
    assert entry["env"]["PRISMOR_HOME"] == str(tmp_path / "home")


def test_default_prismor_home_is_not_written_into_the_entry(tmp_path, monkeypatch):
    from prismor.runtime import mirror_cli
    monkeypatch.setattr("prismor.runtime.pause.active_state", lambda: None)
    monkeypatch.setenv("PRISMOR_HOME", str(Path.home() / ".prismor"))
    assert mirror_cli.mirror_on(tmp_path) == 0
    entry = json.loads((tmp_path / ".mcp.json").read_text())["mcpServers"][mirror.MIRROR_SERVER_NAME]
    assert "PRISMOR_HOME" not in entry["env"]


def test_on_refuses_to_disable_natives_when_the_server_cannot_start(tmp_path, monkeypatch, capsys):
    """The worst outcome is a half-install: natives denied, mirror broken, agent
    with no tools and no explanation. Preflight has to fail closed."""
    from prismor.runtime import mirror_cli
    monkeypatch.setattr("prismor.runtime.pause.active_state", lambda: None)
    monkeypatch.setattr(mirror_cli, "_preflight", lambda entry, timeout=25.0: (False, "boom"))
    assert mirror_cli.mirror_on(tmp_path) == 1
    out = capsys.readouterr().out
    assert "failed to start" in out and "Nothing was changed" in out
    assert not (tmp_path / ".mcp.json").exists()
    assert not (tmp_path / ".claude" / "settings.json").exists()


def test_preflight_really_starts_the_server_and_lists_tools(tmp_path, monkeypatch):
    """End-to-end through the actual entry the command writes: spawn it, speak
    MCP, get the roster back."""
    from prismor.runtime import mirror_cli
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / "home"))
    entry = mirror_cli._server_entry(tmp_path, "enforce")
    ok, detail = mirror_cli._preflight(entry, timeout=60.0)
    assert ok, detail
    assert "Bash" in detail and "Read" in detail


# ── host-side approval (the trap that made `on` a no-tools install) ──────────

def test_on_approves_only_this_server_in_local_settings(tmp_path, monkeypatch):
    """A project .mcp.json server does not load until a human approves it, and
    a project file cannot vouch for itself. Verified against Claude Code
    2.1.210: with this key the mirror connects; without it the agent gets no
    tools at all, because the natives are already denied."""
    from prismor.runtime import mirror_cli
    monkeypatch.setattr("prismor.runtime.pause.active_state", lambda: None)
    monkeypatch.setattr(mirror_cli, "_preflight", lambda entry, timeout=25.0: (True, "Bash, Read"))
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.local.json").write_text(
        json.dumps({"enabledMcpjsonServers": ["some-other"], "permissions": {"allow": ["WebSearch"]}}))

    assert mirror_cli.mirror_on(tmp_path) == 0
    local = json.loads((tmp_path / ".claude" / "settings.local.json").read_text())
    assert local["enabledMcpjsonServers"] == ["some-other", "prismor-tools"]
    assert local["permissions"] == {"allow": ["WebSearch"]}, "unrelated local settings must survive"
    # Never the blanket grant: that would auto-trust every server any repo declares.
    assert "enableAllProjectMcpServers" not in local

    assert mirror_cli.mirror_off(tmp_path) == 0
    local = json.loads((tmp_path / ".claude" / "settings.local.json").read_text())
    assert local["enabledMcpjsonServers"] == ["some-other"]


def test_off_removes_a_local_settings_file_it_created(tmp_path, monkeypatch):
    from prismor.runtime import mirror_cli
    monkeypatch.setattr("prismor.runtime.pause.active_state", lambda: None)
    monkeypatch.setattr(mirror_cli, "_preflight", lambda entry, timeout=25.0: (True, "Bash"))
    assert mirror_cli.mirror_on(tmp_path) == 0
    assert (tmp_path / ".claude" / "settings.local.json").exists()
    assert mirror_cli.mirror_off(tmp_path) == 0
    assert not (tmp_path / ".claude" / "settings.local.json").exists()


def test_on_respects_an_explicit_human_no(tmp_path, monkeypatch, capsys):
    """If the human disabled this server, `on` must not flip it back — it warns
    instead, so they are not left silently toolless."""
    from prismor.runtime import mirror_cli
    monkeypatch.setattr("prismor.runtime.pause.active_state", lambda: None)
    monkeypatch.setattr(mirror_cli, "_preflight", lambda entry, timeout=25.0: (True, "Bash"))
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.local.json").write_text(
        json.dumps({"disabledMcpjsonServers": ["prismor-tools"]}))
    assert mirror_cli.mirror_on(tmp_path) == 0
    out = capsys.readouterr().out
    assert "could not auto-approve" in out and "disabledMcpjsonServers" in out
    local = json.loads((tmp_path / ".claude" / "settings.local.json").read_text())
    assert "enabledMcpjsonServers" not in local


# ── tool permissions (the second reason `on` produced a toolless agent) ──────

def test_existing_allow_posture_is_carried_onto_the_mirrored_names(tmp_path, monkeypatch):
    """Claude Code gates MCP tools behind the same prompt as any other tool, and
    the mirror renames them, so every allow rule for Bash stops applying."""
    from prismor.runtime import mirror_cli
    monkeypatch.setattr("prismor.runtime.pause.active_state", lambda: None)
    monkeypatch.setattr(mirror_cli, "_preflight", lambda entry, timeout=25.0: (True, "Bash"))
    home = tmp_path / "home"; (home / ".claude").mkdir(parents=True)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    # User had Bash/Read allowed outright, Glob only for one pattern.
    (home / ".claude" / "settings.json").write_text(json.dumps(
        {"permissions": {"allow": ["Bash", "Read", "Glob(src/**)", "WebSearch"]}}))
    ws = tmp_path / "proj"; ws.mkdir()

    assert mirror_cli.mirror_on(ws) == 0
    # The grant lands in the human's LOCAL settings: a project's shared
    # settings.json may restrict but may not widen its own authority, so an
    # allow rule written there is ignored by the host (verified live).
    local = json.loads((ws / ".claude" / "settings.local.json").read_text())
    allow = local["permissions"]["allow"]
    assert allow == ["mcp__prismor-tools__Bash", "mcp__prismor-tools__Read"]
    shared = json.loads((ws / ".claude" / "settings.json").read_text())
    assert "allow" not in shared.get("permissions", {})
    assert shared["permissions"]["deny"], "the restriction still belongs in the shared file"
    # A pattern-scoped rule has no meaning over MCP, so it is NOT widened.
    assert not any("Glob" in a for a in allow)
    # And nothing is invented for tools the human never allowed.
    assert not any("Write" in a for a in allow)

    assert mirror_cli.mirror_off(ws) == 0
    local = json.loads((ws / ".claude" / "settings.local.json").read_text()) \
        if (ws / ".claude" / "settings.local.json").exists() else {}
    assert "allow" not in local.get("permissions", {})


def test_allow_tools_flag_pre_allows_everything_for_headless(tmp_path, monkeypatch):
    from prismor.runtime import mirror_cli
    monkeypatch.setattr("prismor.runtime.pause.active_state", lambda: None)
    monkeypatch.setattr(mirror_cli, "_preflight", lambda entry, timeout=25.0: (True, "Bash"))
    home = tmp_path / "home"; (home / ".claude").mkdir(parents=True)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    ws = tmp_path / "proj"; ws.mkdir()
    assert mirror_cli.mirror_on(ws, allow_tools=True) == 0
    allow = json.loads((ws / ".claude" / "settings.local.json").read_text())["permissions"]["allow"]
    assert sorted(allow) == sorted(f"mcp__prismor-tools__{t}" for t in mirror.mirror_tool_names())


def test_without_prior_allow_the_command_says_headless_will_stall(tmp_path, monkeypatch, capsys):
    from prismor.runtime import mirror_cli
    monkeypatch.setattr("prismor.runtime.pause.active_state", lambda: None)
    monkeypatch.setattr(mirror_cli, "_preflight", lambda entry, timeout=25.0: (True, "Bash"))
    home = tmp_path / "home"; (home / ".claude").mkdir(parents=True)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    ws = tmp_path / "proj"; ws.mkdir()
    assert mirror_cli.mirror_on(ws) == 0
    assert "--allow-tools" in capsys.readouterr().out


def test_no_split_brain_warning_for_one_install_spelled_two_ways(tmp_path, monkeypatch):
    """The hook installer and older builds disagree on whether PYTHONPATH names
    the package or its parent. Both spellings are the SAME install, and a
    warning that fires on every ordinary pipx setup is one nobody reads."""
    from prismor.runtime import mirror_cli
    site = tmp_path / "site-packages"
    (site / "prismor" / "runtime").mkdir(parents=True)
    home = tmp_path / "home"; (home / ".claude").mkdir(parents=True)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    (home / ".claude" / "settings.json").write_text(json.dumps({"hooks": {"PreToolUse": [
        {"hooks": [{"type": "command",
                    "command": f'PRISMOR_HOME="{home}/.prismor" PYTHONPATH="{site}/prismor" '
                               f'python3 -m prismor.runtime.immunity_cli hook-dispatch --agent claude'}]}]}}))
    # An installed tree can also carry a nested prismor/prismor/runtime; the
    # resolution must not mistake that for a second installation.
    (site / "prismor" / "prismor" / "runtime").mkdir(parents=True)
    entry = {"env": {"PYTHONPATH": str(site), "PRISMOR_HOME": str(home / ".prismor")}}
    assert mirror_cli._coherence_warnings(tmp_path, entry) == []

    # A genuinely different checkout still warns.
    other = tmp_path / "other"; (other / "prismor" / "runtime").mkdir(parents=True)
    entry["env"]["PYTHONPATH"] = str(other)
    warns = mirror_cli._coherence_warnings(tmp_path, entry)
    assert warns and "install-hooks" in warns[0]


# ── governance surfaces (what `prismor setup` shows) ────────────────────────

def test_hooks_are_recommended_wherever_they_exist():
    """The two surfaces are not interchangeable: hooks cover the agent's whole
    tool surface, the mirror only holds while the natives stay off. So an agent
    with hooks must never be steered to the mirror by default."""
    from prismor.runtime.integrations.registry import load_registry, governance
    for entry in load_registry():
        g = governance(entry.id)
        if g["hooks"]:
            assert g["recommended"] == "hooks", entry.id


def test_agents_that_cannot_disable_natives_are_not_offered_a_mirror():
    """Mirroring a host that cannot switch its built-ins off is bypassable —
    the model just calls the real Bash. Better to report no surface than to
    imply a control that is not there."""
    from prismor.runtime.integrations.registry import load_registry, governance
    for entry in load_registry():
        if str(entry.mirror.get("status")) == "unsupported":
            assert governance(entry.id)["recommended"] != "mirror", entry.id


def test_mirror_only_agents_are_surfaced_to_setup():
    """They are absent from the wizard's hook list by construction, so without
    this they look unsupported rather than differently-supported."""
    from prismor.runtime.setup_wizard import _mirror_only_agents
    names = _mirror_only_agents()
    assert "Amp" in names
    assert "Claude Code" not in names, "an agent with hooks must not be listed as MCP-only"
    # OpenCode's hooks are a plugin install-hooks writes; it is not MCP-only.
    assert "OpenCode" not in names


def test_registry_mirror_blocks_are_well_formed():
    from prismor.runtime.integrations.registry import load_registry
    seen = 0
    for entry in load_registry():
        m = entry.mirror
        if not m:
            continue
        seen += 1
        assert m["status"] in ("verified", "possible", "unsupported"), entry.id
        if m["status"] in ("verified", "possible"):
            assert m.get("scope") in ("project", "machine"), entry.id
            assert m.get("disable"), f"{entry.id}: a usable mirror must say how natives are disabled"
        else:
            assert m.get("notes"), f"{entry.id}: an unsupported mirror must say why"
    assert seen >= 20


# ── setup: the mirror is opt-in, hooks are what you get by default ──────────

def test_setup_offers_the_mirror_only_where_it_can_actually_wire_it():
    """A toggle that cannot complete is worse than no toggle: a half-install
    leaves the agent with no tools at all."""
    from prismor.runtime.setup_wizard import _can_mirror
    from prismor.runtime.mirror_cli import INSTALLABLE_AGENTS
    assert _can_mirror("claude", {"mirror": "verified"})
    assert _can_mirror("codex", {"mirror": "verified"})
    # A host whose built-ins cannot be switched off is never offered one: the
    # model would simply call the real Bash instead.
    assert not _can_mirror("warp", {"mirror": "unsupported"})
    assert _can_mirror("opencode", {"mirror": "possible"})
    # ...and neither is a host nobody has wired, however capable it is.
    assert "amp" not in INSTALLABLE_AGENTS
    assert not _can_mirror("amp", {"mirror": "possible"})


def test_do_install_signature_defaults_to_hooks_only():
    """Every caller that does not ask for the mirror must get hooks only —
    installing it by default would replace the agent's tools without consent."""
    import inspect
    from prismor.runtime.setup_wizard import _do_install
    sig = inspect.signature(_do_install)
    assert sig.parameters["mirror_agents"].default is None


def test_non_interactive_setup_never_installs_the_mirror():
    """`prismor setup --non-interactive` has no screen to opt in on, so it must
    not silently replace an agent's toolkit."""
    import re
    from pathlib import Path
    import prismor.runtime.setup_wizard as w
    src = Path(w.__file__).read_text()
    # the non-interactive branch calls _do_install without mirror_agents
    calls = re.findall(r"_do_install\(([^)]*)\)", src, re.S)
    assert calls, "no _do_install call sites found"
    assert any("mirror_agents" not in c for c in calls), "non-interactive path must stay hooks-only"


def test_codex_is_wired_and_declares_machine_scope():
    """Codex reads MCP servers and [features] only from the user-level config,
    so mirroring it cannot be scoped to one project — the command has to say so
    rather than let someone discover it later."""
    from prismor.runtime.mirror_cli import INSTALLABLE_AGENTS, _CODEX_NATIVE_FEATURES
    from prismor.runtime.integrations.registry import governance
    assert "codex" in INSTALLABLE_AGENTS
    assert governance("codex")["scope"] == "machine"
    # unified_exec is a SECOND shell surface; disabling only shell_tool leaves
    # the model a way around the mirror.
    assert "shell_tool" in _CODEX_NATIVE_FEATURES
    assert "unified_exec" in _CODEX_NATIVE_FEATURES


def test_codex_off_only_re_enables_what_it_disabled(tmp_path, monkeypatch):
    """A feature the user had already turned off for their own reasons is not
    ours to switch back on."""
    from prismor.runtime import mirror_cli
    calls = []
    monkeypatch.setattr(mirror_cli, "_codex", lambda *a: (calls.append(a) or (True, "")))
    monkeypatch.setattr(mirror_cli, "_codex_record_path", lambda: tmp_path / "rec.json")
    (tmp_path / "rec.json").write_text(json.dumps(
        {"server": "prismor-tools", "features_disabled": ["shell_tool"]}))
    assert mirror_cli.mirror_off_codex(tmp_path) == 0
    enabled = [c for c in calls if c[:2] == ("features", "enable")]
    assert enabled == [("features", "enable", "shell_tool")]


# ── OpenCode ────────────────────────────────────────────────────────────────

def test_opencode_round_trips_its_project_config(tmp_path, monkeypatch):
    """One project file declares the server AND grants it — OpenCode has no
    separate trust gate — so `on` is a single edit and `off` must undo it
    exactly, leaving unrelated keys alone."""
    from prismor.runtime import mirror_cli
    monkeypatch.setattr(mirror_cli, "_preflight", lambda entry, timeout=25.0: (True, "Bash, Read"))
    cfg = tmp_path / "opencode.json"
    cfg.write_text(json.dumps({"model": "anthropic/claude-sonnet-4-5",
                               "tools": {"webfetch": False}}))

    assert mirror_cli.mirror_on_opencode(tmp_path) == 0
    data = json.loads(cfg.read_text())
    # keyed directly under `mcp`, not `mcp.servers` (OpenCode 1.18 rejects that)
    server = data["mcp"]["prismor-tools"]
    assert server["type"] == "local" and server["enabled"] is True
    assert "--mirror" in server["command"]
    for key in mirror_cli._OPENCODE_DENY_KEYS:
        assert data["permission"][key] == "deny"
        for agent in mirror_cli._OPENCODE_AGENTS:
            assert data["agent"][agent]["permission"][key] == "deny"
    assert data["model"] == "anthropic/claude-sonnet-4-5", "unrelated config must survive"
    assert data["tools"] == {"webfetch": False}, "the developer's own tools block is left alone"
    assert (tmp_path / "opencode.json.pre-mirror.bak").exists()

    assert mirror_cli.mirror_off_opencode(tmp_path) == 0
    data = json.loads(cfg.read_text())
    data.pop("$schema", None)  # `on` adds it; harmless to keep
    assert data == {"model": "anthropic/claude-sonnet-4-5", "tools": {"webfetch": False}}


def test_opencode_off_leaves_a_tool_the_developer_disabled(tmp_path, monkeypatch):
    from prismor.runtime import mirror_cli
    monkeypatch.setattr(mirror_cli, "_preflight", lambda entry, timeout=25.0: (True, "Bash"))
    cfg = tmp_path / "opencode.json"
    cfg.write_text(json.dumps({"tools": {"bash": False}}))
    assert mirror_cli.mirror_on_opencode(tmp_path) == 0
    assert mirror_cli.mirror_off_opencode(tmp_path) == 0
    data = json.loads(cfg.read_text())
    assert data["tools"]["bash"] is False, "on() never disabled it, so off() must not enable it"


def test_opencode_is_hooked_first_and_mirrorable():
    """OpenCode's hooks are a plugin `install-hooks` writes, so hooks are the
    recommendation; the mirror stays available as the layer that holds under
    `opencode --pure` (no external plugins)."""
    from prismor.runtime.integrations.registry import governance
    from prismor.runtime.mirror_cli import INSTALLABLE_AGENTS
    g = governance("opencode")
    assert g["hooks"] is True
    assert g["recommended"] == "hooks"
    assert g["surfaces"] == "hooks + MCP"
    assert "opencode" in INSTALLABLE_AGENTS


# OpenCode merges the developer's `permission` over `tools: {x: false}` and
# applies the last matching rule, so a mirror that only set `tools` left the
# natives on whenever any config layer allowed them (verified on 1.19.2).

def _oc_on_off(tmp_path, monkeypatch, project):
    from prismor.runtime import mirror_cli
    monkeypatch.setattr(mirror_cli, "_preflight", lambda entry, timeout=25.0: (True, "Bash"))
    cfg = tmp_path / "opencode.json"
    cfg.write_text(json.dumps(project))
    assert mirror_cli.mirror_on_opencode(tmp_path) == 0
    on = json.loads(cfg.read_text())
    assert mirror_cli.mirror_off_opencode(tmp_path) == 0
    off = json.loads(cfg.read_text()) if cfg.exists() else {}
    off.pop("$schema", None)  # `on` adds it; harmless to keep
    return on, off


@pytest.mark.parametrize("permission", [
    {"bash": "allow"},
    {"bash": "allow", "*": "allow"},
    "allow",
    {"bash": {"git *": "allow", "*": "ask"}, "external_directory": "deny"},
])
def test_opencode_denies_come_last_and_off_restores_permission(tmp_path, monkeypatch, permission):
    from prismor.runtime import mirror_cli
    on, off = _oc_on_off(tmp_path, monkeypatch, {"permission": permission})
    keys = list(on["permission"])
    assert keys[-len(mirror_cli._OPENCODE_DENY_KEYS):] == list(mirror_cli._OPENCODE_DENY_KEYS), \
        "OpenCode applies the last matching rule: the denies must come after any '*'"
    if isinstance(permission, str):
        assert on["permission"]["*"] == permission, "a blanket permission is kept for everything else"
    assert off == {"permission": permission}


def test_opencode_agent_denies_keep_the_developers_agent_config(tmp_path, monkeypatch):
    project = {"agent": {"build": {"model": "x/y", "permission": {"bash": "allow"}},
                         "reviewer": {"prompt": "review"}}}
    on, off = _oc_on_off(tmp_path, monkeypatch, project)
    assert on["agent"]["build"]["model"] == "x/y"
    assert on["agent"]["build"]["permission"]["bash"] == "deny"
    assert on["agent"]["explore"]["permission"]["bash"] == "deny"
    assert on["agent"]["reviewer"] == {"prompt": "review"}
    assert off == project


def test_opencode_on_twice_still_restores_the_original(tmp_path, monkeypatch):
    from prismor.runtime import mirror_cli
    monkeypatch.setattr(mirror_cli, "_preflight", lambda entry, timeout=25.0: (True, "Bash"))
    cfg = tmp_path / "opencode.json"
    original = {"permission": {"bash": "allow"}}
    cfg.write_text(json.dumps(original))
    assert mirror_cli.mirror_on_opencode(tmp_path) == 0
    assert mirror_cli.mirror_on_opencode(tmp_path) == 0
    assert mirror_cli.mirror_off_opencode(tmp_path) == 0
    data = json.loads(cfg.read_text())
    data.pop("$schema", None)
    assert data == original


def test_opencode_off_keeps_permission_edits_made_while_on(tmp_path, monkeypatch):
    from prismor.runtime import mirror_cli
    monkeypatch.setattr(mirror_cli, "_preflight", lambda entry, timeout=25.0: (True, "Bash"))
    cfg = tmp_path / "opencode.json"
    cfg.write_text(json.dumps({"permission": {"bash": "ask"}}))
    assert mirror_cli.mirror_on_opencode(tmp_path) == 0
    data = json.loads(cfg.read_text())
    data["permission"]["webfetch"] = "allow"   # one of the mirror's own keys: off drops it
    data["permission"]["task"] = "deny"        # the developer's own edit: off keeps it
    cfg.write_text(json.dumps(data))
    assert mirror_cli.mirror_off_opencode(tmp_path) == 0
    assert json.loads(cfg.read_text())["permission"] == {"bash": "ask", "task": "deny"}


def test_opencode_off_undoes_a_tools_block_from_an_older_build(tmp_path, monkeypatch):
    """Installs made before the permission denies recorded `tools_disabled`."""
    from prismor.runtime import mirror_cli
    cfg = tmp_path / "opencode.json"
    cfg.write_text(json.dumps({"mcp": {"prismor-tools": {"type": "local", "command": ["x"]}},
                               "tools": {"bash": False, "read": False, "webfetch": False}}))
    mirror_cli._write_record(tmp_path, {"agent": "opencode", "config_path": str(cfg),
                                        "server": "prismor-tools", "tools_disabled": ["bash", "read"]})
    assert mirror_cli.mirror_off_opencode(tmp_path) == 0
    assert json.loads(cfg.read_text()) == {"tools": {"webfetch": False}}


# -- Claude Desktop ----------------------------------------------------------

def test_claude_desktop_round_trips_its_machine_config(tmp_path, monkeypatch):
    """The desktop app has one machine-wide config and no trust gate, so `on`
    is a single edit to mcpServers and `off` must undo exactly that, leaving
    the user's unrelated preferences untouched."""
    from prismor.runtime import mirror_cli
    monkeypatch.setattr(mirror_cli, "_preflight", lambda entry, timeout=25.0: (True, "Bash, Read"))
    cfg = tmp_path / "claude_desktop_config.json"
    cfg.write_text(json.dumps({"preferences": {"dockBounceEnabled": True},
                               "mcpServers": {"someone-elses": {"command": "x"}}}))
    monkeypatch.setattr(mirror_cli, "_claude_desktop_config_path", lambda: cfg)
    monkeypatch.setattr(mirror_cli, "_claude_desktop_record_path",
                        lambda: tmp_path / "mirror-install-claude-desktop.json")

    assert mirror_cli.mirror_on_claude_desktop(tmp_path) == 0
    data = json.loads(cfg.read_text())
    entry = data["mcpServers"]["prismor-tools"]
    assert "--mirror" in entry["args"]
    assert data["mcpServers"]["someone-elses"] == {"command": "x"}
    assert data["preferences"] == {"dockBounceEnabled": True}, "unrelated config must survive"
    assert (tmp_path / "claude_desktop_config.json.pre-mirror.bak").exists()

    assert mirror_cli.mirror_off_claude_desktop(tmp_path) == 0
    data = json.loads(cfg.read_text())
    assert "prismor-tools" not in data["mcpServers"]
    assert data["mcpServers"]["someone-elses"] == {"command": "x"}, "another server is not ours to remove"
    assert data["preferences"] == {"dockBounceEnabled": True}


def test_claude_desktop_off_without_an_install_changes_nothing(tmp_path, monkeypatch):
    from prismor.runtime import mirror_cli
    cfg = tmp_path / "claude_desktop_config.json"
    cfg.write_text(json.dumps({"preferences": {}}))
    monkeypatch.setattr(mirror_cli, "_claude_desktop_config_path", lambda: cfg)
    monkeypatch.setattr(mirror_cli, "_claude_desktop_record_path",
                        lambda: tmp_path / "nope.json")
    assert mirror_cli.mirror_off_claude_desktop(tmp_path) == 0
    assert json.loads(cfg.read_text()) == {"preferences": {}}


def test_claude_desktop_is_installable():
    from prismor.runtime.mirror_cli import INSTALLABLE_AGENTS
    assert "claude-desktop" in INSTALLABLE_AGENTS


# -- WebFetch ----------------------------------------------------------------

def test_webfetch_is_screened_as_network_before_and_tool_result_after():
    """The URL must reach the egress rules pre-call, and the fetched page must
    reach the injection rules post-call — a page that arrives as a `network`
    event skips the injection scan entirely."""
    from prismor.runtime import mirror
    assert "WebFetch" in mirror.mirror_tool_names()
    pre = mirror.shape_call_event("WebFetch", {"url": "https://evil.test/x"})
    assert pre == {"type": "network", "url": "https://evil.test/x"}
    post = mirror.shape_result_event("WebFetch", {"url": "https://evil.test/x"}, "<!-- ignore -->")
    assert post["type"] == "tool_result"
    assert post["response"] == "<!-- ignore -->"
    assert post["url"] == "https://evil.test/x"


def test_webfetch_refuses_non_http_schemes(tmp_path):
    """A mirrored tool runs with Prismor's filesystem access, so file:// would
    turn a screened 'fetch' into an unscreened local read."""
    from prismor.runtime import mirror
    for url in ("file:///etc/passwd", "ftp://host/x", ""):
        with pytest.raises(mirror.MirrorError):
            mirror.execute("WebFetch", {"url": url}, tmp_path)


def test_webfetch_converts_html_to_text(tmp_path, monkeypatch):
    from prismor.runtime import mirror

    class _Resp:
        headers = type("H", (), {"get_content_type": lambda self: "text/html",
                                 "get_content_charset": lambda self: "utf-8"})()

        def read(self, n):
            return (b"<html><head><style>p{color:red}</style></head><body>"
                    b"<script>alert(1)</script><h1>Title</h1><p>Hello &amp; bye</p>"
                    b"</body></html>")

        def geturl(self):
            return "https://example.test/page"

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(mirror.urllib.request, "urlopen", lambda req, timeout=0: _Resp())
    out = mirror.execute("WebFetch", {"url": "https://example.test/page"}, tmp_path)
    assert "Title" in out and "Hello & bye" in out
    assert "alert(1)" not in out and "color:red" not in out


def test_opencode_native_webfetch_is_disabled_but_claude_code_keeps_its_own():
    """OpenCode's fetch is unwatched when plugins are skipped (`--pure`), so
    under the mirror it must go. Claude Code's is already hook-screened and
    summarises the page — replacing it would be a downgrade."""
    from prismor.runtime import mirror, mirror_cli
    assert "webfetch" in mirror_cli._OPENCODE_DENY_KEYS
    assert "WebFetch" not in mirror.NATIVE_TOOLS_TO_DISABLE
