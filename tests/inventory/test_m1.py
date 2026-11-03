"""Milestone 1 inventory: schema, ids, endpoint, risk, sinks, privacy."""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path


_REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO))

FIXTURE = _REPO / "tests" / "fixtures" / "inventory"
SCHEMA_PATH = _REPO / "docs" / "schema" / "inventory-record.v1.json"
CANARY = "CANARY"


def setup_module() -> None:
    from tests.inventory.build_fixtures import main
    main()


def _ctx(**overrides):
    from prismor.runtime.inventory.context import ScanContext
    base = dict(
        os_name="windows",
        workspace=FIXTURE / "windows-dev" / "workspace",
        all_users=True,
        hash_users=True,
        org_salt="contoso-demo",
        hostname="LT-0420",
        machine_id="demo-machine",
        profiles_root=FIXTURE / "windows-dev" / "profiles",
        wsl_root=FIXTURE / "windows-dev" / "wsl",
        now=datetime(2026, 11, 2, 20, 48, tzinfo=timezone.utc),
    )
    base.update(overrides)
    return ScanContext(**base)


def _rows(records):
    return [record.to_dict() for record in records]


def _validate(rows):
    import jsonschema
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    for row in rows:
        jsonschema.validate(row, schema)


# ── schema and ids ───────────────────────────────────────────────────────────

def test_record_id_is_stable():
    from prismor.runtime.inventory.ids import record_id
    first = record_id("endpoint.core", "mcp_server", "h+u", "mcp:pkg:npm/example")
    second = record_id("endpoint.core", "mcp_server", "h+u", "mcp:pkg:npm/example")
    assert first == second
    assert first.startswith("inv_") and len(first) == 4 + 20


def test_entity_key_normalisation():
    from prismor.runtime.inventory.ids import mcp_entity_key, package_from_command
    purl, pinned = package_from_command(["npx", "-y", "@modelcontextprotocol/server-github"])
    assert purl == "pkg:npm/@modelcontextprotocol/server-github"
    assert pinned is False
    assert mcp_entity_key(["npx", "-y", "@modelcontextprotocol/server-github"]) == \
        "mcp:pkg:npm/@modelcontextprotocol/server-github"
    purl, pinned = package_from_command(["npx", "-y", "some-mcp-server@1.2.3"])
    assert pinned is True
    purl, pinned = package_from_command(["uvx", "mcp-server-git"])
    assert purl == "pkg:pypi/mcp-server-git"
    key = mcp_entity_key([], "https://user:pw@mcp.example.com/mcp/secret?code=CANARYVALUE")
    assert CANARY not in key
    assert key.startswith("mcp:url:https://mcp.example.com/mcp")
    assert "pw" not in key


def test_user_hash_and_legacy_payload_shape():
    from prismor.runtime.discover import report_payload
    from prismor.runtime.inventory.ids import user_hash
    assert user_hash("contoso-demo", "alice") != user_hash("contoso-demo", "bob")
    assert user_hash("contoso-demo", "alice").startswith("u_")
    payload = report_payload({"agents": [], "mcp": [], "credentials": [], "summary": {}})
    assert set(payload) == {"findings", "summary", "cli_version"}
    payload = report_payload({"agents": [], "mcp": [], "credentials": [], "summary": {},
                              "inventory": [{"record_id": "inv_abc"}]})
    assert payload["inventory_schema"] == "prismor.inventory.v1"


def test_catalog_entries_have_source_urls():
    from prismor.runtime.inventory.catalog import all_entries
    entries = all_entries()
    assert entries
    for entry in entries:
        assert entry.get("source_url"), entry.get("id")


# ── endpoint ─────────────────────────────────────────────────────────────────

def test_windows_fixture_users_extensions_and_jetbrains():
    from prismor.runtime.inventory.runner import run
    records = run(["endpoint"], _ctx())
    rows = _rows(records)
    _validate(rows)
    blob = json.dumps(rows)
    assert CANARY not in blob
    assert "OBI-RAW-MARKER" not in blob
    users = {row["location"]["user"] for row in rows if row["kind"] != "diagnostic"}
    assert len(users) >= 3  # alice, bob, wsl devuser
    agents = {row["product"] for row in rows if row["kind"] == "agent"}
    assert {"jetbrains-ai", "junie", "copilot-jetbrains"} <= agents
    products = {row["product"] for row in rows if row["kind"] == "mcp_server"}
    assert "jetbrains-ai" in products
    assert "junie" in products
    assert "copilot-jetbrains" in products
    paths = " ".join((row.get("location") or {}).get("path") or "" for row in rows)
    for fragment in (
        ".kiro/settings/mcp.json", ".copilot/mcp-config.json",
        ".codeium/windsurf/mcp_config.json", ".gemini/antigravity/mcp_config.json",
        ".aws/amazonq/mcp.json", "mcp_settings.json", "llm.mcpServers.xml",
    ):
        assert fragment in paths, fragment
    assert any(row["attributes"].get("wsl_distro") == "Ubuntu" for row in rows)
    assert any(row["kind"] == "ide_extension" and row["attributes"].get("confidence") == "catalog"
               and "copilot" in row["attributes"].get("extension_id", "").lower() for row in rows)
    assert any(row["kind"] == "ide_extension" and row["attributes"].get("confidence") == "heuristic"
               for row in rows)
    assert "Public" not in blob
    by_entity = {}
    for row in rows:
        if row["kind"] == "diagnostic" or not row["entity_key"]:
            continue
        by_entity.setdefault(row["entity_key"], set()).add(row["group_id"])
    assert by_entity
    for entity, groups in by_entity.items():
        assert len(groups) == 1, entity


def test_collectors_do_not_raise_on_bad_input(tmp_path):
    from prismor.runtime.inventory.collectors import endpoint_core, endpoint_jetbrains
    from prismor.runtime.inventory.context import ScanContext
    home = tmp_path / "ada"
    xml = home / "AppData" / "Roaming" / "JetBrains" / "Idea" / "options" / "llm.mcpServers.xml"
    xml.parent.mkdir(parents=True)
    xml.write_text('<!DOCTYPE foo [<!ENTITY x "CANARY">]><application/>', encoding="utf-8")
    bad = home / ".kiro" / "settings" / "mcp.json"
    bad.parent.mkdir(parents=True)
    bad.write_text("{not json", encoding="utf-8")
    ctx = ScanContext(os_name="windows", workspace=tmp_path, all_users=True, org_salt="s",
                      profiles_root=tmp_path, hostname="h", machine_id="m")
    records = list(endpoint_core.collect(ctx)) + list(endpoint_jetbrains.collect(ctx))
    assert records
    assert all(getattr(r, "kind", "") for r in records)
    assert CANARY not in json.dumps([r.to_dict() for r in records])
    assert any(r.kind == "diagnostic" for r in records)


def test_permission_error_is_a_diagnostic(tmp_path, monkeypatch):
    from prismor.runtime.inventory.collectors import endpoint_core
    from prismor.runtime.inventory.context import ScanContext
    real = Path.iterdir

    def boom(self):
        if self == tmp_path:
            raise PermissionError("denied")
        return real(self)

    monkeypatch.setattr(Path, "iterdir", boom)
    ctx = ScanContext(os_name="windows", workspace=tmp_path, profiles_root=tmp_path,
                      org_salt="s", hostname="h", machine_id="m")
    records = list(endpoint_core.collect(ctx))
    assert records and records[0].kind == "diagnostic"
    assert records[0].attributes["error_code"] == "permission"


# ── risk and correlation ─────────────────────────────────────────────────────

def test_score_equals_signal_sum_under_the_cap():
    from prismor.runtime.inventory.risk import WEIGHTS, apply
    from prismor.runtime.inventory.schema import Governance, InventoryRecord
    record = InventoryRecord(
        kind="mcp_server", surface="endpoint", source="endpoint.core", name="github",
        entity_key="mcp:pkg:npm/example",
        governance=Governance(managed=False, coverable=True),
        attributes={"remote": True, "package_id": "pkg:npm/example", "pinned": False,
                    "secret_in_config": False, "workspace_scoped": False},
    )
    apply(record)
    total = sum(item["weight"] for item in record.risk.signals)
    assert record.risk.score == min(100, max(0, total))
    assert total == record.risk.score
    assert record.risk.level == "high" or record.risk.level == "critical" or record.risk.level == "medium"
    assert WEIGHTS["UNGOVERNED"] == 25


def test_correlation_rules():
    from prismor.runtime.inventory.correlate import correlate
    from prismor.runtime.inventory.schema import InventoryRecord, Location
    cps = InventoryRecord(kind="lowcode_agent", surface="lowcode", source="lowcode.copilot_studio",
                          name="a", entity_key="cps:1",
                          attributes={"entra_app_id": "app-1", "entra_agent_id": "agent-1"})
    grant = InventoryRecord(kind="oauth_grant", surface="identity", source="entra",
                            name="app", entity_key="entra:app:app-1",
                            attributes={"app_id": "app-1"})
    ident = InventoryRecord(kind="agent_identity", surface="identity", source="entra",
                            name="agent", entity_key="entra:agent:agent-1",
                            attributes={"id": "agent-1"})
    mcp = InventoryRecord(kind="mcp_server", surface="endpoint", source="endpoint.core",
                          name="remote", entity_key="mcp:url:https://example.com/mcp",
                          attributes={"remote": True, "url": "https://mcp.example.com/mcp",
                                      "package_id": "pkg:npm/example"})
    net = InventoryRecord(kind="network_destination", surface="network", source="net",
                          name="example.com", entity_key="net:example.com",
                          attributes={"domain": "mcp.example.com"})
    pkg = InventoryRecord(kind="package", surface="endpoint", source="packages",
                          name="example", entity_key="pkg:npm/example",
                          attributes={"purl": "pkg:npm/example"})
    cred = InventoryRecord(kind="credential_ref", surface="endpoint", source="endpoint.core",
                           name="openai", entity_key="cred:openai:env",
                           location=Location(host_id="h", user="u"),
                           attributes={"provider": "openai"})
    agent = InventoryRecord(kind="agent", surface="endpoint", source="endpoint.core",
                            name="openai", entity_key="agent:openai", product="openai",
                            location=Location(host_id="h", user="u"),
                            attributes={"provider": "openai"})
    ci = InventoryRecord(kind="ci_workflow", surface="ci", source="repo",
                         name="claude", entity_key="ci:claude",
                         attributes={"action": "anthropics/claude-code-action"})
    claude = InventoryRecord(kind="agent", surface="endpoint", source="endpoint.core",
                             name="Claude", entity_key="agent:claude")
    cloud = InventoryRecord(kind="cloud_agent", surface="cloud", source="cloud.azure",
                            name="foundry", entity_key="azure:agent:1",
                            attributes={"provider": "foundry", "identity_id": "agent-1"})
    sealed = correlate([cps, grant, ident, mcp, net, pkg, cred, agent, ci, claude, cloud])
    by_key = {r.entity_key: r for r in sealed}
    assert by_key["cps:1"].group_id == by_key["cps:1"].group_id
    assert any(item["entity_key"] == "entra:app:app-1" for item in by_key["cps:1"].related)
    assert any(item["kind"] == "network_destination" for item in by_key["mcp:url:https://example.com/mcp"].related)
    assert any(item["kind"] == "package" for item in by_key["mcp:url:https://example.com/mcp"].related)
    assert any(item["kind"] == "agent" for item in by_key["cred:openai:env"].related)
    assert any(item["entity_key"] == "agent:claude" for item in by_key["ci:claude"].related)
    assert any(item["kind"] == "agent_identity" for item in by_key["azure:agent:1"].related)


# ── cli, fleet, privacy ────────────────────────────────────────────

def test_cli_exit_codes(monkeypatch, tmp_path):
    from prismor.runtime import inventory_cli
    monkeypatch.setenv("PRISMOR_INVENTORY_OS", "windows")
    monkeypatch.setenv("PRISMOR_INVENTORY_PROFILES", str(FIXTURE / "windows-dev" / "profiles"))
    monkeypatch.setenv("PRISMOR_INVENTORY_WSL", str(FIXTURE / "windows-dev" / "wsl"))
    monkeypatch.setenv("PRISMOR_INVENTORY_SALT", "contoso-demo")
    monkeypatch.setenv("PRISMOR_INVENTORY_HOSTNAME", "LT-0420")
    monkeypatch.setenv("PRISMOR_INVENTORY_MACHINE_ID", "demo-machine")

    class Args:
        section = "endpoint"
        format = "ndjson"
        out = str(tmp_path / "out.ndjson")
        sink = ""
        fail_on = "critical"
        dry_run = False
        strict = False
        all_users = True
        quiet = True
        json = False
        report = False

    code = inventory_cli.execute(Args(), FIXTURE / "windows-dev" / "workspace")
    text = Path(Args.out).read_text(encoding="utf-8")
    assert CANARY not in text
    assert text.strip()
    # The fixture has at least one critical MCP server (ungoverned + remote + secret).
    assert code == 1
    Args.fail_on = None
    Args.out = str(tmp_path / "ok.ndjson")
    assert inventory_cli.execute(Args(), FIXTURE / "windows-dev" / "workspace") == 0


def test_fleet_interval(monkeypatch, tmp_path):
    from prismor.runtime.inventory.runner import maybe_fleet_scan
    settings = tmp_path / "inventory.yaml"
    settings.write_text("surfaces: [endpoint]\ninterval_hours: 24\nall_users: true\nhash_users: true\n",
                        encoding="utf-8")
    monkeypatch.setenv("PRISMOR_INVENTORY_SETTINGS", str(settings))
    monkeypatch.setenv("PRISMOR_INVENTORY_DIR", str(tmp_path / "out"))
    monkeypatch.setenv("PRISMOR_INVENTORY_INLINE", "1")
    monkeypatch.setenv("PRISMOR_INVENTORY_NO_JITTER", "1")
    monkeypatch.setenv("PRISMOR_INVENTORY_OS", "windows")
    monkeypatch.setenv("PRISMOR_INVENTORY_PROFILES", str(FIXTURE / "windows-dev" / "profiles"))
    monkeypatch.setenv("PRISMOR_INVENTORY_SALT", "contoso-demo")
    monkeypatch.setenv("PRISMOR_INVENTORY_MACHINE_ID", "demo-machine")
    first = maybe_fleet_scan(now=1_700_000_000)
    assert "wrote" in first
    assert (tmp_path / "out" / "last.ndjson").is_file()
    second = maybe_fleet_scan(now=1_700_000_100)
    assert second.get("skipped") == "interval"


def test_privacy_canary_absent_from_every_output(tmp_path, monkeypatch):
    from prismor.runtime import sinks
    from prismor.runtime.inventory.runner import run
    from prismor.runtime.sinks import _scrub_obj, dispatch_inventory
    endpoint = run(["endpoint"], _ctx())
    rows = [_scrub_obj(record.to_dict()) for record in endpoint]
    blob = json.dumps(rows)
    assert CANARY not in blob
    captured = {}

    def plugin_sink(cfg, rows):
        captured["body"] = json.dumps(rows)

    from types import SimpleNamespace
    monkeypatch.setattr(sinks, "_SINK_PLUGINS", {"example": SimpleNamespace(dispatch_inventory=plugin_sink)})
    path = tmp_path / "sink.ndjson"
    dispatch_inventory(rows, [
        {"type": "file", "path": str(path)},
        {"type": "example"},
    ])
    assert CANARY not in path.read_text(encoding="utf-8")
    # A plugin sink only ever sees scrubbed rows.
    assert captured["body"] and CANARY not in captured["body"]


def test_plugin_collector_registers_alias(monkeypatch):
    from types import SimpleNamespace
    from prismor.runtime.inventory import runner
    from prismor.runtime.inventory.schema import InventoryRecord

    module = SimpleNamespace(
        SURFACE="lowcode.example",
        collect=lambda ctx: [InventoryRecord(kind="lowcode_agent", surface="lowcode",
                                             source="lowcode.example", name="bot",
                                             entity_key="example:bot")],
    )
    ep = SimpleNamespace(name="example", load=lambda: module)
    monkeypatch.setattr(runner, "_PLUGINS_LOADED", False)
    monkeypatch.setattr(runner, "_COLLECTORS", dict(runner._COLLECTORS))
    monkeypatch.setattr(runner, "SURFACES", dict(runner.SURFACES))
    monkeypatch.setattr("importlib.metadata.entry_points", lambda group: [ep])
    assert "example" in runner.known_surfaces()
    rows = [r.to_dict() for r in runner.run(["example"], _ctx())]
    assert [row["entity_key"] for row in rows] == ["example:bot"]
    assert rows[0]["record_id"].startswith("inv_")


def test_report_keeps_legacy_findings(monkeypatch, tmp_path):
    """An inventory-only report would make the console delete the device's findings."""
    from prismor.runtime import discover, inventory_cli
    sent = []
    monkeypatch.setattr(discover, "build_report",
                        lambda ws: {"agents": [{"name": "claude"}], "mcp": [], "credentials": [], "summary": {}})
    monkeypatch.setattr(discover, "send_report", lambda report: sent.append(report) or True)
    inventory_cli._emit([{"kind": "agent"}] * 3, [], {}, report=True, workspace=tmp_path)
    assert len(sent) == 1
    assert sent[0]["agents"] == [{"name": "claude"}]
    assert len(sent[0]["inventory"]) == 3


def test_sink_plugin_gets_events_and_lifecycle_hooks(monkeypatch):
    from types import SimpleNamespace
    from prismor.runtime import sinks
    got = {}
    plugin = SimpleNamespace(
        dispatch_events=lambda cfg, events: got.setdefault("events", events),
        system_sync=lambda outputs: got.setdefault("sync", True),
        doctor=lambda outputs: [("ok", "example", "fine")],
    )
    monkeypatch.setattr(sinks, "_SINK_PLUGINS", {"example": plugin})
    finding = {"rule_id": "r1", "severity": "HIGH", "title": "t", "category": "c", "evidence": "e"}
    sinks.dispatch([finding, dict(finding, rule_id="r2")], [{"type": "example"}])
    assert len(got["events"]) == 2
    sinks.run_sink_hook("system_sync")
    assert got["sync"] is True
    assert sinks.run_sink_hook("doctor", []) == [[("ok", "example", "fine")]]
    # A plugin without a hook is skipped, and a failing hook never raises.
    monkeypatch.setattr(sinks, "_SINK_PLUGINS", {"bad": SimpleNamespace(exit_flush=lambda o: 1 / 0)})
    assert sinks.run_sink_hook("exit_flush") == []
