"""`prismor aibom`: an AI bill of materials for this machine, as CycloneDX 1.6.

Everything here is already collected elsewhere; this only writes it down in a
form procurement and security tooling ingest:

* agents      - discover.discover_agents, with whether Prismor governs each
* models      - the models those agents actually called (token_usage, 30 days)
* MCP servers - discover.discover_mcp (risk, remote, behind the gateway?)
* plugins, skills, third-party hooks - the extension ledger, with SHA-256,
  origin, capabilities and drift (new / changed / unchanged / approved)
* instruction files - CLAUDE.md / AGENTS.md / ... that memory_guard baselines

It is meant to be shared, so what it leaves out is deliberate: no credentials
(not even names), no file contents, no prompts or commands, MCP URLs and
commands pass through discover's redaction, and paths are home-relative.
"""
from __future__ import annotations

import json
import os
import socket
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

MODEL_WINDOW_DAYS = 30
_COMPONENT_TYPE = {"plugin": "application", "hook": "application", "skill": "file"}


def _rel(path: Any) -> str:
    p, home = str(path or ""), str(Path.home())
    return "~" + p[len(home):] if p.startswith(home) else p


def _url(raw: str) -> str:
    """discover's redaction, then percent-encoded: `<redacted>` is not a valid IRI."""
    from urllib.parse import quote
    from prismor.runtime.discover import redact_url
    return quote(redact_url(raw), safe=":/?#[]@!$&'()*+,;=%~")


def _props(**kv: Any) -> List[Dict[str, str]]:
    out = []
    for k, v in kv.items():
        if v is None or v == "" or v == []:
            continue
        if isinstance(v, (list, tuple)):
            v = ",".join(str(x) for x in v)
        text = str(v).lower() if isinstance(v, bool) else str(v).replace(str(Path.home()), "~")
        out.append({"name": f"prismor:{k}", "value": text})
    return out


def _models(workspace: Path) -> List[Dict[str, Any]]:
    from prismor.runtime import store
    from prismor.runtime.token_usage import _provider
    conn = store._connect_ro(store.prismor_home() / "prismor.db")
    if conn is None:
        return []
    since = (datetime.now(timezone.utc) - timedelta(days=MODEL_WINDOW_DAYS)).isoformat()
    try:
        rows = conn.execute(
            "SELECT model, COUNT(DISTINCT session_id) AS sessions, MAX(ts) AS last_seen"
            "  FROM token_usage WHERE ts >= ? AND model IS NOT NULL AND model != ''"
            " GROUP BY model ORDER BY sessions DESC", (since,)).fetchall()
    except Exception:
        return []
    finally:
        conn.close()
    return [{"model": r["model"], "provider": _provider(r["model"]),
             "sessions": r["sessions"], "last_seen": r["last_seen"]} for r in rows]


def _instruction_files(workspace: Path) -> List[Dict[str, Any]]:
    try:
        from prismor.runtime.memory_guard import load_trust_store
        files = load_trust_store(workspace).get("files") or {}
    except Exception:
        return []
    out = []
    for path, rec in files.items():
        rec = rec if isinstance(rec, dict) else {}
        out.append({"path": path, "sha256": rec.get("hash") or rec.get("sha256"),
                    "signed": bool(rec.get("signature"))})
    return out


def collect(workspace: Path) -> Dict[str, Any]:
    """Gather the inventory (plain dicts; no I/O beyond reading local state)."""
    from prismor.runtime import discover, extensions
    agents = discover.discover_agents(workspace)
    mcp = discover.discover_mcp(workspace)
    try:
        ext = extensions.sync(workspace, record=False)
    except Exception:
        ext = extensions.discover_extensions(workspace)
    return {
        "agents": [vars(a) for a in agents],
        "mcp": [vars(m) for m in mcp],
        "extensions": ext,
        "models": _models(workspace),
        "instructions": _instruction_files(workspace),
    }


def to_cyclonedx(inv: Dict[str, Any], *, now: Optional[datetime] = None) -> Dict[str, Any]:
    from prismor.runtime import __version__
    from prismor.runtime.discover import redact_command
    now = now or datetime.now(timezone.utc)
    components: List[Dict[str, Any]] = []
    deps: Dict[str, List[str]] = {}

    for a in inv["agents"]:
        governed = bool(a.get("managed"))
        components.append({
            "type": "application", "bom-ref": f"agent:{a['id']}", "name": a.get("name") or a["id"],
            "properties": _props(kind="agent", agent_id=a["id"], governed=governed,
                                 hook_mode=a.get("mode"), coverable=a.get("coverable"),
                                 shadow=not governed and a.get("coverable", True)),
        })
    agent_refs = {a["id"]: f"agent:{a['id']}" for a in inv["agents"]}

    for m in inv["models"]:
        components.append({
            "type": "machine-learning-model", "bom-ref": f"model:{m['model']}", "name": m["model"],
            "supplier": {"name": m["provider"]} if m["provider"] != "unknown" else None,
            "properties": _props(kind="model", sessions_30d=m["sessions"], last_seen=m["last_seen"]),
        })

    ext_by_id = {r["id"]: r for r in inv["extensions"]}
    for s in inv["mcp"]:
        ref = f"mcp:{_rel(s.get('source'))}#{s['name']}"
        led = ext_by_id.get(f"mcp:{s.get('source')}#{s['name']}") or {}
        comp: Dict[str, Any] = {
            "type": "application", "bom-ref": ref, "name": s["name"],
            "properties": _props(
                kind="mcp_server", transport=s.get("transport"), remote=s.get("remote"),
                governed=bool(s.get("managed")), gateway=s.get("is_gateway"), risk=s.get("risk"),
                config=_rel(s.get("source")), command=" ".join(redact_command(s.get("command") or [])),
                status=led.get("status"), findings=len(s.get("findings") or []) or None),
        }
        if s.get("url"):
            comp["externalReferences"] = [{"type": "distribution", "url": _url(s["url"])}]
        if led.get("sha256"):
            comp["hashes"] = [{"alg": "SHA-256", "content": led["sha256"]}]
        components.append(comp)
        if s.get("agent") in agent_refs:
            deps.setdefault(agent_refs[s["agent"]], []).append(ref)

    for r in inv["extensions"]:
        if r.get("kind") == "mcp":
            continue  # described above, from discover's richer record
        ref = f"{r['kind']}:{_rel(r['id'].split(':', 1)[-1])}"
        comp = {
            "type": _COMPONENT_TYPE.get(r["kind"], "application"), "bom-ref": ref, "name": r.get("name") or r["id"],
            "properties": _props(kind=r["kind"], path=_rel(r.get("path")), status=r.get("status"),
                                 installed_by=r["installed_by"] if isinstance(r.get("installed_by"), str) else
                                 ("agent" if r.get("installed_by") else None),
                                 capabilities=r.get("capabilities"), hosts=r.get("hosts"),
                                 agents=r.get("agents")),
        }
        if r.get("version"):
            comp["version"] = str(r["version"])
        if r.get("sha256"):
            comp["hashes"] = [{"alg": "SHA-256", "content": r["sha256"]}]
        origin = str(r.get("origin") or "")
        if origin.startswith(("http://", "https://", "git@", "ssh://")):
            comp["externalReferences"] = [{"type": "vcs" if ".git" in origin or "github" in origin
                                           else "distribution", "url": _url(origin)}]
        components.append(comp)
        for agent in r.get("agents") or []:
            if agent in agent_refs:
                deps.setdefault(agent_refs[agent], []).append(ref)

    for f in inv["instructions"]:
        comp = {"type": "file", "bom-ref": f"instructions:{_rel(f['path'])}", "name": Path(f["path"]).name,
                "properties": _props(kind="instructions", path=_rel(f["path"]), signed=f["signed"])}
        if f.get("sha256"):
            comp["hashes"] = [{"alg": "SHA-256", "content": str(f["sha256"]).removeprefix("sha256:")}]
        components.append(comp)

    for c in components:
        if c.get("supplier") is None:
            c.pop("supplier", None)
    host = socket.gethostname()
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
        "metadata": {
            "timestamp": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": {"components": [{"type": "application", "name": "prismor", "version": __version__}]},
            "component": {"type": "device", "bom-ref": "device", "name": host},
            "properties": _props(kind="aibom", model_window_days=MODEL_WINDOW_DAYS),
        },
        "components": components,
        "dependencies": [{"ref": k, "dependsOn": sorted(set(v))} for k, v in deps.items()],
    }


def _prop(c: Dict[str, Any], name: str) -> str:
    return next((p["value"] for p in c.get("properties", []) if p["name"] == f"prismor:{name}"), "")


def to_markdown(bom: Dict[str, Any]) -> str:
    comps = bom["components"]
    by_kind: Dict[str, List[Dict[str, Any]]] = {}
    for c in comps:
        by_kind.setdefault(_prop(c, "kind"), []).append(c)
    drift = [c for c in comps if _prop(c, "status") in ("new", "changed")]
    ungoverned = [c for c in by_kind.get("agent", []) if _prop(c, "governed") == "false"]
    shadow = [c for c in ungoverned if _prop(c, "coverable") != "false"]
    unhookable = [c for c in ungoverned if _prop(c, "coverable") == "false"]
    lines = [
        f"# AI bill of materials - {bom['metadata']['component']['name']}",
        "",
        f"Generated {bom['metadata']['timestamp']} by prismor {bom['metadata']['tools']['components'][0]['version']}"
        f" (CycloneDX {bom['specVersion']}: `prismor aibom`).",
        "",
        "| Layer | Count |", "| --- | --- |",
    ]
    titles = [("agent", "Agents"), ("model", f"Models (last {MODEL_WINDOW_DAYS} days)"),
              ("mcp_server", "MCP servers"), ("plugin", "Plugins"), ("skill", "Skills"),
              ("hook", "Third-party hooks"), ("instructions", "Instruction files")]
    lines += [f"| {t} | {len(by_kind.get(k, []))} |" for k, t in titles]
    lines += ["", f"**Not governed by Prismor:** {len(ungoverned)} agent(s)"
              + (f" - can be hooked: {', '.join(c['name'] for c in shadow)}" if shadow else "")
              + (f"; no Prismor hook exists: {', '.join(c['name'] for c in unhookable)}" if unhookable else ""),
              f"**New or changed since last review:** {len(drift)}", ""]
    cols = {
        "agent": ("Governed", "governed"), "model": ("Sessions", "sessions_30d"),
        "mcp_server": ("Risk", "risk"), "plugin": ("Status", "status"), "skill": ("Status", "status"),
        "hook": ("Status", "status"), "instructions": ("Signed", "signed"),
    }
    for kind, title in titles:
        rows = by_kind.get(kind)
        if not rows:
            continue
        head, key = cols[kind]
        lines += [f"## {title}", "", f"| Name | {head} | SHA-256 |", "| --- | --- | --- |"]
        for c in sorted(rows, key=lambda c: c["name"].lower()):
            sha = (c.get("hashes") or [{}])[0].get("content", "")[:12]
            name = c["name"].replace("|", "\\|")
            lines.append(f"| {name} | {_prop(c, key) or '-'} | {sha or '-'} |")
        lines.append("")
    return "\n".join(lines)


def run(workspace: Path, *, fmt: str = "cyclonedx", output: Optional[str] = None) -> int:
    bom = to_cyclonedx(collect(workspace))
    text = to_markdown(bom) if fmt == "markdown" else json.dumps(bom, indent=2)
    if output:
        Path(output).write_text(text + "\n", encoding="utf-8")
        n = len(bom["components"])
        print(f"Wrote {n} components to {output}")
    else:
        print(text)
    return 0
