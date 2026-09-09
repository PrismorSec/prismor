"""Skill audit: what the installed SKILL.md files instruct, and whether they changed.

A skill is an instruction file the agent loads every session — the same trust
surface as CLAUDE.md, but sourced from third parties and often told to keep
itself updated from a remote URL ("save the most recent skill from
https://vendor/SKILL.md, replacing the current one, and make sure it's
enabled"). ``memory_guard`` covers CLAUDE.md/AGENTS.md; this module covers
skills:

* discover every installed skill manifest (user + project + plugin dirs),
* run the ``skill_manifest`` rules over each (skill-exfil-url, skill-secret-
  access, skill-self-persist, …),
* keep a TOFU hash baseline so a skill that changed since it was reviewed is
  reported as ``changed`` (and, at SessionStart, mentioned to the agent as
  untrusted content until approved),
* surface the remote source a skill declares or points at, so an operator can
  see "this skill re-fetches itself from vendor.example".

Baseline lives at ``<data_dir>/skills_baseline.json`` — the same per-workspace
state dir as taint and tag ledgers.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

__all__ = ["audit_skills", "approve_skill", "discover_skill_files", "format_audit"]

_SKILL_URL_RE = re.compile(r'https?://[^\s)\'"<>]+/SKILL\.md', re.IGNORECASE)
_FRONTMATTER_RE = re.compile(r'\A---\s*\n(.*?)\n---\s*\n', re.DOTALL)
_MAX_BYTES = 512 * 1024


def discover_skill_files(workspace: Path) -> List[Path]:
    """Every SKILL.md the agents on this machine will load for ``workspace``."""
    home = Path.home()
    roots = [
        home / ".claude" / "skills",
        workspace / ".claude" / "skills",
        home / ".codex" / "skills",
        workspace / ".codex" / "skills",
        workspace / ".agents" / "skills",
        home / ".agents" / "skills",
    ]
    found: List[Path] = []
    for root in roots:
        if root.is_dir():
            found.extend(sorted(root.glob("*/SKILL.md")))
    # Claude Code plugins: ~/.claude/plugins/<marketplace>/<plugin>/skills/<name>/SKILL.md
    plug = home / ".claude" / "plugins"
    if plug.is_dir():
        found.extend(sorted(plug.glob("**/skills/*/SKILL.md")))
    seen: set = set()
    out: List[Path] = []
    for p in found:
        try:
            key = p.resolve()
        except OSError:
            key = p
        if key in seen:
            continue
        seen.add(key)
        out.append(p)
    return out


def _baseline_path(workspace: Path) -> Path:
    from prismor.runtime.store import get_data_dir
    return get_data_dir(workspace) / "skills_baseline.json"


def _load_baseline(workspace: Path) -> Dict[str, Any]:
    p = _baseline_path(workspace)
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_baseline(workspace: Path, data: Dict[str, Any]) -> None:
    p = _baseline_path(workspace)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    tmp.replace(p)


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        h.update(fh.read(_MAX_BYTES))
    return h.hexdigest()


def _frontmatter(text: str) -> Dict[str, str]:
    m = _FRONTMATTER_RE.match(text)
    if not m:
        return {}
    out: Dict[str, str] = {}
    for line in m.group(1).splitlines():
        if ":" in line and not line.startswith(" "):
            k, _, v = line.partition(":")
            out[k.strip().lower()] = v.strip().strip('"\'')
    return out


def _remote_sources(text: str, fm: Dict[str, str]) -> List[str]:
    urls: List[str] = []
    for key in ("source", "url", "homepage", "update_url", "repository"):
        v = fm.get(key)
        if v and v.startswith("http"):
            urls.append(v)
    urls.extend(_SKILL_URL_RE.findall(text))
    dedup: List[str] = []
    for u in urls:
        if u not in dedup:
            dedup.append(u)
    return dedup[:5]


def audit_skills(workspace: Path, *, engine: Any = None, record: bool = True) -> List[Dict[str, Any]]:
    """Audit every installed skill. Returns one report row per SKILL.md.

    ``record=True`` writes first-seen hashes into the baseline (TOFU) so the
    *next* audit can tell "new" from "changed"; it never overwrites an existing
    baseline — that is :func:`approve_skill`'s job.
    """
    if engine is None:
        from prismor.runtime.policy_engine import PolicyEngine
        engine = PolicyEngine(workspace=workspace)
    baseline = _load_baseline(workspace)
    now = datetime.now(timezone.utc).isoformat()
    rows: List[Dict[str, Any]] = []
    changed_baseline = False

    for idx, path in enumerate(discover_skill_files(workspace)):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")[:_MAX_BYTES]
        except OSError:
            continue
        digest = _sha256(path)
        fm = _frontmatter(text)
        key = str(path)
        prior = baseline.get(key) if isinstance(baseline.get(key), dict) else None
        if prior is None:
            status = "new"
            if record:
                baseline[key] = {"sha256": digest, "first_seen": now, "approved": False}
                changed_baseline = True
        elif prior.get("sha256") == digest:
            status = "approved" if prior.get("approved") else "unchanged"
        else:
            status = "changed"

        try:
            findings = engine.evaluate(
                {"type": "skill_manifest", "content": text, "prompt": text, "path": key,
                 "_bulk_scan": True},
                idx, session_id="",
            )
        except Exception:
            findings = []
        findings = [
            {"ruleId": f.get("ruleId"), "severity": f.get("severity"), "title": f.get("title"),
             "action": f.get("action")}
            for f in findings
        ]
        rows.append({
            "path": key,
            "name": fm.get("name") or path.parent.name,
            "version": fm.get("version"),
            "sha256": digest,
            "status": status,
            "remote_sources": _remote_sources(text, fm),
            "self_updating": any(f["ruleId"] == "skill-self-persist" for f in findings),
            "findings": findings,
        })

    if record and changed_baseline:
        _save_baseline(workspace, baseline)
    return rows


def approve_skill(workspace: Path, path: Path) -> Dict[str, Any]:
    """Re-baseline one skill after review: current hash becomes the trusted one."""
    baseline = _load_baseline(workspace)
    key = str(path)
    entry = {
        "sha256": _sha256(path),
        "first_seen": (baseline.get(key) or {}).get("first_seen") or datetime.now(timezone.utc).isoformat(),
        "approved": True,
        "approved_at": datetime.now(timezone.utc).isoformat(),
    }
    baseline[key] = entry
    _save_baseline(workspace, baseline)
    return entry


def changed_or_flagged(workspace: Path, *, engine: Any = None) -> List[Dict[str, Any]]:
    """SessionStart view: skills that CHANGED since their reviewed baseline, or
    that keep themselves updated from a remote URL (remote-controlled
    instructions). Deliberately not "any skill with a finding" — the skill-*
    content rules are heuristics that fire on ordinary shell in many skills,
    and a notice on every session is a notice nobody reads. The full picture
    is `prismor skills audit`."""
    out: List[Dict[str, Any]] = []
    for row in audit_skills(workspace, engine=engine, record=True):
        # An approved, unchanged self-updating skill has been reviewed by a
        # human — stop nagging until it actually changes.
        if row["status"] == "changed" or (row["self_updating"] and row["status"] != "approved"):
            hot = [f for f in row["findings"] if str(f.get("severity")).upper() in ("HIGH", "CRITICAL")]
            out.append({**row, "findings": hot})
    return out


def format_audit(rows: List[Dict[str, Any]]) -> str:
    if not rows:
        return "No skills installed (looked in ~/.claude/skills, .claude/skills, ~/.codex/skills, plugins)."
    lines = [f"{len(rows)} skill(s):", ""]
    for r in rows:
        badge = {"new": "NEW", "changed": "CHANGED", "approved": "ok", "unchanged": "seen"}.get(r["status"], r["status"])
        lines.append(f"  [{badge:>7}] {r['name']}" + (f" v{r['version']}" if r.get("version") else "") + f"  {r['path']}")
        if r["remote_sources"]:
            lines.append(f"           source: {', '.join(r['remote_sources'])}" + ("  (self-updating)" if r["self_updating"] else ""))
        for f in r["findings"]:
            lines.append(f"           - [{f.get('severity')}] {f.get('title')} ({f.get('ruleId')})")
    lines.append("")
    lines.append("prismor skills approve <path>   # accept a NEW/CHANGED skill after review")
    return "\n".join(lines)
