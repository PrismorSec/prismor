"""Prismor governance modes — named policy templates that compile to policy.yaml.

A mode is not a new enforcement path. It is a template that writes the
primitives the engine already reads, so `PolicyEngine.evaluate` never learns
that modes exist:

    modes.yaml  ──compile──▶  .prismor/policy.yaml   settings.default_mode,
                                                     .egress, .tool_tags,
                                                     .sandbox, rule overlays
                          ──▶  .prismor/agents.yaml   global_deny_tools,
                                                     global_ask_tools

That indirection is the point. Six policy axes hand-assembled per project is
how a security tool ends up configured wrong; four named postures with an
honest residual-risk statement each is something a developer can actually
choose between. `prismor mode explain <id>` prints the trade rather than
selling the mode — a mode that claims no downside is a mode nobody should
trust.

Two merge hazards this module exists to get right:

* ``settings.update()`` in ``_apply_override`` is a SHALLOW replace, so a mode
  that writes ``egress`` wholesale drops the default cloud-metadata deny list
  unless it carries it forward. modes.yaml anchors those entries into every
  mode that enables egress; ``_check_metadata_deny`` fails the compile if a
  hand-edit ever loses them.
* ``settings.mode`` is already an alias for ``default_mode``
  (policy_engine._load), so mode provenance is stamped as ``settings.mode_id``.
  Writing it as ``mode`` would set the global fallback to a mode name and
  resolve every rule to a nonsense posture.
"""
from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_MODES_PATH = Path(__file__).parent / "modes.yaml"

# Cloud-metadata hosts that must survive a mode's egress block. Compared by
# host only — the reason strings are prose and may be reworded.
_REQUIRED_DENY_HOSTS = frozenset({
    "169.254.169.254", "metadata.google.internal", "169.254.0.0/16",
})


class ModeError(ValueError):
    """A mode id that does not exist, or a mode that fails its own invariants."""


# ── Loading ─────────────────────────────────────────────────────────────────

def load_modes() -> Dict[str, Dict[str, Any]]:
    """Every mode defined in modes.yaml, keyed by id and in file order."""
    import yaml
    raw = yaml.safe_load(_MODES_PATH.read_text(encoding="utf-8")) or {}
    modes = raw.get("modes") or {}
    if not isinstance(modes, dict):
        raise ModeError("modes.yaml: `modes` must be a mapping of id -> mode")
    return {str(k): dict(v or {}) for k, v in modes.items()}


def get_mode(mode_id: str) -> Dict[str, Any]:
    """One mode by id, with its id folded in. Raises ModeError if unknown."""
    modes = load_modes()
    mode = modes.get(mode_id)
    if mode is None:
        raise ModeError(
            f"unknown mode '{mode_id}' — available: {', '.join(modes)}"
        )
    return {**mode, "id": mode_id}


# ── Rule selection ──────────────────────────────────────────────────────────

def _floor_rule_ids() -> Tuple[List[str], int]:
    """(safety-floor rule ids, total rule count) from the default policy.

    The floor is what `prismor setup` badges "recommended": core rule ids plus
    every rule whose category is a core block category. Self-protection rules
    are excluded because they always enforce regardless of selection — listing
    them would imply a mode could switch them off.
    """
    import yaml
    from prismor.runtime.policy_engine import (
        _DEFAULT_POLICY_PATH, _NON_OVERRIDABLE_RULE_IDS,
        _CORE_BLOCK_CATEGORIES, _SELF_PROTECTION_RULE_IDS,
    )
    data = yaml.safe_load(_DEFAULT_POLICY_PATH.read_text(encoding="utf-8")) or {}
    rules = data.get("rules") or []
    floor = [
        r["id"] for r in rules
        if r.get("id") not in _SELF_PROTECTION_RULE_IDS
        and (r.get("id") in _NON_OVERRIDABLE_RULE_IDS
             or r.get("category") in _CORE_BLOCK_CATEGORIES)
    ]
    return floor, len(rules)


def enforcing_rule_ids(mode: Dict[str, Any]) -> List[str]:
    """Rule ids this mode marks `mode: enforce`, in default-policy order.

    Empty for both `none` (nothing blocks) and `all` (default_mode carries it,
    so no per-rule overlay is needed) — see `coverage` for the honest count.
    """
    selector = str(mode.get("enforce_rules") or "none")
    floor, _ = _floor_rule_ids()
    if selector == "all":
        return []
    picked = list(floor) if selector == "floor" else []
    for rid in mode.get("enforce_extra") or []:
        if rid not in picked:
            picked.append(rid)
    return picked


def coverage(mode: Dict[str, Any]) -> Tuple[int, int]:
    """(rules that block under this mode, total rules) — computed, not asserted.

    Derived from the real ruleset so the number in `mode explain` tracks the
    policy as rules are added, instead of drifting into a marketing figure.
    """
    _, total = _floor_rule_ids()
    selector = str(mode.get("enforce_rules") or "none")
    if selector == "all":
        return total, total
    return len(enforcing_rule_ids(mode)), total


# ── Compilation ─────────────────────────────────────────────────────────────

def _check_metadata_deny(mode: Dict[str, Any]) -> None:
    """Refuse to compile an egress-enabled mode that lost the metadata denies.

    settings.update() replaces `egress` wholesale, so an edit that drops these
    from modes.yaml would silently reopen the cloud-metadata SSRF pivot on
    every workspace running that mode. Fail loudly at compile instead.
    """
    egress = mode.get("egress") or {}
    if not egress.get("enabled"):
        return
    hosts = {
        (e.get("host") if isinstance(e, dict) else e)
        for e in (egress.get("deny") or [])
    }
    missing = _REQUIRED_DENY_HOSTS - hosts
    if missing:
        raise ModeError(
            f"mode '{mode.get('id')}' enables egress but its deny list is missing "
            f"{sorted(missing)} — settings.egress is replaced wholesale, so these "
            f"must be carried forward or cloud metadata becomes reachable"
        )


def _command_rules(mode: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Compile `commands.deny` / `commands.ask` into generated policy rules.

    One rule per action rather than one per pattern: the engine reports the
    first matching pattern as evidence either way, and a single rule keeps the
    generated policy readable when someone opens it to see what a mode did.
    """
    commands = mode.get("commands") or {}
    out: List[Dict[str, Any]] = []
    for action, severity, verb in (
        ("deny", "HIGH", "block"),
        ("ask", "MEDIUM", "step_up"),
    ):
        patterns = commands.get(action) or []
        if not patterns:
            continue
        out.append({
            "id": f"mode-{mode['id']}-{action}-commands",
            "severity": severity,
            "category": "mode_command_control",
            "title": f"Command {'denied' if action == 'deny' else 'gated'} by mode {mode['id']}",
            "event_types": ["shell"],
            "fields": ["command"],
            "patterns": list(patterns),
            "action": verb,
            "mode": "enforce",
        })
    return out


def compile_mode(mode: Dict[str, Any]) -> str:
    """Render a mode as the text of a complete `.prismor/policy.yaml`.

    Pure: takes a mode, returns YAML text, touches no disk. That is what lets
    `mode apply --dry-run` show exactly what would land, and what makes the
    compiler testable without a workspace.
    """
    import yaml
    _check_metadata_deny(mode)

    settings: Dict[str, Any] = {"mode_id": mode["id"], "default_mode": mode.get("default_mode", "observe")}
    # `selection: explicit` says "the rules listed below are the blocking set",
    # which is only meaningful when the mode names one. An `all` mode carries
    # enforcement in default_mode and must NOT set it, or the floor turns opt-in.
    if str(mode.get("enforce_rules")) != "all":
        settings["selection"] = "explicit"
    for key in ("egress", "tool_tags", "sandbox"):
        if mode.get(key):
            settings[key] = mode[key]

    rules: List[Dict[str, Any]] = [
        {"id": rid, "mode": "enforce"} for rid in enforcing_rule_ids(mode)
    ]
    rules.extend(_command_rules(mode))

    body = yaml.dump(
        {"version": "1.0", "settings": settings, "rules": rules},
        default_flow_style=False, sort_keys=False, width=100, allow_unicode=True,
    )
    blocking, total = coverage(mode)
    header = "\n".join([
        f"# Prismor governance mode: {mode['id']} ({mode.get('name', '')})",
        f"# Generated by `prismor mode apply {mode['id']}` on {date.today().isoformat()}.",
        "#",
        f"# {mode.get('intent', '')}",
        f"# {blocking} of {total} rules block. See the residual risk before you trust it:",
        f"#   prismor mode explain {mode['id']}",
        "#",
        "# Safe to hand-edit — but `prismor mode show` will then report drift, and",
        "# re-applying a mode overwrites this file (a .bak is kept).",
        "",
    ])
    return header + body


def apply_mode(
    workspace: Path, mode_id: str, force: bool = False
) -> Tuple[Path, List[str]]:
    """Write a mode's compiled policy into ``workspace``. Returns (path, notes).

    Refuses to overwrite a policy this tool did not generate unless ``force``,
    because a hand-written policy is somebody's deliberate work and clobbering
    it silently is how a governance tool loses an argument it should win. A
    ``.bak`` is kept either way.
    """
    mode = get_mode(mode_id)
    policy_path = workspace / ".prismor" / "policy.yaml"
    notes: List[str] = []

    if policy_path.exists():
        previous = active_mode(workspace)
        if previous is None and not force:
            raise ModeError(
                f"{policy_path} was not generated by a mode — applying '{mode_id}' would "
                f"overwrite it. Review it first, then re-run with --force."
            )
        backup = policy_path.with_suffix(".yaml.bak")
        backup.write_text(policy_path.read_text(encoding="utf-8"), encoding="utf-8")
        notes.append(f"previous policy backed up to {backup}")

    policy_path.parent.mkdir(parents=True, exist_ok=True)
    policy_path.write_text(compile_mode(mode), encoding="utf-8")

    # Tool axis lives in agents.yaml, not the policy — set_tool_policy owns the
    # deny/ask/allow tri-state and keeps the two lists disjoint for us.
    from prismor.runtime.agents import set_tool_policy
    tools = mode.get("tools") or {}
    for action in ("deny", "ask"):
        for tool in tools.get(action) or []:
            set_tool_policy(workspace, "global", tool, action)
            notes.append(f"tool '{tool}' -> {action} (global)")

    return policy_path, notes


def active_mode(workspace: Path) -> Optional[str]:
    """The mode id stamped into this workspace's policy, or None if unmanaged."""
    import yaml
    policy_path = workspace / ".prismor" / "policy.yaml"
    if not policy_path.exists():
        return None
    try:
        raw = yaml.safe_load(policy_path.read_text(encoding="utf-8")) or {}
    except Exception:
        return None
    mode_id = ((raw.get("settings") or {}).get("mode_id"))
    return str(mode_id) if mode_id else None


def has_drifted(workspace: Path) -> bool:
    """True when the policy claims a mode but no longer matches its compile.

    Drift is not an error — hand-editing a generated policy is legitimate. It
    is reported so `mode show` never claims a posture the file stopped having.
    """
    mode_id = active_mode(workspace)
    if mode_id is None:
        return False
    policy_path = workspace / ".prismor" / "policy.yaml"
    try:
        current = policy_path.read_text(encoding="utf-8")
        expected = compile_mode(get_mode(mode_id))
    except (OSError, ModeError):
        return False
    # Compare everything below the generated header — the header carries a
    # date, so a same-content re-compile a day later is not drift.
    return _strip_header(current) != _strip_header(expected)


def _strip_header(text: str) -> str:
    return "\n".join(
        line for line in text.splitlines() if not line.startswith("#")
    ).strip()


# ── Presentation ────────────────────────────────────────────────────────────

def _bar(pct: int, width: int = 20) -> str:
    filled = max(0, min(width, round(pct / 100 * width)))
    return "█" * filled + "░" * (width - filled)


def format_list(workspace: Optional[Path] = None) -> str:
    """The `mode list` table: id, what it costs, what it gives back."""
    active = active_mode(workspace) if workspace is not None else None
    lines = ["", "  Prismor governance modes", ""]
    for mode_id, mode in load_modes().items():
        blocking, total = coverage({**mode, "id": mode_id})
        pct = round(blocking / total * 100) if total else 0
        marker = " ← active" if mode_id == active else ""
        lines.append(f"  {mode_id:<20} {mode.get('name', '')}{marker}")
        lines.append(f"  {'':<20} {mode.get('intent', '')}")
        lines.append(
            f"  {'':<20} coverage {pct:>3}%  ·  friction {mode.get('friction_index', 0):>3}%"
            f"  ·  {blocking}/{total} rules block"
        )
        lines.append("")
    lines.append("  prismor mode explain <id>   the risk/reward trade before you adopt it")
    lines.append("  prismor mode apply <id>     compile it into .prismor/policy.yaml")
    lines.append("")
    return "\n".join(lines)


def format_explain(mode: Dict[str, Any]) -> str:
    """The `mode explain` risk-reward preview.

    Reward and friction get equal billing, and residual risk gets the last
    word, because the failure this whole feature guards against is somebody
    adopting a posture they believe is stronger than it is.
    """
    blocking, total = coverage(mode)
    pct = round(blocking / total * 100) if total else 0
    friction = int(mode.get("friction_index", 0))
    egress = mode.get("egress") or {}
    tools = mode.get("tools") or {}

    lines = [
        "",
        "  " + "=" * 72,
        f"  MODE EXPLAIN: {mode['id']}  ({mode.get('name', '')})",
        "  " + "=" * 72,
        "",
        f"  {mode.get('intent', '')}",
        "",
        "  " + _wrap(mode.get("scenario", ""), indent=2),
        "",
        "  [ REWARD: PROTECTED THREAT VECTORS ]",
    ]
    for item in mode.get("reward") or []:
        lines.append(f"    + {item}")
    lines += ["", "  [ RISK / FRICTION: DEVELOPER IMPACT ]"]
    for item in mode.get("friction") or []:
        lines.append(f"    ! {item}")

    lines += ["", "  [ POLICY AXES ]"]
    lines.append(f"    Enforcement    : {mode.get('default_mode', 'observe')}"
                 f"  ({blocking} of {total} rules block)")
    if egress.get("enabled"):
        allow = egress.get("allow") or []
        dest = ", ".join(str(a) for a in allow[:4]) + ("…" if len(allow) > 4 else "")
        lines.append(f"    Egress         : default {egress.get('default', 'allow')}"
                     f"  ({dest or 'nothing allowed'})")
    else:
        lines.append("    Egress         : unrestricted (no destination check)")
    tag_rules = (mode.get("tool_tags") or {}).get("rules") or []
    lines.append(f"    Tag rules      : {tag_rules[0] if tag_rules else 'none'}")
    for extra in tag_rules[1:]:
        lines.append(f"                     {extra}")
    sandbox = mode.get("sandbox") or {}
    if sandbox.get("enabled"):
        root = "read-only root" if sandbox.get("read_only_root") else "writable root"
        ring = f"{sandbox.get('mode', 'observe')}, network {sandbox.get('network', 'none')}, {root}"
    else:
        ring = "host native (unconfined)"
    lines.append(f"    Sandbox        : {ring}")
    denied = ", ".join(tools.get("deny") or []) or "none"
    asked = ", ".join(tools.get("ask") or []) or "none"
    lines.append(f"    Tools denied   : {denied}")
    lines.append(f"    Tools gated    : {asked}")

    lines += [
        "",
        "  [ OPERATIONAL METRICS ]",
        f"    Security coverage : [{_bar(pct)}] {pct}%",
        f"    Developer friction: [{_bar(friction)}] {friction}%",
        "",
        "  [ RESIDUAL RISK — what this mode does NOT stop ]",
        "  " + _wrap(mode.get("residual_risk", ""), indent=2),
        "",
        f"  RECOMMENDED FOR    : {mode.get('recommended_for', '')}",
        f"  NOT RECOMMENDED FOR: {mode.get('not_recommended_for', '')}",
        "",
        f"  Apply it:  prismor mode apply {mode['id']}",
        "",
    ]
    return "\n".join(lines)


def _wrap(text: str, width: int = 74, indent: int = 2) -> str:
    import textwrap
    return ("\n" + " " * indent).join(
        textwrap.wrap(" ".join(str(text).split()), width=width)
    )
