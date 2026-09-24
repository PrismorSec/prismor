"""Human-actionable unblock steps to print alongside an enforcement block.

A block that only says "no" pushes the human toward the one lever they can
always find: turning Prismor off. Every deny path therefore prints the
*narrowest* override that would let this specific call through — one call, one
rule, one session, one repo — and only then the broader ones. The floor rules
say so plainly instead of offering an override that would be silently ignored.

The steps address the human at the keyboard, not the model. `.prismor/policy.yaml`
and the agent hook configs are guarded by the `agent-config-tampering` rule, so
an agent that tries to apply them for itself just earns a second block.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from prismor.runtime.allow import literal_pattern, yaml_single_quoted
from prismor.runtime.policy_engine import (
    _CORE_BLOCK_CATEGORIES,
    _NON_OVERRIDABLE_RULE_IDS,
    _SELF_PROTECTION_RULE_IDS,
)

# Longest rule pattern worth quoting back. The core rules carry multi-line
# lookahead regexes that fill a screen; past this, naming the rule is kinder.
_MAX_READABLE_PATTERN = 80


def is_floor(finding: Dict[str, Any]) -> bool:
    """True when no local policy layer can disable or weaken this finding.

    Mirrors the clamp in PolicyEngine._apply_override: for these rule IDs and
    categories, `enabled: false`, `mode: observe` and `disable_patterns` are
    dropped from every override layer, including a signed org bundle.
    """
    return (
        str(finding.get("ruleId") or "") in _NON_OVERRIDABLE_RULE_IDS
        or str(finding.get("category") or "") in _CORE_BLOCK_CATEGORIES
    )


def _policy_path(workspace: Optional[Path]) -> str:
    return str((workspace / ".prismor" / "policy.yaml")) if workspace else ".prismor/policy.yaml"


def _allowlist_yaml(rule_id: str, finding: Dict[str, Any]) -> List[str]:
    """YAML for an allowlist entry suppressing this rule for this evidence only."""
    pattern = literal_pattern(finding.get("evidence") or "")
    if pattern is None:
        pattern = "<regex matching only the case you want to allow>"
    # Column 0 for the top-level key: these lines are meant to be pasted
    # straight into policy.yaml, and a decorative indent makes them unparseable.
    return [
        "allowlists:",
        f"  - id: allow-{rule_id}",
        f"    rule_ids: [{yaml_single_quoted(rule_id)}]",
        "    patterns:",
        f"      - {yaml_single_quoted(pattern)}",
        "    reason: '<why this specific case is safe>'",
    ]


def _shell_single_quoted(value: str) -> str:
    """Quote a pattern for a copy-pasteable shell command line."""
    return "'" + value.replace("'", "'\\''") + "'"


def _rule_override_steps(rule_id: str, finding: Dict[str, Any], workspace: Optional[Path]) -> List[str]:
    """The standard narrow-to-broad ladder for an ordinary policy rule.

    Each rung is a command rather than a paste of YAML: the paste is what makes
    "just turn Prismor off" the easier option, and the whole point of printing
    an unblock path is that the narrow one should be the easy one.
    """
    path = _policy_path(workspace)
    pattern = literal_pattern(finding.get("evidence") or "")
    steps: List[str] = []
    if pattern:
        steps.append(
            f"1. Allow only this case:  prismor allow {rule_id} "
            f"--pattern {_shell_single_quoted(pattern)}"
        )
        steps.append(
            "   (add --expires 30m to make it temporary)"
        )
    else:
        steps.append(
            f"1. Allow only this case:  prismor allow {rule_id} --pattern '<literal to allow>'"
        )
    steps += [
        f"2. Or keep the rule but stop it blocking (still reported):  prismor allow {rule_id} --observe",
        f"3. Or turn it off in this repo:  prismor allow {rule_id} --off --yes",
        f"   Each writes {path}; `prismor allow --list` shows what you have added, "
        f"and `prismor allow --undo <id>` removes one.",
        "Then verify without re-running the agent: prismor check '<your command>'",
    ]
    return steps


def _self_protection_steps(rule_id: str, workspace: Optional[Path]) -> List[str]:
    """Blocks on the rules Prismor uses to guard itself.

    These are the only blocks whose answer is a password. Everything else can be
    relaxed from the command line; if this one could be too, an agent that hit
    any other rule could simply relax this one first and then that one.
    """
    # Say which state this machine is in. "Set a password if you haven't" left
    # the agent guessing, and it guessed "just run prismor unlock", which on a
    # fresh install only prints that no password exists.
    try:
        from prismor.runtime import unlock as _unlock
        configured = _unlock.is_configured()
    except Exception:
        configured = True
    if configured:
        let_agent = ("2. To let the agent do it: open a short window with  prismor unlock  "
                     "(you will be asked for your Prismor password; the window is 3 minutes "
                     "by default), then have the agent retry.")
    else:
        let_agent = ("2. To let the agent do it: no unlock password is set on this machine yet. "
                     "In your own terminal run  prismor unlock --set-password  once, then  "
                     "prismor unlock  (a 3-minute window), then have the agent retry.")
    return [
        f"{rule_id} guards Prismor's own configuration, so it cannot be relaxed "
        "with `prismor allow`.",
        "1. If a person asked for this: run it yourself in your own terminal — "
        "Prismor governs agent tool calls, not you.",
        let_agent,
    ]


def _floor_steps(rule_id: str, finding: Dict[str, Any], enrolled: bool) -> List[str]:
    """Floor rules: say so, then give the outs that actually exist."""
    steps = [
        f"{rule_id} is a floor rule — `enabled: false`, `mode: observe` and "
        "`disable_patterns` are ignored for it in every policy layer, so editing "
        "policy.yaml will not clear this block.",
        f"0. Allow just this one case (allowlists do apply to floor rules):  "
        f"prismor allow {rule_id} --pattern '<literal>' --yes",
    ]
    # Only quote the pattern when a human could actually read it — the core
    # rules carry multi-line lookahead regexes that fill a screen and tell the
    # reader nothing the title did not.
    pattern = str(finding.get("pattern") or "")
    if pattern and len(pattern) <= _MAX_READABLE_PATTERN:
        steps.append(f"1. Narrow the action so it stops matching: {pattern}")
    else:
        steps.append(
            "1. Narrow the action so it stops matching — see what the rule covers "
            f"with: prismor policy show | grep {rule_id}"
        )
    steps.append(
        "2. Or run it yourself in a terminal outside the agent session — Prismor "
        "governs agent tool calls, not you."
    )
    if enrolled:
        steps.append(
            "3. Or ask an admin for a scoped exemption: prismor exempt request "
            '--reason "<why>" — they can grant it for one rule against this '
            "session, device, or user, with an expiry. It lands in your next "
            "signed policy pull."
        )
    return steps


def _subsystem_steps(
    rule_id: str,
    finding: Dict[str, Any],
    workspace: Optional[Path],
    session_id: Optional[str],
) -> Optional[List[str]]:
    """Steps for blocks that policy.yaml does not govern. None = not one of these."""
    if rule_id == "agent-disabled":
        # Not a policy rule: a kill switch in agents.yaml or the org control
        # plane, hardcoded to enforce. An allowlist would do nothing. The
        # finding's own remediation already names the layer that pulled it
        # (local / org / both), and only that layer can lift it — so defer to
        # it rather than invent a second, vaguer answer.
        steps = ["This agent is paused — every tool call is blocked, not just this one."]
        remediation = str(finding.get("remediation") or "").strip()
        if remediation:
            steps.append(f"1. {remediation}")
        steps.append("2. Check which layer paused it: prismor agents list")
        return steps

    if rule_id == "iam":
        path = str((workspace / ".prismor" / "iam.yaml")) if workspace else ".prismor/iam.yaml"
        return [
            "This is an agent identity limit, not a policy rule.",
            f"1. See what this identity may do: prismor iam show $PRISMOR_AGENT_ID",
            f"2. Grant the tool in {path} (or ~/.prismor/iam.yaml) — remove it from "
            "`deny_tools`, or add it to `allow_tools`.",
            "3. Or run the agent under an identity that already has it: PRISMOR_AGENT_ID=<name>",
        ]

    if rule_id == "scoped-agent":
        sid = session_id or "<session-id>"
        return [
            "This is a session scope Prismor synthesized from your prompts so far — "
            "it is not a policy rule and it dies with the session. Asking for the "
            "task in a new prompt usually widens it automatically.",
            f"1. See the scope: prismor scope show {sid}",
            f"2. Widen it by hand: prismor scope edit {sid}",
            f"3. Or drop it for this session entirely: prismor scope clear {sid}",
            "   (`latest` works in place of the session id)",
        ]

    if rule_id == "tool-category-crossover":
        path = _policy_path(workspace)
        return [
            "This is the tool-category crossover guard: the session combined tool "
            "tags your policy declares incompatible. The finding cannot be "
            "downgraded once it fires, so relax the tagging instead — in "
            f"{path}, under `settings.tool_tags`:",
            "  - drop the tag from the tool that should not carry it (`tags:`), or",
            "  - narrow which tag pairs conflict (`incompatible:`), or",
            "  - `enabled: false` to turn the guard off for this repo.",
            "Start a fresh session afterwards — tags accumulate across the session.",
        ]

    if rule_id.startswith("codex-cloak-"):
        return [
            "This is secret cloaking, not a policy rule — Codex hooks cannot "
            "rewrite a Bash command or scrub its output, so the real value would "
            "reach the process and the transcript.",
            "1. Run it through Prismor, which substitutes and scrubs: "
            "prismor cloak run -- <command>",
            "2. If the placeholder is unregistered: prismor cloak add <NAME>",
            "3. If it fired on something that is not a secret: prismor cloak list, "
            "then prismor cloak remove <NAME> to drop the bad registration.",
        ]

    return None


def unblock_steps(
    finding: Dict[str, Any],
    *,
    workspace: Optional[Path] = None,
    session_id: Optional[str] = None,
    org_managed: bool = False,
    enrolled: bool = False,
) -> List[str]:
    """Ordered narrow-to-broad steps a human can take to clear this block."""
    rule_id = str(finding.get("ruleId") or "").strip()
    if not rule_id or rule_id == "unknown":
        return []

    if rule_id in _SELF_PROTECTION_RULE_IDS:
        return _self_protection_steps(rule_id, workspace)

    steps = _subsystem_steps(rule_id, finding, workspace, session_id)
    if steps is None:
        if is_floor(finding):
            steps = _floor_steps(rule_id, finding, enrolled)
        else:
            steps = _rule_override_steps(rule_id, finding, workspace)
            if org_managed:
                # The remote layer merges after the project layer, so a local
                # override only survives on rules the org bundle stays silent
                # about. Say which way it can fail rather than let the user
                # edit a file that gets overwritten on the next pull.
                steps.append(
                    "This workspace is org-managed: the above works only if your "
                    "org's signed policy does not pin this rule. If the block "
                    "persists after the next policy pull, ask an admin: "
                    'prismor exempt request --reason "<why>"'
                )

    return steps


def format_unblock(
    finding: Dict[str, Any],
    *,
    workspace: Optional[Path] = None,
    session_id: Optional[str] = None,
    org_managed: bool = False,
    enrolled: bool = False,
) -> str:
    """Render the steps as a block of text, or "" when there is nothing to say."""
    steps = unblock_steps(
        finding,
        workspace=workspace,
        session_id=session_id,
        org_managed=org_managed,
        enrolled=enrolled,
    )
    if not steps:
        return ""
    header = (
        "To unblock (for the human at the keyboard — an agent running these is "
        "blocked unless `prismor unlock` is open):"
    )
    return "\n".join(
        [header] + steps
        + _delegate_steps(str(finding.get("ruleId") or "").strip(), workspace)
    )


def _delegate_steps(rule_id: str, workspace: Optional[Path]) -> List[str]:
    """The other way out: hand the fix to the agent for a few minutes.

    Without this the window is unreachable in the ordinary case. The text above
    tells the agent these commands are the human's to run, so a careful agent
    relays them and stops — correctly — and nobody ever learns that delegating
    was an option. Observed exactly that on the first real agent run.

    Deliberately not offered for self-protection rules: those are the ones the
    window lifts, and pointing at it there would read as "unlock to let the
    agent stop me guarding myself", which is the opposite of the trade.
    """
    if rule_id in _SELF_PROTECTION_RULE_IDS:
        return []
    try:
        from prismor.runtime import unlock as _unlock
        if _unlock.org_self_edit_disabled():
            return []
        configured = _unlock.is_configured()
    except Exception:
        return []

    open_cmd = "prismor unlock" if configured else "prismor unlock --set-password"
    return [
        f"Or let the agent apply one of these itself: {open_cmd}"
        + ("" if configured else ", then prismor unlock"),
        "   Opens a short password-gated window in which it may change policy — "
        "it still cannot run the blocked action directly. Then tell it to retry.",
    ]
