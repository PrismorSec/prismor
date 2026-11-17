"""Security posture audit for Prismor.

Performs a single-shot check across all Prismor subsystems:
  1. Hook integrations     — are hooks installed? which agents? what mode?
  2. Policy coverage       — disabled rules, missing block categories
  3. Cloaking status       — hooks installed? secrets registered?
  4. Secret permissions    — directory and file modes (0700 / 0600)
  5. Feed signature        — Ed25519 signature verification
  6. Egress allowlist      — is network lockdown configured?
  7. Network isolation     — are network rules enabled?
  8. Sandbox readiness     — is the OS sandbox on, and can it start here?

Each check returns findings with a severity, a human-readable message,
and an optional auto-fix function for ``prismor audit --fix``.
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from prismor.runtime.feed_signature import MISMATCH as SIG_MISMATCH
from prismor.runtime.feed_signature import MISSING as SIG_MISSING
from prismor.runtime.feed_signature import VERIFIED as SIG_VERIFIED
from prismor.runtime.feed_signature import is_signature_mismatch, verify_feed_file
from prismor.runtime.policy_engine import PolicyEngine, _load_yaml


# ── Finding model ───────────────────────────────────────────────────────────

class AuditFinding:
    """A single audit finding."""

    __slots__ = ("severity", "category", "message", "fix_label", "fix_fn")

    SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "PASS": 5}

    def __init__(
        self,
        severity: str,
        category: str,
        message: str,
        fix_label: Optional[str] = None,
        fix_fn: Optional[Callable[[], str]] = None,
    ) -> None:
        self.severity = severity
        self.category = category
        self.message = message
        self.fix_label = fix_label
        self.fix_fn = fix_fn

    @property
    def fixable(self) -> bool:
        return self.fix_fn is not None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "severity": self.severity,
            "category": self.category,
            "message": self.message,
        }
        if self.fix_label:
            d["fixable"] = True
            d["fix"] = self.fix_label
        return d


# ── Audit runner ────────────────────────────────────────────────────────────

def run_audit(
    workspace: Path,
    repo_root: Path,
) -> List[AuditFinding]:
    """Run all audit checks. Returns findings sorted by severity."""
    findings: List[AuditFinding] = []

    findings.extend(_check_hooks(workspace, repo_root))
    findings.extend(_check_policy(workspace))
    findings.extend(_check_cloaking(workspace))
    findings.extend(_check_secret_permissions())
    findings.extend(_check_feed_signature(repo_root))
    findings.extend(_check_egress_allowlist(workspace))
    findings.extend(_check_network_rules(workspace))
    findings.extend(_check_sandbox(workspace))
    findings.extend(_check_lockfile_presence(workspace))

    findings.sort(key=lambda f: AuditFinding.SEVERITY_ORDER.get(f.severity, 99))
    return findings


def apply_fixes(findings: List[AuditFinding]) -> List[str]:
    """Run all available auto-fixes. Returns list of actions taken."""
    actions: List[str] = []
    for f in findings:
        if f.fix_fn is not None:
            result = f.fix_fn()
            if result:
                actions.append(result)
    return actions


# ── Individual checks ───────────────────────────────────────────────────────

def _check_hooks(workspace: Path, repo_root: Path) -> List[AuditFinding]:
    """Check hook installation across agents, in both project and global scope."""
    from prismor.runtime.hooks import coverage, _config_path

    findings: List[AuditFinding] = []

    installed: List[str] = []
    mode_found: Optional[str] = None
    for agent, scopes in coverage(workspace).items():
        hit = [sc for sc, ok in scopes.items() if ok]
        if not hit:
            continue
        installed.append(agent if "project" in hit else f"{agent} (global)")
        if mode_found is None:
            try:
                content = _config_path(agent, hit[0], workspace).read_text(encoding="utf-8")
            except (OSError, ValueError):
                continue
            if "--mode enforce" in content:
                mode_found = "enforce"
            elif "--mode observe" in content:
                mode_found = "observe"

    if not installed:
        def _fix_install_hooks() -> str:
            from prismor.runtime.hooks import install_hooks
            from prismor.runtime.store import register_workspace
            install_hooks(
                repo_root=repo_root,
                workspace=workspace,
                agent="all",
                scope="project",
                mode="enforce",
            )
            register_workspace(workspace)
            return "Installed Prismor hooks for all agents in enforce mode"

        findings.append(AuditFinding(
            severity="CRITICAL",
            category="hooks",
            message="No Prismor hooks installed — agent actions are not monitored",
            fix_label="Install hooks for all agents (enforce mode)",
            fix_fn=_fix_install_hooks,
        ))
    else:
        findings.append(AuditFinding(
            severity="PASS",
            category="hooks",
            message=f"Hooks installed: {', '.join(installed)}",
        ))

        if mode_found == "observe":
            findings.append(AuditFinding(
                severity="MEDIUM",
                category="hooks",
                message="Hooks are in observe mode — dangerous actions are logged but not blocked",
            ))
        elif mode_found == "enforce":
            findings.append(AuditFinding(
                severity="PASS",
                category="hooks",
                message="Hooks running in enforce mode",
            ))

    return findings


def _check_policy(workspace: Path) -> List[AuditFinding]:
    """Check policy coverage — disabled rules, missing categories."""
    findings: List[AuditFinding] = []

    engine = PolicyEngine(workspace=workspace)
    default_path = Path(__file__).resolve().parent / "default_policy.yaml"
    default_data = _load_yaml(default_path)

    if default_data is None:
        findings.append(AuditFinding(
            severity="HIGH",
            category="policy",
            message="Cannot load default policy — rule engine may be broken",
        ))
        return findings

    total_rules = len(default_data.get("rules", []))
    active_rules = len(engine.rules)
    disabled = total_rules - active_rules

    if disabled > 0:
        findings.append(AuditFinding(
            severity="MEDIUM",
            category="policy",
            message=f"{disabled} of {total_rules} default rules are disabled",
        ))
    else:
        findings.append(AuditFinding(
            severity="PASS",
            category="policy",
            message=f"All {total_rules} default rules are active",
        ))

    # Check for project-level policy
    project_policy = workspace / ".prismor" / "policy.yaml"
    if project_policy.exists():
        findings.append(AuditFinding(
            severity="PASS",
            category="policy",
            message="Project-level policy overrides present",
        ))

    return findings


def _check_cloaking(workspace: Path) -> List[AuditFinding]:
    """Check cloaking hook installation and secret registration."""
    findings: List[AuditFinding] = []

    try:
        from prismor.runtime.cloaking import status as cloak_status, list_secrets
    except ImportError:
        findings.append(AuditFinding(
            severity="HIGH",
            category="cloaking",
            message="Cloaking module not available",
        ))
        return findings

    for _scope in ("project", "user"):
        result = cloak_status(workspace=workspace, scope=_scope)
        if result["installed"]:
            break

    if not result["installed"]:
        def _fix_install_cloak() -> str:
            from prismor.runtime.cloaking import install as cloak_install
            cloak_install(workspace=workspace, scope="project")
            return "Installed cloaking hooks at project scope"

        findings.append(AuditFinding(
            severity="HIGH",
            category="cloaking",
            message="Cloaking hooks not installed — secrets are not protected at the tool boundary",
            fix_label="Install cloaking hooks (project scope)",
            fix_fn=_fix_install_cloak,
        ))
    else:
        events = result.get("events", [])
        findings.append(AuditFinding(
            severity="PASS",
            category="cloaking",
            message=f"Cloaking hooks installed ({len(events)} hook event(s))",
        ))

    secrets = list_secrets()
    if not secrets:
        findings.append(AuditFinding(
            severity="LOW",
            category="cloaking",
            message="No secrets registered — consider registering secrets with `prismor cloak add`",
        ))
    else:
        findings.append(AuditFinding(
            severity="PASS",
            category="cloaking",
            message=f"{len(secrets)} secret(s) registered",
        ))

    return findings


def _check_secret_permissions() -> List[AuditFinding]:
    """Check filesystem permissions on secrets directory and files."""
    findings: List[AuditFinding] = []

    try:
        from prismor.runtime.cloaking.secrets_store import secrets_dir, check_permissions
    except ImportError:
        return findings

    sdir = secrets_dir()
    if not sdir.exists():
        # No secrets dir yet — not an issue
        return findings

    warnings = check_permissions()
    if warnings:
        def _fix_permissions() -> str:
            fixed = 0
            sdir_inner = secrets_dir()
            try:
                sdir_inner.chmod(0o700)
                fixed += 1
            except PermissionError:
                pass
            for child in sdir_inner.iterdir():
                if child.is_file():
                    try:
                        child.chmod(0o600)
                        fixed += 1
                    except PermissionError:
                        pass
            return f"Fixed permissions on {fixed} path(s) in {sdir_inner}"

        for w in warnings:
            findings.append(AuditFinding(
                severity="HIGH",
                category="permissions",
                message=w,
                fix_label="Set directory to 0700 and files to 0600",
                fix_fn=_fix_permissions,
            ))
    else:
        findings.append(AuditFinding(
            severity="PASS",
            category="permissions",
            message="Secret file permissions are correct (0700/0600)",
        ))

    return findings


def _openssl_label() -> str:
    """The openssl flavour and version, for a cannot-verify message."""
    try:
        out = subprocess.run(
            ["openssl", "version"], capture_output=True, timeout=5, text=True
        )
        return (out.stdout or out.stderr).strip().splitlines()[0] or "openssl"
    except Exception:
        return "openssl"


# Shared with feed.load_feed and the setup wizard; re-exported for callers/tests.
_is_signature_mismatch = is_signature_mismatch


def _check_feed_signature(repo_root: Path) -> List[AuditFinding]:
    """Verify the advisory feed Ed25519 signature."""
    findings: List[AuditFinding] = []

    from prismor.runtime.paths import feed_path as _feed_path, feed_sig_path, public_key_path

    feed_path = _feed_path()
    sig_path = feed_sig_path()
    pub_key = public_key_path()

    if not feed_path.exists():
        findings.append(AuditFinding(
            severity="MEDIUM",
            category="feed",
            message="Advisory feed not found — threat intelligence not available",
        ))
        return findings

    if not sig_path.exists():
        findings.append(AuditFinding(
            severity="HIGH",
            category="feed",
            message="Feed signature file missing — cannot verify feed integrity",
        ))
        return findings

    if not pub_key.exists():
        findings.append(AuditFinding(
            severity="HIGH",
            category="feed",
            message="Public key not found — cannot verify feed signature",
        ))
        return findings

    # Verify signature (cryptography, then openssl; never the cache -- an
    # audit is the place to do the real check).
    try:
        result = verify_feed_file(feed_path, sig_path, pub_key, use_cache=False)
    except Exception as exc:
        findings.append(AuditFinding(
            severity="MEDIUM",
            category="feed",
            message=f"Feed signature check error: {exc}",
        ))
        return findings

    if result.status == SIG_VERIFIED:
        try:
            feed_data = json.loads(feed_path.read_text(encoding="utf-8"))
            n_advisories = len(feed_data.get("advisories", []))
            message = f"Feed signature valid — {n_advisories} advisories loaded"
        except Exception:
            message = "Feed signature valid"
        findings.append(AuditFinding(severity="PASS", category="feed", message=message))
    elif result.status == SIG_MISMATCH:
        findings.append(AuditFinding(
            severity="CRITICAL",
            category="feed",
            message="Feed signature verification FAILED — feed may be tampered with",
        ))
    elif result.status == SIG_MISSING:
        findings.append(AuditFinding(
            severity="HIGH",
            category="feed",
            message=f"Feed signature unusable — {result.detail}",
        ))
    else:
        detail = result.detail
        if result.backend == "openssl":
            detail = f"{_openssl_label()} could not run the check (needs OpenSSL 3.x for Ed25519 with -rawin)"
        findings.append(AuditFinding(
            severity="MEDIUM",
            category="feed",
            message=f"Cannot verify feed signature — {detail}",
        ))

    return findings


def _check_egress_allowlist(workspace: Path) -> List[AuditFinding]:
    """Report the network egress posture.

    Three levels matter, not two: no policy at all, a policy that only observes,
    and a policy that actually refuses off-list destinations. A configured but
    observe-mode egress policy is a common half-finished state — it looks
    protective in a config file while blocking nothing.
    """
    findings: List[AuditFinding] = []

    engine = PolicyEngine(workspace=workspace)
    egress = engine.egress

    if not egress.enabled:
        findings.append(AuditFinding(
            severity="LOW",
            category="network",
            message="No egress policy configured — every outbound destination is permitted "
                    "(enable with `prismor egress enable`)",
        ))
        return findings

    if egress.legacy:
        findings.append(AuditFinding(
            severity="LOW",
            category="network",
            message=f"Using the deprecated settings.egress_allowlist ({len(egress.allow)} "
                    "domain(s)) — warn-only, never blocks. Migrate with `prismor egress migrate`",
        ))
        return findings

    mode = egress.mode or engine.device_mode or engine.default_mode
    scope = "strict allowlist" if egress.default == "deny" else "denylist only"
    detail = (f"{len(egress.allow)} allow / {len(egress.deny)} deny entr(ies), {scope}"
              + (", org-managed" if egress.source == "remote" else ""))

    if mode == "enforce":
        findings.append(AuditFinding(
            severity="PASS",
            category="network",
            message=f"Egress policy enforcing — {detail}",
        ))
    else:
        findings.append(AuditFinding(
            severity="LOW",
            category="network",
            message=f"Egress policy is in observe mode — off-policy destinations are logged "
                    f"but not blocked ({detail}). Review `prismor egress report`, then "
                    "`prismor egress mode enforce`",
        ))

    return findings


def _check_network_rules(workspace: Path) -> List[AuditFinding]:
    """Check that network isolation rules are enabled."""
    findings: List[AuditFinding] = []

    engine = PolicyEngine(workspace=workspace)
    network_rule_ids = {
        "raw-ip-outbound", "bind-all-interfaces",
        "reverse-tunnel", "network-exfil-tool", "suspicious-network",
    }

    active_ids = {r.id for r in engine.rules}
    missing_network = network_rule_ids - active_ids

    if missing_network:
        findings.append(AuditFinding(
            severity="MEDIUM",
            category="network",
            message=f"Network isolation rules disabled: {', '.join(sorted(missing_network))}",
        ))
    else:
        findings.append(AuditFinding(
            severity="PASS",
            category="network",
            message=f"All {len(network_rule_ids)} network isolation rules active",
        ))

    return findings


def _check_sandbox(workspace: Path) -> List[AuditFinding]:
    """Check the Prismor sandbox's configuration and whether its OS engine can start."""
    findings: List[AuditFinding] = []

    try:
        from prismor.runtime import sandbox as sandbox_mod
    except ImportError:
        findings.append(AuditFinding(
            severity="MEDIUM",
            category="sandbox",
            message="Sandbox module not available",
        ))
        return findings

    engine = PolicyEngine(workspace=workspace)
    cfg = sandbox_mod.effective_config(getattr(engine, "sandbox_config", {}))

    def _add(severity: str, message: str) -> None:
        findings.append(AuditFinding(severity=severity, category="sandbox", message=message))

    if not cfg.get("enabled"):
        _add("LOW", "Prismor sandbox is off — allowed shell commands run unconfined (prismor sandbox on)")
        return findings

    status = sandbox_mod.backend_status()
    if not status.get("available"):
        _add("HIGH" if cfg.get("mode") == "enforce" else "MEDIUM",
             f"Prismor sandbox is on but cannot start here: {status.get('error') or 'unknown error'}")
    elif cfg.get("mode") != "enforce":
        _add("MEDIUM", "Prismor sandbox is in observe mode — commands are not confined")
    else:
        _add("PASS", f"Prismor sandbox enforcing ({status.get('engine')})")

    network = cfg.get("network")
    if network == "open":
        _add("MEDIUM", "Sandbox network is open — use ring 2 to hold commands to the egress allowlist")
    elif network == "proxy" and not getattr(engine.egress, "enabled", False):
        _add("LOW", "Sandbox network goes through the proxy, but the egress allowlist is off "
                    "(prismor egress enable)")
    else:
        _add("PASS", f"Sandbox network: {network}")
    return findings


def _check_lockfile_presence(workspace: Path) -> List[AuditFinding]:
    """Check that lockfiles exist alongside dependency manifests."""
    findings: List[AuditFinding] = []

    try:
        from prismor.runtime.deps import check_lockfile_presence as check_locks
    except ImportError:
        return findings

    issues = check_locks(workspace)
    if issues:
        for issue in issues:
            findings.append(AuditFinding(
                severity=issue["severity"],
                category="supply_chain",
                message=issue["message"],
            ))
    else:
        # Only report PASS if there are manifests at all
        from prismor.runtime.deps import find_manifests
        manifests = find_manifests(workspace)
        if manifests:
            findings.append(AuditFinding(
                severity="PASS",
                category="supply_chain",
                # Scoped deliberately: this only verifies lockfiles exist
                # (version pins are locked), not that those pinned
                # versions are CVE-free — that live OSV/typosquat/IOC
                # scoring happens at hook time (the
                # supply_chain_install_check / supply_chain_transitive_
                # scan settings), not in this static audit. An earlier
                # version of this message ("All dependency manifests have
                # corresponding lockfiles") was easy to misread as a
                # vulnerability-free verdict.
                message=(
                    "Lockfile presence: all dependency manifests have lockfiles "
                    "(does not mean dependencies are CVE-free — that's checked "
                    "live at install/edit time, not by this audit)"
                ),
            ))

    return findings
