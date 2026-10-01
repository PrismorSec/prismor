"""Security posture audit for Prismor.

Performs a single-shot check across all Prismor subsystems:
  1. Hook integrations     — are hooks installed? which agents? what mode?
  2. Policy coverage       — disabled rules, missing block categories
  3. Cloaking status       — hooks installed? secrets registered?
  4. Secret permissions    — directory and file modes (0700 / 0600)
  5. Feed signature        — Ed25519 signature verification
  6. Egress allowlist      — is network lockdown configured?
  7. Network isolation     — are network rules enabled?
  8. Sandbox readiness     — is Docker sandboxing configured and available?

Each check returns findings with a severity, a human-readable message,
and an optional auto-fix function for ``prismor audit --fix``.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

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


def _is_signature_mismatch(result: "subprocess.CompletedProcess") -> bool:
    """Whether openssl actually rejected the signature.

    A non-zero exit is not enough. macOS ships LibreSSL, which cannot load an
    Ed25519 key and has no -rawin, so it exits non-zero for a feed that is
    perfectly intact. Only OpenSSL's explicit rejection line means tampering;
    anything else is a toolchain that could not answer the question.
    """
    output = b"".join(
        part for part in (result.stdout, result.stderr) if isinstance(part, bytes)
    ).decode("utf-8", "replace")
    return "signature verification failure" in output.lower()


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

    # Check if openssl is available
    if not shutil.which("openssl"):
        findings.append(AuditFinding(
            severity="MEDIUM",
            category="feed",
            message="openssl not found — cannot verify feed signature",
        ))
        return findings

    # Verify signature
    try:
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            sig_b64 = sig_path.read_bytes()
            import base64
            tmp.write(base64.b64decode(sig_b64))
            tmp_path = tmp.name

        result = subprocess.run(
            [
                "openssl", "pkeyutl", "-verify",
                "-pubin", "-inkey", str(pub_key),
                "-rawin",
                "-in", str(feed_path),
                "-sigfile", tmp_path,
            ],
            capture_output=True,
            timeout=10,
        )
        os.unlink(tmp_path)

        if result.returncode == 0:
            # Also report advisory count
            try:
                feed_data = json.loads(feed_path.read_text(encoding="utf-8"))
                n_advisories = len(feed_data.get("advisories", []))
                findings.append(AuditFinding(
                    severity="PASS",
                    category="feed",
                    message=f"Feed signature valid — {n_advisories} advisories loaded",
                ))
            except Exception:
                findings.append(AuditFinding(
                    severity="PASS",
                    category="feed",
                    message="Feed signature valid",
                ))
        elif _is_signature_mismatch(result):
            findings.append(AuditFinding(
                severity="CRITICAL",
                category="feed",
                message="Feed signature verification FAILED — feed may be tampered with",
            ))
        else:
            findings.append(AuditFinding(
                severity="MEDIUM",
                category="feed",
                message=(
                    "Cannot verify feed signature — "
                    f"{_openssl_label()} could not run the check "
                    "(needs OpenSSL 3.x for Ed25519 with -rawin)"
                ),
            ))
    except Exception as exc:
        findings.append(AuditFinding(
            severity="MEDIUM",
            category="feed",
            message=f"Feed signature check error: {exc}",
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
    """Check Docker sandbox configuration and backend readiness."""
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

    if not cfg.get("enabled"):
        findings.append(AuditFinding(
            severity="LOW",
            category="sandbox",
            message="Docker sandboxing is disabled — Bash commands run on the host after policy checks",
        ))
        return findings

    status = sandbox_mod.docker_status()
    if not status.get("cli_found"):
        findings.append(AuditFinding(
            severity="HIGH" if cfg.get("mode") == "enforce" else "MEDIUM",
            category="sandbox",
            message="Docker sandboxing is enabled but the docker CLI was not found",
        ))
    elif not status.get("server_reachable"):
        findings.append(AuditFinding(
            severity="HIGH" if cfg.get("mode") == "enforce" else "MEDIUM",
            category="sandbox",
            message=f"Docker sandboxing is enabled but Docker is not reachable: {status.get('error') or 'unknown error'}",
        ))
    else:
        findings.append(AuditFinding(
            severity="PASS",
            category="sandbox",
            message=f"Docker sandbox backend available (image: {cfg.get('image')})",
        ))

    if cfg.get("network") in {"host", "bridge"}:
        findings.append(AuditFinding(
            severity="MEDIUM",
            category="sandbox",
            message=f"Sandbox network mode is {cfg.get('network')} — use 'none' for strongest exfiltration protection",
        ))
    else:
        findings.append(AuditFinding(
            severity="PASS",
            category="sandbox",
            message="Sandbox network is disabled by default",
        ))

    if not cfg.get("read_only_root", True):
        findings.append(AuditFinding(
            severity="MEDIUM",
            category="sandbox",
            message="Sandbox read_only_root is disabled",
        ))

    limits = cfg.get("resource_limits") or {}
    missing_limits = [name for name in ("cpus", "memory", "pids_limit", "timeout_seconds") if not limits.get(name)]
    if missing_limits:
        findings.append(AuditFinding(
            severity="MEDIUM",
            category="sandbox",
            message=f"Sandbox resource limits missing: {', '.join(missing_limits)}",
        ))
    else:
        findings.append(AuditFinding(
            severity="PASS",
            category="sandbox",
            message="Sandbox resource limits configured",
        ))

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
