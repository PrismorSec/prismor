"""Prismor Sweep — scan AI tool configs for leaked secrets, redact with encrypted vault.

Vault: a single AES-256-CBC encrypted file (~/.prismor/sweep.vault.enc) that
accumulates every redacted secret with its exact file:line:col location.
Password required for all mutating operations.
"""
from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from getpass import getpass
from pathlib import Path
from typing import Optional

# ── Constants ───────────────────────────────────────────────────────────

PRISMOR_HOME = Path(os.environ.get("PRISMOR_HOME", Path.home() / ".prismor"))
VAULT_PATH = PRISMOR_HOME / "sweep.vault.enc"
VAULT_SALT_PATH = PRISMOR_HOME / "sweep.vault.salt"  # existence = vault initialized

# Minimum gitleaks version tested against (rule set and JSON schema differ across majors)
GITLEAKS_MIN_VERSION = (8, 18, 0)

# Optional custom rule config for AI-tool-specific patterns
_SWEEP_CONFIG = Path(__file__).parent / "sweep-gitleaks.toml"

# Basic fallback patterns used when gitleaks is not installed
_FALLBACK_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("openai-api-key",    re.compile(r'sk-[A-Za-z0-9]{20,48}')),
    ("anthropic-api-key", re.compile(r'sk-ant-[A-Za-z0-9\-_]{20,}')),
    ("huggingface-token", re.compile(r'hf_[A-Za-z0-9]{30,50}')),
    ("github-pat",        re.compile(r'ghp_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36}')),
    ("aws-access-key",    re.compile(r'(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])')),
    ("replicate-api-key", re.compile(r'r8_[A-Za-z0-9]{32,}')),
    ("generic-api-key",   re.compile(
        r'(?i)(?:api[_-]?key|secret[_-]?key|auth[_-]?token)\s*[:=]\s*["\']?([A-Za-z0-9\-_\.]{20,})'
    )),
]

# Directories to scan, keyed by tool name
TOOL_DIRS: dict[str, Path] = {
    "windsurf": Path.home() / ".codeium",
    "codex": Path.home() / ".codex",
    "antigravity": Path.home() / ".antigravity",
    "cursor": Path.home() / ".config" / "Cursor",
    "claude": Path.home() / ".claude",
    "trae": Path.home() / ".trae",
    "kilocode": Path.home() / ".kilocode",
    "grok": Path.home() / ".grok",
    "herdr": Path.home() / ".config" / "herdr",
    "kiro": Path.home() / ".kiro",
    "crush": Path.home() / ".config" / "crush",
    "openhands": Path.home() / ".openhands",
    "qwen": Path.home() / ".qwen",
    "continue": Path.home() / ".continue",
    "goose": Path.home() / ".config" / "goose",
}

# Config files that should NEVER be redacted (they hold keys the tools need)
CONFIG_ALLOWLIST = {
    "settings.json",
    "config.json",
    "config.yaml",
    "config.yml",
    "credentials.json",
    "prefs.json",
    "auth.json",
    ".env",
}

# ANSI
_RED = "\033[0;31m"
_GREEN = "\033[0;32m"
_YELLOW = "\033[1;33m"
_BLUE = "\033[0;34m"
_DIM = "\033[2m"
_BOLD = "\033[1m"
_NC = "\033[0m"


def _c(text: str, color: str) -> str:
    if not sys.stderr.isatty():
        return text
    return f"{color}{text}{_NC}"


def info(msg: str) -> None:
    print(_c("[sweep]", _BLUE) + f" {msg}")


def ok(msg: str) -> None:
    print(_c("[sweep]", _GREEN) + f" {msg}")


def warn(msg: str) -> None:
    print(_c("[sweep]", _YELLOW) + f" {msg}")


def err(msg: str) -> None:
    print(_c("[sweep]", _RED) + f" {msg}", file=sys.stderr)


# ── Vault crypto (openssl CLI) ──────────────────────────────────────────

def _vault_encrypt(plaintext: bytes, passphrase: str) -> bytes:
    """Encrypt bytes with AES-256-CBC + PBKDF2 via openssl."""
    proc = subprocess.run(
        ["openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-salt", "-pass", f"pass:{passphrase}"],
        input=plaintext,
        capture_output=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"openssl encrypt failed: {proc.stderr.decode()}")
    return proc.stdout


def _vault_decrypt(ciphertext: bytes, passphrase: str) -> bytes:
    """Decrypt AES-256-CBC + PBKDF2 via openssl."""
    proc = subprocess.run(
        ["openssl", "enc", "-d", "-aes-256-cbc", "-pbkdf2", "-pass", f"pass:{passphrase}"],
        input=ciphertext,
        capture_output=True,
    )
    if proc.returncode != 0:
        raise RuntimeError("Wrong passphrase or corrupted vault.")
    return proc.stdout


def _vault_exists() -> bool:
    return VAULT_PATH.exists() and VAULT_PATH.stat().st_size > 0


def _read_vault(passphrase: str) -> list[dict]:
    """Decrypt and parse vault entries."""
    if not _vault_exists():
        return []
    ciphertext = VAULT_PATH.read_bytes()
    try:
        plaintext = _vault_decrypt(ciphertext, passphrase)
    except RuntimeError:
        err("Wrong passphrase or corrupted vault.")
        raise SystemExit(1)
    return json.loads(plaintext)


def _write_vault(entries: list[dict], passphrase: str) -> None:
    """Encrypt and write vault entries."""
    PRISMOR_HOME.mkdir(parents=True, exist_ok=True)
    plaintext = json.dumps(entries, indent=2).encode()
    ciphertext = _vault_encrypt(plaintext, passphrase)
    VAULT_PATH.write_bytes(ciphertext)
    # Mark vault as initialized
    VAULT_SALT_PATH.touch()


def _prompt_passphrase(confirm: bool = False) -> str:
    """Prompt user for vault passphrase. If confirm=True, ask twice (new vault)."""
    if not sys.stdin.isatty():
        env_pass = os.environ.get("PRISMOR_SWEEP_PASS")
        if env_pass:
            return env_pass
        raise RuntimeError("No TTY and PRISMOR_SWEEP_PASS not set.")

    if confirm:
        print()
        print(_c("=" * 60, _YELLOW))
        info("Creating your Prismor Sweep vault.")
        print()
        print(f"  This vault encrypts every secret we redact so you can")
        print(f"  restore them later if needed. It is protected by a")
        print(f"  passphrase that {_c('only you know', _BOLD)}.")
        print()
        print(f"  {_c('IMPORTANT:', _RED)}")
        print(f"  {_c('This passphrase is shown ONCE and cannot be recovered.', _RED)}")
        print(f"  {_c('If you lose it, the vault is permanently locked.', _RED)}")
        print()
        print(f"  Store it somewhere safe:")
        print(f"    - a password manager")
        print(f"    - an encrypted note")
        print(f"    - {_c('NOT', _RED)} in a file inside these config directories")
        print(_c("=" * 60, _YELLOW))
        print()
        p1 = getpass("  Choose vault passphrase: ")
        if len(p1) < 4:
            err("Passphrase too short (min 4 characters).")
            raise SystemExit(1)
        p2 = getpass("  Confirm passphrase: ")
        if p1 != p2:
            err("Passphrases don't match.")
            raise SystemExit(1)
        print()
        ok("Vault passphrase set. Keep it safe — it will not be shown again.")
        print()
        return p1
    else:
        return getpass("  Vault passphrase: ")


# ── Gitleaks scanner ────────────────────────────────────────────────────

def _gitleaks_install_hint() -> str:
    """Return a platform-appropriate install hint for gitleaks."""
    system = platform.system()
    if system == "Darwin":
        return "brew install gitleaks"
    if system == "Linux":
        return (
            "go install github.com/gitleaks/gitleaks/v8@latest\n"
            "  Or download a pre-built binary from https://github.com/gitleaks/gitleaks/releases"
        )
    if system == "Windows":
        return (
            "choco install gitleaks  (or: winget install gitleaks.gitleaks)\n"
            "  Or download a pre-built binary from https://github.com/gitleaks/gitleaks/releases"
        )
    return "https://github.com/gitleaks/gitleaks/releases"


def _find_gitleaks() -> Optional[str]:
    """Return gitleaks binary path, or None if not installed."""
    return shutil.which("gitleaks")


def _check_gitleaks_version(path: str) -> None:
    """Warn (non-fatal) if installed gitleaks is below the minimum tested version."""
    try:
        result = subprocess.run(
            [path, "version"], capture_output=True, text=True, timeout=5
        )
        version_output = (result.stdout + result.stderr).strip()
        m = re.search(r'v?(\d+)\.(\d+)\.(\d+)', version_output)
        if m:
            found = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
            if found < GITLEAKS_MIN_VERSION:
                min_str = ".".join(str(v) for v in GITLEAKS_MIN_VERSION)
                found_str = ".".join(str(v) for v in found)
                warn(
                    f"gitleaks {found_str} is below minimum tested version {min_str} — "
                    "built-in rule set and JSON report schema have changed across major versions; "
                    "results may vary. Consider upgrading."
                )
    except (subprocess.TimeoutExpired, OSError, ValueError):
        pass  # Non-fatal; proceed with whatever version is present


def _scan_directory(gitleaks: str, directory: Path) -> list[dict]:
    """Run gitleaks on a directory, return findings."""
    # mkstemp creates with 0o600 perms — secrets are safe if the process crashes mid-scan
    fd, report_path = tempfile.mkstemp(suffix=".json")
    os.close(fd)  # gitleaks opens the file itself; we just need the path

    try:
        cmd = [
            gitleaks, "dir", str(directory),
            "--report-format", "json",
            "--report-path", report_path,
            "--no-banner",
            "--max-target-megabytes", "1",
            "--exit-code", "0",
            "-l", "warn",
        ]
        if _SWEEP_CONFIG.exists():
            cmd += ["--config", str(_SWEEP_CONFIG)]

        subprocess.run(cmd, capture_output=True)
        report = Path(report_path)
        if report.exists() and report.stat().st_size > 0:
            return json.loads(report.read_text(encoding="utf-8"))
        return []
    finally:
        Path(report_path).unlink(missing_ok=True)


def _fallback_scan(directory: Path) -> list[dict]:
    """Minimal built-in pattern scan used when gitleaks is not installed.

    Covers common AI-tool secret formats so `prismor sweep` still catches obvious
    leaks on a fresh machine before the user has installed the gitleaks dependency.
    """
    findings: list[dict] = []
    scan_exts = {
        '.json', '.yaml', '.yml', '.toml', '.env', '.txt', '.md',
        '.log', '.conf', '.cfg', '.ini', '.py', '.js', '.ts', '.sh',
    }
    skip_dirs = {'.git', '__pycache__', 'node_modules', '.tox', 'venv', '.venv'}

    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for filename in files:
            if not any(filename.endswith(ext) for ext in scan_exts):
                continue
            filepath = os.path.join(root, filename)
            try:
                with open(filepath, 'r', encoding='utf-8', errors='replace') as fh:
                    for lineno, line in enumerate(fh, 1):
                        for rule_id, pattern in _FALLBACK_PATTERNS:
                            m = pattern.search(line)
                            if not m:
                                continue
                            secret = m.group(1) if m.lastindex else m.group(0)
                            findings.append({
                                "File": filepath,
                                "RuleID": rule_id,
                                "Secret": secret,
                                "StartLine": lineno,
                                "StartColumn": m.start(),
                                "EndColumn": m.end(),
                                "Match": line.strip()[:200],
                                "Description": "basic-mode finding (gitleaks not installed)",
                            })
            except (OSError, PermissionError):
                pass

    return findings


def _is_config_file(filepath: str) -> bool:
    """Check if a file is in the config allowlist (should not be redacted)."""
    name = Path(filepath).name
    return name in CONFIG_ALLOWLIST


# ── Core operations ─────────────────────────────────────────────────────

def scan(custom_dirs: Optional[list[str]] = None) -> list[dict]:
    """Scan AI tool directories and return findings.

    Falls back to built-in regex patterns when gitleaks is not installed so the
    command still provides basic coverage on a fresh machine.
    """
    gitleaks = _find_gitleaks()
    if gitleaks:
        _check_gitleaks_version(gitleaks)
    else:
        warn("gitleaks not found — running in basic mode (limited secret coverage).")
        warn(f"Install for full coverage: {_gitleaks_install_hint()}")

    scan_dirs: list[tuple[str, Path]] = []

    if custom_dirs:
        for d in custom_dirs:
            p = Path(d).expanduser().resolve()
            if p.is_dir():
                scan_dirs.append((str(p), p))
    else:
        for tool, path in TOOL_DIRS.items():
            if path.is_dir():
                scan_dirs.append((tool, path))
                info(f"Found {tool} config: {_c(str(path), _DIM)}")

    if not scan_dirs:
        ok("No AI tool config directories found. Nothing to scan.")
        return []

    all_findings: list[dict] = []
    for label, directory in scan_dirs:
        info(f"Scanning {directory}...")
        if gitleaks:
            findings = _scan_directory(gitleaks, directory)
        else:
            findings = _fallback_scan(directory)
        all_findings.extend(findings)

    return all_findings


def report_findings(findings: list[dict]) -> None:
    """Print a summary of findings."""
    if not findings:
        ok("No secrets found. Clean.")
        return

    # Separate config vs residue
    residue = [f for f in findings if not _is_config_file(f["File"])]
    config = [f for f in findings if _is_config_file(f["File"])]

    warn(f"Found {len(findings)} secret(s): {len(residue)} in residue, {len(config)} in config files")
    print()

    # Group by rule
    by_rule: dict[str, list[dict]] = {}
    for f in residue:
        by_rule.setdefault(f["RuleID"], []).append(f)

    for rule, items in sorted(by_rule.items()):
        print(f"  {_c('●', _RED)} {_c(rule, _BOLD)}  ({len(items)} occurrences)")
        # Show first 3 files
        shown = set()
        for item in items[:3]:
            short = item["File"].replace(str(Path.home()), "~")
            key = f"{short}:{item['StartLine']}"
            if key not in shown:
                print(f"    {_c(short, _DIM)}:{item['StartLine']}")
                shown.add(key)
        if len(items) > 3:
            print(f"    {_c(f'...and {len(items) - 3} more', _DIM)}")

    if config:
        print()
        info(f"{len(config)} secret(s) in config files (skipped — these are intentional):")
        for f in config[:5]:
            short = f["File"].replace(str(Path.home()), "~")
            print(f"    {_c('○', _YELLOW)} {short}")
        if len(config) > 5:
            print(f"    {_c(f'...and {len(config) - 5} more', _DIM)}")


def redact(findings: list[dict], passphrase: str, purge: bool = False) -> int:
    """Redact secrets in residue files. Returns count of redacted secrets.

    - Appends each redacted secret to the encrypted vault.
    - Skips config files (allowlisted).
    - If purge=True, skips vault entirely (no recovery).
    """
    residue = [f for f in findings if not _is_config_file(f["File"])]
    if not residue:
        ok("Nothing to redact (all findings are in config files).")
        return 0

    # Load existing vault (or start fresh)
    if not purge:
        vault_entries = _read_vault(passphrase) if _vault_exists() else []

    redacted_count = 0
    now = datetime.now(timezone.utc).isoformat()

    # Group findings by file for efficient processing
    by_file: dict[str, list[dict]] = {}
    for f in residue:
        by_file.setdefault(f["File"], []).append(f)

    for filepath, file_findings in by_file.items():
        if not Path(filepath).exists():
            continue

        try:
            content = Path(filepath).read_text(errors="replace", encoding="utf-8")
        except (OSError, PermissionError) as e:
            warn(f"Cannot read {filepath}: {e}")
            continue

        modified = content
        for finding in file_findings:
            secret = finding["Secret"]
            if not secret or secret not in modified:
                continue

            # Build mask
            if len(secret) > 8:
                mask = secret[:4] + "*" * (len(secret) - 4)
            else:
                mask = "*" * len(secret)

            # Record in vault before redacting
            if not purge:
                vault_entries.append({
                    "file": filepath,
                    "line": finding["StartLine"],
                    "col": finding["StartColumn"],
                    "end_col": finding["EndColumn"],
                    "secret": secret,
                    "mask": mask,
                    "rule": finding["RuleID"],
                    "redacted_at": now,
                })

            modified = modified.replace(secret, mask)
            redacted_count += 1

        # Write back
        if modified != content:
            try:
                Path(filepath).write_text(modified, encoding="utf-8")
                short = filepath.replace(str(Path.home()), "~")
                count = len(file_findings)
                print(f"  {_c('✓', _GREEN)} Redacted {count} secret(s) in {_c(short, _DIM)}")
            except (OSError, PermissionError) as e:
                warn(f"Cannot write {filepath}: {e}")

    # Save vault
    if not purge and redacted_count > 0:
        _write_vault(vault_entries, passphrase)
        ok(f"Vault updated: {len(vault_entries)} total entries")
        short_vault = str(VAULT_PATH).replace(str(Path.home()), "~")
        print(f"  {_c(short_vault, _DIM)}")
        print()
        print(f"  {_c('Reminder:', _YELLOW)} You need your vault passphrase to restore these secrets.")
        print(f"  Run {_c('prismor sweep --restore', _BOLD)} to recover them later.")

    if purge and redacted_count > 0:
        print()
        warn("Purge mode — no vault backup was created. These secrets are gone.")
        print(f"  If these keys are still active, rotate them now.")

    return redacted_count


def restore(passphrase: str, target_file: Optional[str] = None, all_entries: bool = False) -> int:
    """Restore redacted secrets from the vault. Returns count restored."""
    if not _vault_exists():
        err("No vault found. Nothing to restore.")
        return 0

    entries = _read_vault(passphrase)
    if not entries:
        ok("Vault is empty.")
        return 0

    # Filter entries
    if target_file:
        target = str(Path(target_file).resolve())
        entries = [e for e in entries if e["file"] == target]
        if not entries:
            err(f"No vault entries for {target_file}")
            return 0
    elif not all_entries:
        # Show what's in the vault and let user decide
        _show_vault_summary(entries)
        print()
        info("Use --all to restore everything, or --file <path> to restore a specific file.")
        return 0

    restored = 0
    for entry in entries:
        filepath = entry["file"]
        if not Path(filepath).exists():
            warn(f"File gone: {filepath}")
            continue

        try:
            content = Path(filepath).read_text(errors="replace", encoding="utf-8")
        except (OSError, PermissionError):
            continue

        mask = entry["mask"]
        secret = entry["secret"]

        if mask in content:
            content = content.replace(mask, secret, 1)
            Path(filepath).write_text(content, encoding="utf-8")
            short = filepath.replace(str(Path.home()), "~")
            print(f"  {_c('✓', _GREEN)} Restored {entry['rule']} in {_c(short, _DIM)}:{entry['line']}")
            restored += 1

    if restored:
        ok(f"Restored {restored} secret(s)")
    else:
        warn("No masks found in files — secrets may have already been restored or files changed.")

    return restored


def clean(findings: list[dict], passphrase: str) -> int:
    """Delete residue files that contain leaked secrets. Returns count deleted."""
    residue = [f for f in findings if not _is_config_file(f["File"])]
    if not residue:
        ok("Nothing to clean.")
        return 0

    # Unique files
    files = sorted(set(f["File"] for f in residue if Path(f["File"]).exists()))
    if not files:
        ok("No residue files found on disk.")
        return 0

    # Record secrets in vault before deleting
    vault_entries = _read_vault(passphrase) if _vault_exists() else []
    now = datetime.now(timezone.utc).isoformat()

    for finding in residue:
        if finding["Secret"]:
            vault_entries.append({
                "file": finding["File"],
                "line": finding["StartLine"],
                "col": finding["StartColumn"],
                "end_col": finding["EndColumn"],
                "secret": finding["Secret"],
                "mask": None,
                "rule": finding["RuleID"],
                "redacted_at": now,
                "action": "deleted",
            })

    deleted = 0
    for filepath in files:
        try:
            Path(filepath).unlink()
            short = filepath.replace(str(Path.home()), "~")
            print(f"  {_c('✗', _RED)} Deleted {_c(short, _DIM)}")
            deleted += 1
        except (OSError, PermissionError) as e:
            warn(f"Cannot delete {filepath}: {e}")

    if deleted:
        _write_vault(vault_entries, passphrase)
        ok(f"Deleted {deleted} file(s). Secrets saved to vault before deletion.")

    return deleted


def show_vault(passphrase: str) -> None:
    """Show vault contents."""
    if not _vault_exists():
        err("No vault found.")
        return
    entries = _read_vault(passphrase)
    _show_vault_summary(entries)


def _show_vault_summary(entries: list[dict]) -> None:
    """Print a grouped summary of vault entries."""
    if not entries:
        ok("Vault is empty.")
        return

    info(f"Vault contains {len(entries)} entries:")
    print()

    # Group by file
    by_file: dict[str, list[dict]] = {}
    for e in entries:
        by_file.setdefault(e["file"], []).append(e)

    for filepath, file_entries in sorted(by_file.items()):
        short = filepath.replace(str(Path.home()), "~")
        action = file_entries[0].get("action", "redacted")
        marker = _c("✗", _RED) if action == "deleted" else _c("●", _YELLOW)
        print(f"  {marker} {_c(short, _DIM)}  ({len(file_entries)} secrets)")
        for e in file_entries[:3]:
            rule = e["rule"]
            line = e["line"]
            ts = e["redacted_at"][:10]
            print(f"      line {line}: {rule}  [{ts}]")
        if len(file_entries) > 3:
            print(f"      {_c(f'...and {len(file_entries) - 3} more', _DIM)}")
