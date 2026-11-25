"""Project-memory integrity: TOFU baseline, git-aware change classification.

Kept separate from hooks.py because it owns persistent state (trust store)
and a git-aware classification path that belongs in the runtime layer, not
the hook-normalizer layer. Imported by hooks.py for SessionStart verification
and by immunity_cli.py for the ``prismor memory`` subcommands.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Maximum seconds to wait for a git subprocess call.
# A stalled git should not hang the session.
_GIT_TIMEOUT = 5  # seconds

# Schema version written to every trust store file.
_SCHEMA_VERSION = "prismor.memory-integrity.v1"

# Precompiled metric — updated on every load so telemetry can gauge store size.
_TRUST_STORE_SIZE_GAUGE = 0


# ── Path helpers ──────────────────────────────────────────────────────────


def _prismor_home() -> Path:
    """The directory Prismor uses for persistent state: ``~/.prismor``."""
    raw = os.environ.get("PRISMOR_HOME")
    if raw:
        return Path(raw)
    return Path.home() / ".prismor"


def _global_trust_path() -> Path:
    """Global (per-machine) trust store."""
    return _prismor_home() / "memory-trust.json"


def _workspace_trust_path(workspace: Path) -> Path:
    """Per-workspace trust store override."""
    return workspace / ".prismor" / "memory-trust.json"


# ── Git helpers ───────────────────────────────────────────────────────────


def _git(cmd: list, cwd: str, timeout: int = _GIT_TIMEOUT) -> subprocess.CompletedProcess | None:
    """Run a git command with timeout. Returns None on any failure."""
    try:
        return subprocess.run(
            ["git"] + cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None


def _resolve_repo_root(workspace: Path) -> Optional[Path]:
    """Resolve the git repository root for ``workspace``. None if not in a repo."""
    result = _git(["rev-parse", "--show-toplevel"], cwd=str(workspace))
    if result and result.returncode == 0 and result.stdout.strip():
        return Path(result.stdout.strip())
    return None


def _current_commit(repo_root: Path) -> Optional[str]:
    """HEAD SHA (short) for ``repo_root``. None if unavailable."""
    result = _git(["rev-parse", "--short", "HEAD"], cwd=str(repo_root))
    if result and result.returncode == 0:
        return result.stdout.strip()
    return None


# ── Core functions ────────────────────────────────────────────────────────


def _norm_eol(data: bytes) -> bytes:
    """CRLF -> LF for text, so a line-ending-only edit is not a change."""
    return data if b"\0" in data else data.replace(b"\r\n", b"\n")


def compute_file_hash(path: Path, normalize: bool = True) -> str:
    """SHA-256 hex digest of the file bytes (CRLF normalised to LF).

    ``normalize=False`` gives the raw-bytes digest older baselines stored;
    comparisons accept either. Returns an empty string on any error — the
    caller treats this as ``unable_to_verify`` rather than crashing.
    """
    try:
        data = path.read_bytes()
        return hashlib.sha256(_norm_eol(data) if normalize else data).hexdigest()
    except Exception:
        return ""


def hash_hint(path: Path) -> str:
    """The shell command that prints this file's SHA-256 on this OS."""
    if os.name == "nt":
        return f'Get-FileHash -Algorithm SHA256 "{path}"'
    import shutil
    return f"sha256sum {path}" if shutil.which("sha256sum") else f"shasum -a 256 {path}"


def load_trust_store(workspace: Path) -> dict:
    """Load the merged trust state: per-workspace store overlaid on the global store.

    Returns a dict with ``schema``, ``files``, and ``signing`` keys — even on
    first run when no store exists yet.
    """
    merged: Dict[str, Any] = {
        "schema": _SCHEMA_VERSION,
        "files": {},
        "signing": {"enabled": False, "public_keys": {}},
    }

    # Load global store first (per-machine baseline).
    global_path = _global_trust_path()
    if global_path.is_file():
        try:
            global_data = json.loads(global_path.read_text(encoding="utf-8"))
            if isinstance(global_data.get("files"), dict):
                merged["files"].update(global_data["files"])
            if isinstance(global_data.get("signing"), dict):
                merged["signing"].update(global_data["signing"])
        except (json.JSONDecodeError, OSError):
            pass

    # Overlay with workspace store (project-shared baselines).
    ws_path = _workspace_trust_path(workspace)
    if ws_path.is_file():
        try:
            ws_data = json.loads(ws_path.read_text(encoding="utf-8"))
            if isinstance(ws_data.get("files"), dict):
                merged["files"].update(ws_data["files"])
            if isinstance(ws_data.get("signing"), dict):
                merged["signing"].update(ws_data["signing"])
        except (json.JSONDecodeError, OSError):
            pass

    global _TRUST_STORE_SIZE_GAUGE
    _TRUST_STORE_SIZE_GAUGE = len(merged["files"])
    return merged


def _save_trust_store(store: dict, workspace: Path) -> None:
    """Persist the per-workspace trust store.

    Creates ``.prismor/`` if needed; writes atomically via a temp file so a
    crash mid-write leaves the original intact. Files are 0600 — the hashes
    aren't secrets, but the store is writable-only.
    """
    ws_path = _workspace_trust_path(workspace)
    try:
        ws_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    except OSError:
        return
    try:
        tmp = ws_path.with_suffix(ws_path.suffix + ".tmp")
        tmp.write_text(json.dumps(store, indent=2, default=str), encoding="utf-8")
        tmp.chmod(0o600)
        tmp.replace(ws_path)
    except OSError:
        pass


def _classify_change(
    path: Path,
    current_hash: str,
    stored: dict,
    session_log_dir: Optional[Path],
) -> Tuple[str, str, str]:
    """Classify why ``path``'s content hash differs from its trust baseline.

    Returns ``(origin, severity, message)`` where *origin* is one of
    ``changed_in_commit``, ``uncommitted_change``, ``agent_session_change``,
    ``file_removed``, or ``unclassified_change``.
    """
    repo_root = _resolve_repo_root(path.parent)
    if repo_root is None:
        return (
            "unclassified_change",
            "LOW",
            f"{path.name} changed but git is unavailable — cannot classify",
        )

    try:
        rel = str(path.relative_to(repo_root))
    except ValueError:
        return (
            "unclassified_change",
            "LOW",
            f"{path.name} changed — not in current git repo",
        )

    # ── Check 1: Is the file at its committed (HEAD) state? ──────────
    cat_file = _git(["cat-file", "-e", f"HEAD:{rel}"], cwd=str(repo_root))
    if cat_file and cat_file.returncode == 0:
        # Use subprocess.run with text=False so git show's raw bytes
        # are hashed directly — matching compute_file_hash() which reads
        # raw bytes from the working tree.  _git() uses text=True, which
        # applies universal-newline translation and would produce a
        # different hash for CRLF-committed files.
        try:
            show = subprocess.run(
                ["git", "show", f"HEAD:{rel}"],
                capture_output=True,
                text=False,
                timeout=_GIT_TIMEOUT,
                cwd=str(repo_root),
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            show = None
        if show and show.returncode == 0:
            committed_hash = hashlib.sha256(_norm_eol(show.stdout)).hexdigest()
            if committed_hash == current_hash:
                commit_sha = _current_commit(repo_root) or "HEAD"
                return (
                    "changed_in_commit",
                    "MEDIUM",
                    f"{path.name} changed in commit {commit_sha} — content hash differs "
                    f"from last approved baseline",
                )

    # ── Check 2: Uncommitted working-tree change? ────────────────────
    diff = _git(["diff", "--name-only", "HEAD", "--", rel], cwd=str(repo_root))
    if diff and diff.returncode == 0 and rel in diff.stdout:
        # Was this file written by a tool call earlier in THIS session?
        if session_log_dir and session_log_dir.is_dir():
            for log_file in sorted(
                session_log_dir.glob("*.json*"), reverse=True
            ):
                try:
                    content = log_file.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if str(path) in content and '"file_write"' in content:
                    return (
                        "agent_session_change",
                        "HIGH",
                        f"{path.name} was modified by an agent tool call in this session",
                    )
        return (
            "uncommitted_change",
            "MEDIUM",
            f"{path.name} has uncommitted changes since its last trust baseline",
        )

    return (
        "unclassified_change",
        "LOW",
        f"{path.name} changed — cannot determine how",
    )


def verify_memory_files(
    reads: List[Any],
    workspace: Path,
    session_log_dir: Optional[Path] = None,
    record: bool = True,
) -> List[dict]:
    """Core integrity check for auto-loaded instruction files.

    For each entry in *reads* (a list of ``(path_str, hash)`` tuples or
    ``MemoryRead``-like objects):

    1. Compute SHA-256 if not already provided.
    2. If first-seen → TOFU: record baseline, mode=trusted, no finding
       (``record=False`` is the read-only mode: nothing is written, and a
       never-trusted file is reported as having no baseline).
    3. If hash matches trust store → no finding.
    4. If mismatch → classify change origin, emit a ``memory_integrity`` finding.

    Returns a list of findings (empty when clean). Never raises — all errors
    degrade to ``unable_to_verify``, not a crash.
    """
    findings: List[dict] = []
    store = load_trust_store(workspace)
    store_modified = False

    for read in reads:
        # Normalise the input — accepts tuples, dicts, and objects.
        if isinstance(read, tuple):
            raw_path, current_hash = read[0], read[1] if len(read) > 1 else None
        elif isinstance(read, dict):
            raw_path = read.get("path") or read.get("file_path", "")
            current_hash = read.get("hash")
        elif hasattr(read, "path"):
            raw_path = read.path
            current_hash = getattr(read, "hash", None)
        elif hasattr(read, "file_path"):
            raw_path = read.file_path
            current_hash = getattr(read, "hash", None)
        else:
            raw_path = str(read)
            current_hash = None

        try:
            file_path = Path(raw_path).resolve()
        except Exception:
            continue

        if not file_path.is_file():
            # File was deleted — clean up the entry.
            key = str(file_path)
            if key in store["files"]:
                del store["files"][key]
                store_modified = True
            findings.append({
                "ruleId": "memory-integrity-mismatch",
                "severity": "LOW",
                "category": "memory_integrity",
                "title": f"{file_path.name} was removed — entry cleaned up",
                "evidence": {"path": str(file_path), "origin": "file_removed"},
                "action": "warn",
            })
            continue

        final_hash = current_hash or compute_file_hash(file_path)
        if not final_hash:
            findings.append({
                "ruleId": "memory-integrity-mismatch",
                "severity": "LOW",
                "category": "memory_integrity",
                "title": f"Cannot hash {file_path.name}",
                "evidence": {"path": str(file_path), "origin": "unable_to_verify"},
                "action": "warn",
            })
            continue

        stored = store["files"].get(str(file_path))

        if stored is None and not record:
            findings.append({
                "ruleId": "memory-integrity-mismatch",
                "severity": "LOW",
                "category": "memory_integrity",
                "title": f"{file_path.name} has no trust baseline — run `prismor memory trust {file_path}` after reviewing it",
                "evidence": {"path": str(file_path), "origin": "no_baseline"},
                "action": "warn",
            })
            continue

        if stored is None:
            # ── TOFU: first time seeing this file ──────────────────
            now = datetime.now(timezone.utc).isoformat()
            repo_root = _resolve_repo_root(workspace)
            commit = _current_commit(repo_root) if repo_root else None

            store["files"][str(file_path)] = {
                "sha256": final_hash,
                "first_seen_at": now,
                "first_seen_commit": commit,
                "last_approved_at": now,
                "last_approved_commit": commit,
                "mode": "trusted",
                "signing_key_id": None,
            }
            store_modified = True

            short_hash = final_hash[:8]
            sys.stderr.write(
                f"prismor: first time seeing {file_path.name} — "
                f"recording baseline sha256:{short_hash}... [trusted]\n"
            )
            sys.stderr.write(
                f"         verify out-of-band: {hash_hint(file_path)}\n"
            )
            continue

        if stored.get("sha256") in (final_hash, compute_file_hash(file_path, False)):
            # Match (normalised or legacy raw-bytes hash) — no finding.
            continue

        # ── Hash mismatch — classify the change origin ──────────────
        origin, severity, message = _classify_change(
            file_path, final_hash, stored, session_log_dir
        )

        if stored.get("mode") == "signed":
            # A signed file changing is a tamper, whatever git says about it.
            severity, message = "HIGH", f"signed file {message}"
        findings.append({
            "ruleId": "memory-integrity-mismatch",
            "severity": severity,
            "category": "memory_integrity",
            "title": message,
            "evidence": {
                "path": str(file_path),
                "origin": origin,
                "stored_hash": stored.get("sha256", "")[:8],
                "current_hash": final_hash[:8],
            },
            "action": "warn",
        })

    if store_modified:
        _save_trust_store(store, workspace)

    return findings


# ── CLI-facing helpers ────────────────────────────────────────────────────


def trust_memory_file(path: Path, workspace: Path) -> None:
    """Record a TOFU baseline for ``path`` — first-time trust only."""
    store = load_trust_store(workspace)
    key = str(path.resolve())
    current_hash = compute_file_hash(path)
    if not current_hash:
        raise SystemExit(f"prismor memory trust: cannot hash {path}")
    now = datetime.now(timezone.utc).isoformat()
    repo_root = _resolve_repo_root(workspace)
    commit = _current_commit(repo_root) if repo_root else None
    store["files"][key] = {
        "sha256": current_hash,
        "first_seen_at": now,
        "first_seen_commit": commit,
        "last_approved_at": now,
        "last_approved_commit": commit,
        "mode": "trusted",
        "signing_key_id": None,
    }
    _save_trust_store(store, workspace)


def approve_memory_file(path: Path, workspace: Path) -> None:
    """Re-baseline ``path`` after a reviewed change — updates stored hash."""
    store = load_trust_store(workspace)
    key = str(path.resolve())
    current_hash = compute_file_hash(path)
    if not current_hash:
        raise SystemExit(f"prismor memory approve: cannot hash {path}")
    now = datetime.now(timezone.utc).isoformat()
    repo_root = _resolve_repo_root(workspace)
    commit = _current_commit(repo_root) if repo_root else None
    existing = store["files"].get(key, {})
    store["files"][key] = {
        "sha256": current_hash,
        "first_seen_at": existing.get("first_seen_at", now),
        "first_seen_commit": existing.get("first_seen_commit", commit),
        "last_approved_at": now,
        "last_approved_commit": commit,
        "mode": "trusted",
        "signing_key_id": existing.get("signing_key_id"),
    }
    _save_trust_store(store, workspace)


def sign_memory_file(path: Path, key_path: Path, workspace: Path) -> None:
    """Ed25519-sign ``path`` and record the signature in the trust store.

    Requires ``PRISMOR_MEMORY_SIGNED_MODE=1`` in the environment.
    The caller is responsible for gating this behind the env var.
    """
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError:
        sys.stderr.write(
            "prismor memory sign: requires `cryptography` package. "
            "Install with: pip install cryptography\n"
        )
        raise SystemExit(1)

    try:
        key_bytes = key_path.read_bytes()
        private_key = Ed25519PrivateKey.from_private_bytes(key_bytes)
        file_bytes = path.read_bytes()
        signature = private_key.sign(file_bytes)
        pubkey_raw = private_key.public_key().public_bytes_raw()
    except Exception as e:
        sys.stderr.write(f"prismor memory sign: {e}\n")
        raise SystemExit(1)

    import base64
    store = load_trust_store(workspace)
    key = str(path.resolve())
    current_hash = compute_file_hash(path)
    now = datetime.now(timezone.utc).isoformat()

    repo_root = _resolve_repo_root(workspace)
    commit = _current_commit(repo_root) if repo_root else None
    store["signing"]["enabled"] = True
    store["signing"]["public_keys"][key] = base64.b64encode(pubkey_raw).decode("ascii")
    store["files"][key] = {
        "sha256": current_hash,
        "first_seen_at": now,
        "first_seen_commit": commit,
        "last_approved_at": now,
        "last_approved_commit": commit,
        "mode": "signed",
        "signing_key_id": key,
    }
    _save_trust_store(store, workspace)


def unsign_memory_file(path: Path, workspace: Path) -> None:
    """Remove the Ed25519 signature from ``path``'s trust entry — reverts to TOFU."""
    store = load_trust_store(workspace)
    key = str(path.resolve())
    if key in store["files"]:
        entry = store["files"][key]
        entry["mode"] = "trusted"
        entry["signing_key_id"] = None
        _save_trust_store(store, workspace)


def format_trust_status(workspace: Path) -> str:
    """Return a formatted table of the trust store for human consumption."""
    store = load_trust_store(workspace)
    lines = []
    lines.append("Trust Store")
    lines.append("=" * 80)
    if not store["files"]:
        lines.append("  (empty — no instruction files have been trusted yet)")
        return "\n".join(lines)
    lines.append(f"  {'FILE':<50} {'MODE':<10} {'SHA256':>12}")
    lines.append(f"  {'-'*48}  {'-'*8}  {'-'*10}")
    for path, entry in sorted(store["files"].items()):
        fname = Path(path).name if len(path) < 48 else "…" + path[-47:]
        mode = entry.get("mode", "trusted")
        sha_short = (entry.get("sha256") or "")[:8]
        lines.append(f"  {fname:<50} {mode:<10} {sha_short:>12}")
    lines.append("=" * 80)
    if store["signing"].get("enabled"):
        lines.append("  Signed mode: enabled")
    return "\n".join(lines)


# ── Content scan (prismor memory scan) ────────────────────────────────────

_B64_RUN_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{80,}={0,2}(?![A-Za-z0-9+/=])")


def _base64_text_blocks(text: str) -> List[str]:
    """Long base64 runs that decode to mostly printable text (a hidden
    payload). Binary blobs, hashes and data: URIs are not reported."""
    import base64
    out = []
    for m in _B64_RUN_RE.finditer(text):
        if text[max(0, m.start() - 8):m.start()].endswith("base64,"):
            continue
        run = m.group(0)
        try:
            raw = base64.b64decode(run + "=" * (-len(run) % 4), validate=True)
        except Exception:
            continue
        if len(raw) >= 40 and sum(32 <= b < 127 or b in (9, 10, 13) for b in raw) / len(raw) >= 0.9:
            out.append(raw[:60].decode("ascii", "replace"))
    return out


def scan_memory_text(engine: Any, path: str, text: str) -> List[dict]:
    """Findings for one instruction file's decoded text, the way SessionStart
    screens it (a ``memory`` event) plus the structural checks the hook feeds
    in as facts: invisible/bidi/tag characters and base64 payload blocks."""
    from prismor.runtime.hooks import strip_prismor_managed, _INVISIBLE_CONTROL_RE
    findings = engine.evaluate(
        {"type": "memory", "path": path, "content": strip_prismor_managed(text),
         "metadata": {"has_invisible_controls": bool(_INVISIBLE_CONTROL_RE.search(text))}}, 0)
    seen = {g.get("ruleId") for g in findings}
    findings += [f for f in engine.check_text(text) if f.get("ruleId") not in seen]
    for preview in _base64_text_blocks(text)[:3]:
        findings.append({
            "ruleId": "memory-encoded-payload", "severity": "MEDIUM", "category": "memory_poisoning",
            "title": "Instruction file contains a base64 block that decodes to text (possible hidden payload)",
            "evidence": f"decodes to: {preview!r}", "action": "warn",
        })
    return findings
