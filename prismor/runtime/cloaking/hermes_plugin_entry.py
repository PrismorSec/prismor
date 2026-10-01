"""Hermes Agent entry point / plugin module for Prismor cloaking.

This module serves TWO discovery modes with a single ``register()``
implementation:

1. **pip entry point** — when immunity-agent is pip-installed, Hermes
   discovers it via ``pyproject.toml``'s
   ``[project.entry-points."hermes_agent.plugins"]`` section. The entry
   point ``prismor-cloak`` points to
   ``prismor.runtime.cloaking.hermes_plugin_entry:register``.

2. **Filesystem plugin** — when installed via ``prismor cloak install
   --agent hermes``, the plugin directory is copied to
   ``~/.hermes/plugins/prismor-cloak/`` with its own
   ``plugin.yaml`` + ``__init__.py``. That ``__init__.py`` carries a
   verbatim copy of this module's code (enforced by
   tests/test_hermes_plugin_sync.py).

Both paths converge on the same hook registration logic below.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────────────────────────

_SECRET_PLACEHOLDER_RE = re.compile(r"@@SECRET:([a-zA-Z0-9_-]{1,64})@@")

# Built-in secret detection patterns (mirrors prismor/runtime/cloaking/builtin_patterns.txt)
_BUILTIN_PATTERNS: List[re.Pattern] = [
    re.compile(r"sk_live_[0-9a-zA-Z]{24,}"),            # Stripe live secret
    re.compile(r"sk_test_[0-9a-zA-Z]{24,}"),             # Stripe test secret
    re.compile(r"ghp_[0-9a-zA-Z]{36}"),                  # GitHub PAT
    re.compile(r"github_pat_[0-9a-zA-Z]{36,}"),          # GitHub fine-grained PAT
    re.compile(r"gho_[0-9a-zA-Z]{36}"),                   # GitHub OAuth
    re.compile(r"AKIA[0-9A-Z]{16}"),                     # AWS access key
    re.compile(r"AIza[0-9A-Za-z_-]{35}"),                # Google API key
    re.compile(r"sk-[0-9a-zA-Z]{20,}"),                  # OpenAI secret
    re.compile(r"xox[baprs]-[0-9a-zA-Z-]{10,}"),        # Slack token
    re.compile(r"glpat-[0-9a-zA-Z_-]{20,}"),             # GitLab PAT
    re.compile(r"[Bb]earer\s+[0-9a-zA-Z._-]{20,}"),      # Bearer token
    re.compile(r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+"),  # JWT
]

_VAULT_DIR = "auto_vault"
_ALLOW_BYPASS_PREFIX = "!!allow "


# ── Helpers ────────────────────────────────────────────────────────────────


def _secrets_dir() -> Path:
    """Resolve the secrets directory, honoring ``$PRISMOR_SECRETS_DIR``."""
    override = os.environ.get("PRISMOR_SECRETS_DIR")
    if override:
        return Path(override).expanduser()
    home = os.environ.get("PRISMOR_HOME", str(Path.home() / ".prismor"))
    return Path(home) / "secrets"


def _read_secret(name: str) -> Optional[str]:
    """Read a secret value by placeholder name. Returns None if missing.

    Searches the root secrets dir first, then falls back to the
    auto_vault subdirectory so paste-guard-auto-vaulted secrets
    (stored under auto_vault/auto_*) are resolvable by name.
    """
    for base in (_secrets_dir(), _vault_path()):
        try:
            path = base / name
            if path.exists() and path.is_file():
                return path.read_text(encoding="utf-8").strip()
        except Exception:
            continue
    return None


def _vault_path() -> Path:
    """Path to the auto-vault directory within secrets dir."""
    return _secrets_dir() / _VAULT_DIR


def _hash_value(value: str) -> str:
    """Deterministic hash for auto-vault naming."""
    return hashlib.sha256(value.encode()).hexdigest()[:12]


def _vault_secret(value: str) -> str:
    """Vault a raw secret value under a deterministic auto_<hash> name.

    Returns the placeholder name to use (e.g. ``auto_<hash>``).
    If the value is already vaulted, returns the existing name.
    """
    h = _hash_value(value)
    vault_dir = _vault_path()
    vault_dir.mkdir(parents=True, exist_ok=True)
    try:
        vault_dir.chmod(0o700)
    except PermissionError:
        pass

    name = f"auto_{h}"
    path = vault_dir / name

    if path.exists():
        return name

    path.write_text(value, encoding="utf-8")
    try:
        path.chmod(0o600)
    except PermissionError:
        pass
    return name


def _is_already_vaulted(value: str) -> Optional[str]:
    """Check if a secret value is already in the vault.

    Returns the placeholder name if found, None otherwise.
    """
    vault_dir = _vault_path()
    if not vault_dir.exists():
        return None
    h = _hash_value(value)
    candidate = vault_dir / f"auto_{h}"
    if candidate.exists():
        return f"auto_{h}"

    for f in vault_dir.iterdir():
        if f.is_file():
            try:
                if f.read_text(encoding="utf-8").strip() == value:
                    return f.name
            except Exception:
                continue
    return None


def _scan_for_raw_secrets(text: str) -> List[str]:
    """Scan text for known secret patterns. Returns list of matched values."""
    matches = []
    for pat in _BUILTIN_PATTERNS:
        for m in pat.finditer(text):
            matches.append(m.group(0))
    return matches


def _is_scrubbable_secret(value: str) -> bool:
    """Whether a raw secret value is distinctive enough to mask by substring
    without false positives. Eligible if >= 16 chars, or >= 8 chars AND carrying
    a digit, a symbol, or mixed case. A short single-case word collides with
    ordinary text and is skipped. Mirrors is_scrubbable_secret() in runtime.py.
    """
    n = len(value or "")
    if n < 8:
        return False
    if n >= 16:
        return True
    return (
        any(c.isdigit() for c in value)
        or any(not c.isalnum() for c in value)
        or (any(c.isupper() for c in value) and any(c.islower() for c in value))
    )


def _scrub_secrets(text: str) -> str:
    """Replace known secret values in text with ``@@SECRET:name@@`` placeholders."""
    sdir = _secrets_dir()
    if not sdir.exists():
        return text

    value_to_name: Dict[str, str] = {}

    # 1. Auto-vault entries
    vault_dir = sdir / _VAULT_DIR
    if vault_dir.exists():
        for f in vault_dir.iterdir():
            if f.is_file():
                try:
                    value_to_name[f.read_text(encoding="utf-8").strip()] = (
                        f"@@SECRET:{f.name}@@"
                    )
                except Exception:
                    continue

    # 2. Registered secrets
    for f in sdir.iterdir():
        if f.is_file() and f.parent.name != _VAULT_DIR:
            try:
                value_to_name[f.read_text(encoding="utf-8").strip()] = (
                    f"@@SECRET:{f.name}@@"
                )
            except Exception:
                continue

    result = text
    for value, placeholder in sorted(
        value_to_name.items(), key=lambda x: -len(x[0])
    ):
        if value and value in result and _is_scrubbable_secret(value):
            result = result.replace(value, placeholder)
    return result


# ── Hook Handlers ──────────────────────────────────────────────────────────


def on_pre_tool_call(
    tool_name: str,
    args: Dict[str, Any],
    task_id: str = "",
    session_id: str = "",
    tool_call_id: str = "",
) -> Optional[Dict[str, Any]]:
    """Pre-tool-call hook: handle secret placeholders and raw secret detection."""
    search_text = json.dumps(args) if args else ""

    if not search_text:
        return None

    # Phase 1: Resolve @@SECRET:name@@ placeholders
    placeholder_matches = _SECRET_PLACEHOLDER_RE.findall(search_text)
    if placeholder_matches:
        env_vars = {}
        for name in placeholder_matches:
            value = _read_secret(name)
            if value is not None:
                env_key = f"PRISMOR_SECRET_VALUE_{name.upper()}"
                env_vars[env_key] = value
            else:
                logger.warning(
                    "Secret '%s' referenced but not found in %s",
                    name, _secrets_dir(),
                )
                return {
                    "action": "block",
                    "message": (
                        f"Secret @@SECRET:{name}@@ is not registered. "
                        f"Register it with: prismor cloak add {name}"
                    ),
                }

        if env_vars:
            return {
                "action": "decloak",
                "env": env_vars,
                "placeholders": {
                    name: env_vars[f"PRISMOR_SECRET_VALUE_{name.upper()}"]
                    for name in placeholder_matches
                    if f"PRISMOR_SECRET_VALUE_{name.upper()}" in env_vars
                },
            }

    # Phase 2: Raw secret detection - always block, regardless of vault state.
    # If already vaulted we surface the *existing* placeholder name so the agent
    # learns the canonical reference rather than getting a second auto_ name.
    raw_matches = _scan_for_raw_secrets(search_text)
    for value in raw_matches:
        existing = _is_already_vaulted(value)
        placeholder_name = existing if existing else _vault_secret(value)
        if not existing:
            logger.info(
                "Vaulted raw secret under auto_%s (tool=%s, session=%s)",
                placeholder_name, tool_name, session_id,
            )
        return {
            "action": "block",
            "message": (
                f"Raw secret detected in tool call. "
                f"Use @@SECRET:{placeholder_name}@@ instead."
            ),
        }

    return None


def on_post_tool_call(
    tool_name: str,
    args: Dict[str, Any],
    result: str,
    task_id: str = "",
    session_id: str = "",
    tool_call_id: str = "",
    duration_ms: int = 0,
) -> None:
    """Post-tool-call hook: observational audit log (currently a no-op)."""
    pass


def on_transform_terminal_output(
    command: str,
    output: str,
    returncode: int,
    task_id: str = "",
    env_type: str = "",
) -> Optional[str]:
    """Transform terminal output: scrub secret values before they reach context."""
    scrubbed = _scrub_secrets(output)
    if scrubbed != output:
        return scrubbed
    return None


def on_transform_tool_result(
    tool_name: str,
    args: Dict[str, Any],
    result: str,
    task_id: str = "",
    session_id: str = "",
    tool_call_id: str = "",
    duration_ms: int = 0,
) -> Optional[str]:
    """Transform tool result: scrub secret values from non-terminal tool output."""
    scrubbed = _scrub_secrets(result)
    if scrubbed != result:
        return scrubbed
    return None


def on_pre_gateway_dispatch(
    event: Any,
    gateway: Any,
    session_store: Any,
) -> Optional[Dict[str, Any]]:
    """Pre-gateway dispatch: detect and auto-cloak pasted secrets."""
    try:
        text = getattr(event, "text", "") or ""
    except Exception:
        return None

    if not text or not isinstance(text, str):
        return None

    if text.startswith(_ALLOW_BYPASS_PREFIX):
        return {"action": "rewrite", "text": text[len(_ALLOW_BYPASS_PREFIX):]}

    raw_matches = _scan_for_raw_secrets(text)
    if not raw_matches:
        return None

    redacted_text = text
    for value in raw_matches:
        existing = _is_already_vaulted(value)
        placeholder_name = existing if existing else _vault_secret(value)
        placeholder = f"@@SECRET:{placeholder_name}@@"
        redacted_text = redacted_text.replace(value, placeholder)
        logger.info(
            "Auto-cloaked raw secret as %s in gateway message",
            placeholder,
        )

    return {
        "action": "skip",
        "reason": (
            f"Raw secret detected and auto-cloaked. "
            f"Use the placeholder form, or prefix with "
            f"'!!allow ' to bypass: {redacted_text}"
        ),
    }


# ── Plugin Registration ────────────────────────────────────────────────────


def register(ctx) -> None:
    """Register all cloaking hooks with the Hermes plugin system."""
    ctx.register_hook("pre_tool_call", on_pre_tool_call)
    ctx.register_hook("post_tool_call", on_post_tool_call)
    ctx.register_hook("transform_terminal_output", on_transform_terminal_output)
    ctx.register_hook("transform_tool_result", on_transform_tool_result)
    ctx.register_hook("pre_gateway_dispatch", on_pre_gateway_dispatch)

    logger.info(
        "Prismor cloak plugin registered: "
        "pre_tool_call, post_tool_call, transform_terminal_output, "
        "transform_tool_result, pre_gateway_dispatch"
    )
