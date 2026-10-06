"""Runtime helpers for Prismor cloaking.

Codex hooks are currently block-only: they can deny a tool call, but they
cannot rewrite Bash input or scrub Bash output the way Claude cloaking hooks can.
This module keeps that limitation explicit and provides a Prismor-owned runner
for commands that need local placeholder resolution.
"""
from __future__ import annotations

import os
import re
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from prismor.runtime.cloaking.secrets_store import secrets_dir

# Escape form: a backslash before the colon (``@@SECRET\:name@@``) is not a
# valid placeholder — names may not contain a backslash — so the regex skips it
# and no substitution touches it. This is how docs, commit messages, and test
# fixtures write the literal placeholder syntax without tripping the guard.
_PLACEHOLDER_RE = re.compile(r"@@SECRET:([a-zA-Z0-9_-]{1,64})@@")
_ENV_ASSIGNMENT_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$")

_READER_UTILS = frozenset({
    "cat", "bat", "less", "more", "head", "tail", "grep", "egrep", "fgrep",
    "rg", "ag", "base64", "xxd", "od", "hexdump", "strings", "nl", "tac",
    "sort", "uniq", "awk", "sed", "cut", "source", ".",
})


def placeholder_names(text: str) -> List[str]:
    """Return unique placeholder names in encounter order."""
    seen = set()
    out: List[str] = []
    for match in _PLACEHOLDER_RE.finditer(text or ""):
        name = match.group(1)
        if name not in seen:
            seen.add(name)
            out.append(name)
    return out


#: (directory, per-file (name, mtime_ns, size) signature) -> secret map. Masking
#: reads the map once per *string*, and a model request holds dozens: re-reading
#: every secret file each time cost ~4ms a string, a few hundred ms in front of
#: every proxied turn. The signature is re-taken on every call, so an added,
#: rewritten or removed secret is seen on the very next read -- never stale.
_SECRET_MAP_CACHE: Dict[str, Any] = {}


def _read_secret_map() -> Dict[str, str]:
    sdir = secrets_dir()
    if not sdir.is_dir():
        return {}
    try:
        entries = sorted((e for e in os.scandir(sdir) if e.is_file()), key=lambda e: e.name)
        signature = tuple((e.name, e.stat().st_mtime_ns, e.stat().st_size) for e in entries)
    except OSError:
        signature = None
    cached = _SECRET_MAP_CACHE.get(str(sdir))
    if signature is not None and cached and cached[0] == signature:
        return dict(cached[1])
    values: Dict[str, str] = {}
    for child in sorted(sdir.iterdir()):
        if not child.is_file():
            continue
        try:
            values[child.name] = child.read_text(encoding="utf-8")
        except OSError:
            continue
    if signature is not None:
        _SECRET_MAP_CACHE[str(sdir)] = (signature, dict(values))
    return values


def decloak_text(text: str, *, secrets: Optional[Dict[str, str]] = None) -> str:
    """Replace registered placeholders with their secret values.

    Raises ``KeyError`` if the text references an unknown placeholder. The
    caller should fail closed rather than letting a literal placeholder execute.
    """
    secrets = _read_secret_map() if secrets is None else secrets

    def repl(match: re.Match[str]) -> str:
        name = match.group(1)
        if name not in secrets:
            raise KeyError(name)
        return secrets[name]

    return _PLACEHOLDER_RE.sub(repl, text)


# Minimum length before a raw secret value is eligible for substring masking.
# The scrubbers/read-guard replace a value wherever it appears as a SUBSTRING,
# so short or low-entropy values collide with ordinary source and prose — a
# 4-char value blocked reads of 20+ project source files and mangled command
# output. Keep this in sync with the Bash `_prismor_scrubbable` helper in
# cloaking/hooks/*.sh.
_MIN_SCRUB_LEN = 8


def is_scrubbable_secret(value: str) -> bool:
    """Whether a registered secret VALUE is distinctive enough to mask by raw
    substring match without unacceptable false positives.

    A value is eligible when it is either long (>= 16 chars — realistic tokens)
    or short-but-distinctive: it carries a digit, a symbol, or mixed case. A
    short, single-case, all-alphabetic value (a dictionary word, a common
    identifier) is NOT masked, because substring-matching it corrupts unrelated
    text. Realistic API keys/tokens satisfy the shape check; only genuinely
    weak, word-like secrets are skipped.
    """
    v = value or ""
    n = len(v)
    if n < _MIN_SCRUB_LEN:
        return False
    if n >= 16:
        return True
    has_digit = any(c.isdigit() for c in v)
    has_symbol = any(not c.isalnum() for c in v)
    has_mixed_case = any(c.isupper() for c in v) and any(c.islower() for c in v)
    return has_digit or has_symbol or has_mixed_case


def scrub_text(text: str, *, secrets: Optional[Dict[str, str]] = None) -> str:
    """Replace registered raw secret values with placeholders."""
    secrets = _read_secret_map() if secrets is None else secrets
    out = text
    for name, value in sorted(secrets.items(), key=lambda item: len(item[1]), reverse=True):
        if is_scrubbable_secret(value):
            out = out.replace(value, f"@@SECRET:{name}@@")
    return out


def _split_env_assignments(args: List[str]) -> tuple[Dict[str, str], List[str]]:
    """Split leading shell-style env assignments from the command argv."""
    env_updates: Dict[str, str] = {}
    index = 0
    for arg in args:
        match = _ENV_ASSIGNMENT_RE.fullmatch(arg)
        if not match:
            break
        env_updates[match.group(1)] = match.group(2)
        index += 1
    return env_updates, args[index:]


def codex_cloak_finding(event: Dict[str, Any], session_id: str) -> Optional[Dict[str, Any]]:
    """Return a blocking finding for Codex cloak limitations, if applicable."""
    if event.get("type") != "shell":
        return None
    command = str(event.get("command") or "")
    if not command.strip():
        return None

    names = placeholder_names(command)
    if names:
        missing = [name for name in names if not (secrets_dir() / name).is_file()]
        if missing:
            reason = (
                "Codex cannot execute cloaked placeholders directly, and "
                f"{', '.join('@@SECRET:' + name + '@@' for name in missing)} "
                "is not registered."
            )
            remediation = f"Register it first with: prismor cloak add {missing[0]}"
        else:
            reason = (
                "Codex hooks cannot rewrite Bash commands or scrub Bash output. "
                "Executing this command would send the literal placeholder "
                f"{', '.join('@@SECRET:' + name + '@@' for name in names)} "
                "to the downstream process."
            )
            remediation = "Run it through Prismor instead: prismor cloak run -- <command>"
        return _finding(session_id, reason, remediation, "codex-cloak-placeholder")

    read_reason = _codex_secret_read_reason(event)
    if read_reason:
        return _finding(
            session_id,
            read_reason,
            "Use a placeholder with: prismor cloak run -- <command>",
            "codex-cloak-read-guard",
        )
    return None


def _finding(session_id: str, evidence: str, remediation: str, suffix: str) -> Dict[str, Any]:
    return {
        "id": f"{session_id}:{suffix}",
        "ruleId": suffix,
        "severity": "HIGH",
        "category": "secret_exfiltration",
        "title": "Codex cannot safely auto-decloak this command",
        "evidence": evidence,
        "remediation": remediation,
        "action": "block",
        "mode": "enforce",
    }


def _codex_secret_read_reason(event: Dict[str, Any]) -> Optional[str]:
    """Deny reason if a Codex Bash command would print a registered secret."""
    try:
        secrets = {k: v.strip() for k, v in _read_secret_map().items() if len(v.strip()) >= 8}
        if not secrets:
            return None
        command = str(event.get("command") or "")
        try:
            tokens = shlex.split(command, comments=False, posix=True)
        except ValueError:
            tokens = command.split()
        cleaned = [t.strip(";|&<>()`'\" ") for t in tokens]
        uses_reader = any(
            os.path.basename(t) in _READER_UTILS for t in cleaned if t and not t.startswith("-")
        )
        if not uses_reader and "<" not in tokens:
            return None
        cwd = (event.get("metadata") or {}).get("cwd") or os.getcwd()
        for tok in cleaned:
            if not tok:
                continue
            cand = Path(tok) if os.path.isabs(tok) else Path(cwd) / tok
            if not cand.is_file():
                continue
            try:
                content = cand.read_text(encoding="utf-8", errors="ignore")[:1_000_000]
            except OSError:
                continue
            for name, value in secrets.items():
                if value in content:
                    return (
                        f"'{tok}' contains the registered secret '{name}'. Codex cannot "
                        "scrub shell output, so reading it would place the raw value in "
                        "model context."
                    )
    except Exception:
        return None
    return None


def run_decloaked_command(argv: Iterable[str]) -> int:
    """Run a command with placeholders resolved locally and output scrubbed."""
    args = list(argv)
    if args and args[0] == "--":
        args = args[1:]
    if not args:
        raise ValueError("Usage: prismor cloak run -- <command> [args...]")
    secrets = _read_secret_map()
    env_updates, command_args = _split_env_assignments(args)
    if not command_args:
        raise ValueError("Usage: prismor cloak run -- <command> [args...]")
    try:
        resolved_env = {
            name: decloak_text(value, secrets=secrets) for name, value in env_updates.items()
        }
        resolved = [decloak_text(arg, secrets=secrets) for arg in command_args]
    except KeyError as exc:
        name = str(exc).strip("'")
        raise ValueError(
            f"Prismor cloaking: secret '{name}' is not registered. "
            f"Run: prismor cloak add {name} (list registered names: prismor cloak list). "
            f"To write the literal placeholder syntax instead of resolving it, "
            f"escape the colon: @@SECRET\\:{name}@@"
        ) from exc

    env = os.environ.copy()
    env.update(resolved_env)
    proc = subprocess.run(
        resolved,
        capture_output=True,
        text=True,
        errors="replace",
        check=False,
        env=env,
    )
    if proc.stdout:
        sys.stdout.write(scrub_text(proc.stdout, secrets=secrets))
    if proc.stderr:
        sys.stderr.write(scrub_text(proc.stderr, secrets=secrets))
    return int(proc.returncode)
