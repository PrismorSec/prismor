#!/usr/bin/env python3
"""OSS-safety guard for the public Prismor runtime repo.

Prismor is open-core: the runtime + adapters + rule format are public, while the
control plane, the Ed25519 signing **private key**, and the curated premium
threat feed stay proprietary. A single accidental commit of the private key or a
secret would collapse the signing moat — so this guard fails the build if any
must-never-ship material is tracked in the public repo.

It scans the set of git-tracked files (or an explicit list) for:
  * private key material (PEM private-key headers, *.pem / *.key files)
  * obvious cloud/credential secrets (AWS keys, generic API tokens)
  * an explicit path denylist (e.g. keys/private.pem, the signing key env)

Exit code 0 = clean, 1 = a violation was found (CI fails). Zero third-party
dependencies — stdlib only — so it runs anywhere, including as a pre-commit hook.

Usage:
    python3 scripts/check_oss_safe.py            # scan all git-tracked files
    python3 scripts/check_oss_safe.py a.py b.txt # scan an explicit list
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path
from typing import Iterable, List, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent

# Paths that must NEVER be tracked in the public repo. Globs, repo-relative.
PATH_DENYLIST = [
    "keys/private.pem",
    "**/*.pem",          # private keys; public key is keys/public.pub (.pub, allowed)
    "**/*.key",
    "**/id_rsa",
    "**/id_ed25519",
    ".env",
    "**/.env",
]

# Files that are allowed to match a denylist glob (the intentional exceptions).
PATH_ALLOWLIST = {
    "keys/public.pub",   # the verify-only public key is meant to ship
}

# Files exempt from CONTENT-signature scanning because they legitimately contain
# key-shaped or secret-shaped material that is fake by design. Each is an
# explicit, reviewed exception — keep this list short and justified.
CONTENT_ALLOWLIST = {
    "prismor/runtime/canary.py",                 # honeytoken templates: a *fake* SSH key + AWS key planted as bait
    "tests/test_cloak_secret_guard.py", # secret-detection tests: AWS example key + dummy ghp_ token fixtures
    "tests/test_oss_guard.py",          # this guard's own tests embed a fake PEM + AWS example key as fixtures
    "tests/test_cloak_env_guard.py",    # env-guard tests: a planted sk-live-CANARY key the guard must catch
    # inventory fixtures: ghp_CANARY tokens the redaction tests prove never reach output
    "tests/fixtures/inventory/windows-dev/profiles/alice/AppData/Local/github-copilot/intellij/mcp.json",
    "tests/fixtures/inventory/windows-dev/profiles/alice/AppData/Roaming/JetBrains/IntelliJIdea2026.2/options/llm.mcpServers.xml",
}

# Content signatures of secret material. (label, compiled regex)
CONTENT_SIGNATURES: List[Tuple[str, "re.Pattern[str]"]] = [
    ("PEM private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("AWS access key id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("AWS secret access key", re.compile(r"aws_secret_access_key\s*=\s*[A-Za-z0-9/+]{40}")),
    ("GitHub token", re.compile(r"\bghp_[A-Za-z0-9]{36}\b")),
    ("Generic bearer secret", re.compile(r"(?i)(?:secret|token|password|api[_-]?key)\s*[:=]\s*['\"][A-Za-z0-9/+_\-]{24,}['\"]")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
]

# Don't scan obvious binary/asset blobs for content signatures (they false-positive
# and are slow); path rules still apply to them.
SKIP_CONTENT_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".mp4", ".pdf", ".ico", ".woff", ".woff2", ".zip", ".gz"}

# This guard file itself contains the signatures it looks for — never flag it.
SELF = "scripts/check_oss_safe.py"


def _tracked_files() -> List[str]:
    out = subprocess.run(
        ["git", "ls-files"], cwd=REPO_ROOT, capture_output=True, text=True, check=True
    )
    return [line for line in out.stdout.splitlines() if line.strip()]


def _path_violations(rel_paths: Iterable[str]) -> List[str]:
    problems: List[str] = []
    for rel in rel_paths:
        if rel in PATH_ALLOWLIST:
            continue
        p = Path(rel)
        for pattern in PATH_DENYLIST:
            if p.match(pattern):
                problems.append(f"  [path]    {rel}  (matches denylisted pattern '{pattern}')")
                break
    return problems


def _content_violations(rel_paths: Iterable[str]) -> List[str]:
    problems: List[str] = []
    for rel in rel_paths:
        if rel == SELF or rel in CONTENT_ALLOWLIST:
            continue
        if Path(rel).suffix.lower() in SKIP_CONTENT_SUFFIXES:
            continue
        fpath = REPO_ROOT / rel
        try:
            text = fpath.read_text(encoding="utf-8", errors="ignore")
        except (OSError, UnicodeError):
            continue
        for label, rx in CONTENT_SIGNATURES:
            if rx.search(text):
                problems.append(f"  [content] {rel}  (looks like: {label})")
    return problems


def scan(paths: List[str]) -> List[str]:
    rel_paths = paths or _tracked_files()
    return _path_violations(rel_paths) + _content_violations(rel_paths)


def main(argv: List[str]) -> int:
    problems = scan(argv)
    if problems:
        sys.stderr.write(
            "OSS-safety guard FAILED — these must never ship in the public repo:\n"
            + "\n".join(problems)
            + "\n\nRemove them (and rotate any exposed secret). The private signing "
            "key, secrets, and the premium feed belong only in the private repos.\n"
        )
        return 1
    print(f"OSS-safety guard passed — scanned {len(argv or _tracked_files())} files, no leaks.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
