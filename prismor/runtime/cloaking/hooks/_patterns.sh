#!/usr/bin/env bash
# Prismor — shared cloaking helpers, sourced by the hook scripts.
#
# Provides:
#   prismor_load_patterns       Populate the global PATTERNS array from the
#                               built-in pattern file plus the user's custom
#                               pattern file (if any).
#   prismor_value_is_cloaked    Return 0 if a value already exists verbatim in
#                               the secrets vault (so legitimately decloaked
#                               values are never re-flagged).
#
# Pure bash, no external deps beyond coreutils. Sourced — does not run on its
# own. Callers must have `set -uo pipefail` already in effect.

# Resolve this file's directory so we can find builtin_patterns.txt regardless
# of the caller's CWD.
_PRISMOR_HOOKS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_PRISMOR_BUILTIN_PATTERNS="$_PRISMOR_HOOKS_DIR/../builtin_patterns.txt"

# Where custom (org-specific) patterns live. Overridable for testing.
prismor_custom_patterns_file() {
  if [[ -n "${PRISMOR_CLOAK_PATTERNS:-}" ]]; then
    printf '%s' "$PRISMOR_CLOAK_PATTERNS"
  else
    printf '%s' "${PRISMOR_HOME:-$HOME/.prismor}/cloak_patterns.txt"
  fi
}

# Patterns pushed by the org's signed policy; written by the Python runtime on
# policy refresh (cloaking/patterns.py: write_org_patterns). Deliberately not
# env-overridable - it only ever comes from a verified policy.
prismor_org_patterns_file() {
  printf '%s' "${PRISMOR_HOME:-$HOME/.prismor}/cloak_patterns.org.txt"
}

prismor_secrets_dir() {
  if [[ -n "${PRISMOR_SECRETS_DIR:-}" ]]; then
    printf '%s' "$PRISMOR_SECRETS_DIR"
  else
    printf '%s' "${PRISMOR_HOME:-$HOME/.prismor}/secrets"
  fi
}

# Populate the global `PATTERNS` array. Built-ins first (most specific),
# then user patterns, then org-pushed patterns appended. Comment (`#`) and blank lines are skipped.
prismor_load_patterns() {
  PATTERNS=()
  local file line
  for file in "$_PRISMOR_BUILTIN_PATTERNS" "$(prismor_custom_patterns_file)" "$(prismor_org_patterns_file)"; do
    [[ -f "$file" ]] || continue
    while IFS= read -r line || [[ -n "$line" ]]; do
      # Strip nothing — patterns may contain leading spaces only if intended;
      # but skip blank and comment lines.
      [[ -z "${line//[[:space:]]/}" ]] && continue
      [[ "${line#"${line%%[![:space:]]*}"}" == \#* ]] && continue
      PATTERNS+=("$line")
    done < "$file"
  done
}

# prismor_value_is_cloaked <value>
# Returns 0 if any file in the secrets vault contains exactly <value>.
# Used so that a value decloak.sh just substituted in (placeholder -> real),
# or any manually-registered secret, is recognized as already-cloaked and is
# NOT treated as a fresh leak.
prismor_value_is_cloaked() {
  local value="$1" dir f
  dir="$(prismor_secrets_dir)"
  [[ -d "$dir" ]] || return 1
  for f in "$dir"/*; do
    [[ -f "$f" ]] || continue
    if [[ "$(<"$f")" == "$value" ]]; then
      return 0
    fi
  done
  return 1
}

# prismor_scrubbable <value>
# Returns 0 if a raw secret value is distinctive enough to match by substring
# without false positives. Mirrors is_scrubbable_secret() in ../runtime.py:
# eligible if >= 16 chars, or >= 8 chars AND carrying a digit, a symbol, or
# mixed case. A short single-case word (e.g. a 4-char value) collides with
# ordinary source/prose and is skipped so it never wrongly blocks a read.
prismor_scrubbable() {
  local v="$1" n=${#1}
  (( n >= 8 )) || return 1
  [[ "$v" =~ ^[A-Za-z][A-Za-z0-9+.-]*://[A-Za-z0-9.-]+(:[0-9]+)?/?$ ]] && return 1  # bare origin (#930)
  (( n >= 16 )) && return 0
  [[ "$v" == *[[:digit:]]* ]] && return 0
  [[ "$v" == *[![:alnum:]]* ]] && return 0
  [[ "$v" == *[[:lower:]]* && "$v" == *[[:upper:]]* ]] && return 0
  return 1
}

# prismor_find_matches <text>
# Unique pattern matches in <text>, one per line. One grep over every pattern:
# the old per-pattern loop forked grep ~90 times, 25+ s on Git Bash for Windows.
# If grep rejects the combined set (one bad custom pattern) fall back to
# per-pattern runs so the good patterns still work.
prismor_find_matches() {
  local text="$1" pat out rc args=()
  for pat in "${PATTERNS[@]}"; do args+=(-e "$pat"); done
  out="$(printf '%s' "$text" | LC_ALL=C grep -oE "${args[@]}" 2>/dev/null)"; rc=$?
  if (( rc >= 2 )); then
    out="$(for pat in "${PATTERNS[@]}"; do printf '%s' "$text" | LC_ALL=C grep -oE -e "$pat" 2>/dev/null || true; done)"
  fi
  printf '%s\n' "$out" | awk 'NF && !seen[$0]++'
}

# prismor_sha8 <value> — first 8 hex of sha256. Git Bash has no shasum; try each
# tool, then python. Prints nothing and returns 1 if none works: the caller must
# fail loudly, never name a vault entry from an empty hash.
prismor_sha8() {
  local h=""
  if command -v sha256sum >/dev/null 2>&1; then h="$(printf '%s' "$1" | sha256sum | cut -c1-8)"
  elif command -v shasum >/dev/null 2>&1; then h="$(printf '%s' "$1" | shasum -a 256 | cut -c1-8)"
  elif command -v openssl >/dev/null 2>&1; then h="$(printf '%s' "$1" | openssl dgst -sha256 | sed 's/.*= *//' | cut -c1-8)"
  else
    local py; py="$(command -v python3 || command -v python || command -v py)"
    [[ -n "$py" ]] && h="$(printf '%s' "$1" | "$py" -c 'import sys,hashlib;print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest()[:8])' 2>/dev/null)"
  fi
  [[ "$h" =~ ^[0-9a-f]{8}$ ]] || return 1
  printf '%s' "$h"
}

# prismor_benign_match <value> — 0 for look-alikes of a secret that are really
# documentation: a DB URL whose password is a placeholder word or template.
prismor_benign_match() {
  local v="$1" pw
  if [[ "$v" =~ ^[A-Za-z][A-Za-z0-9+.-]*://[^:/@[:space:]]*:([^@/[:space:]]*)@ ]]; then
    pw="${BASH_REMATCH[1]}"
    pw="$(printf '%s' "$pw" | tr 'A-Z' 'a-z')"
    case "$pw" in
      password|pass|passwd|pwd|secret|changeme|change-me|example|test|admin|root|postgres|123456|xxx*|\**|your*|\<*|\$*|\{*|%*|...) return 0 ;;
    esac
  fi
  return 1
}
