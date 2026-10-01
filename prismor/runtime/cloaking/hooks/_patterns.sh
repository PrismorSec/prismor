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
    if [[ "$(cat "$f")" == "$value" ]]; then
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
  (( n >= 16 )) && return 0
  [[ "$v" == *[[:digit:]]* ]] && return 0
  [[ "$v" == *[![:alnum:]]* ]] && return 0
  [[ "$v" == *[[:lower:]]* && "$v" == *[[:upper:]]* ]] && return 0
  return 1
}
