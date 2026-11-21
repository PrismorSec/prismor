#!/usr/bin/env bash
# Prismor — cloaking output scrubber (stdin filter).
#
# Reads every registered secret from $PRISMOR_SECRETS_DIR and rewrites any
# occurrence of a real value on stdin to its `@@SECRET:name@@` placeholder,
# streaming the result to stdout. Used by decloak.sh to sanitize the combined
# stdout/stderr of *every* Bash command the model runs — so a secret that a
# command reads out of a file (grep, cat, source+echo, an HTTP response body,
# etc.) is masked before Claude Code records the output, even when the model
# never referenced an `@@SECRET@@` placeholder.
#
# Why a separate script instead of an inline `sed` in the wrapped command:
# the real secret values must NOT appear in the command string, or they would
# land in `tool_input.command` (and thus the transcript). This helper reads
# the vault itself at runtime, so only its path — never a secret — is embedded
# in the command Claude Code records.
#
# Stdin:  arbitrary command output.
# Stdout: same output with registered secret values replaced by placeholders.
# On any error (missing vault, no jq/sed) it passes stdin through unchanged:
# a scrub is best-effort defense-in-depth and must never swallow command
# output the agent depends on.
set -uo pipefail

SECRETS_DIR="${PRISMOR_SECRETS_DIR:-${PRISMOR_HOME:-$HOME/.prismor}/secrets}"

# No vault, or no secrets registered → nothing to scrub, pass through.
if [[ ! -d "$SECRETS_DIR" ]]; then
  exec cat
fi

# Whether a raw secret value is distinctive enough to match by substring
# without false positives. Mirrors is_scrubbable_secret() in ../runtime.py:
# eligible if >= 16 chars, or >= 8 chars AND carrying a digit, a symbol, or
# mixed case. A short single-case word is skipped — masking it would corrupt
# ordinary output far more than it protects anything.
_prismor_scrubbable() {
  local v="$1" n=${#1}
  (( n >= 8 )) || return 1
  [[ "$v" =~ ^[A-Za-z][A-Za-z0-9+.-]*://[A-Za-z0-9.-]+(:[0-9]+)?/?$ ]] && return 1  # bare origin (#930)
  (( n >= 16 )) && return 0
  [[ "$v" == *[[:digit:]]* ]] && return 0
  [[ "$v" == *[![:alnum:]]* ]] && return 0
  [[ "$v" == *[[:lower:]]* && "$v" == *[[:upper:]]* ]] && return 0
  return 1
}

# Slurp stdin, then replace every registered secret value with its placeholder
# using bash's literal substring substitution (${var//"needle"/repl}).
#
# We deliberately do NOT use sed here. sed treats the value as a regex, so a
# secret containing regex metacharacters ([ ] ( ) { } . * + ? ^ $ |) either
# made sed abort with "unterminated substitute pattern" — dropping the whole
# command's output — or, worse, silently mangled the text. Quoting the needle
# in ${var//"$real"/...} forces a literal match, immune to any byte a secret
# key can contain, and it also spans newlines (sed only scrubs line-by-line).
#
# The `; printf x` / `%x` dance preserves trailing newlines that command
# substitution would otherwise strip.
data="$(cat; printf x)"
data="${data%x}"

# decloak.sh passes the session id so each scrub can be counted against it.
# shellcheck source=_ledger.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_ledger.sh" 2>/dev/null \
  || prismor_cloak_event() { :; }

# Longest value first, like scrub_text() in ../runtime.py: when one secret is a
# prefix of another, replacing the short one first would leave the long one's
# tail in the output.
shopt -s nullglob
LC_COLLATE=C  # glob order must match encoded.py's sorted() for the cache header
names=() reals=() all_names=""
for secret_file in "$SECRETS_DIR"/*; do
  [[ -f "$secret_file" ]] || continue
  all_names+=" $(basename "$secret_file")"
  real="$(cat "$secret_file")"
  _prismor_scrubbable "$real" || continue
  names+=("$(basename "$secret_file")") reals+=("$real")
done
while read -r _ i; do
  real="${reals[i]}" name="${names[i]}"
  [[ "$data" == *"$real"* ]] || continue
  data="${data//"$real"/@@SECRET:${name}@@}"
  prismor_cloak_event output redacted "${PRISMOR_CLOAK_SESSION:-}" "$name" "" Bash
done < <(for i in "${!reals[@]}"; do printf '%d %d\n' "${#reals[i]}" "$i"; done | sort -rn)

# Encoded forms (base64 at each offset, hex, URL-encoded, reversed): otherwise
# `printf %s @@SECRET:X@@ | base64` prints the value in a form the loop above
# misses. encoded.py writes them to a 0600 cache inside the vault; it is
# rebuilt only when the set of names changed or a secret file is newer, so an
# unchanged vault costs no fork. No python3, or a failed rebuild: exact-match
# scrubbing above still ran.
cache="$SECRETS_DIR/.meta/encoded"
if (( ${#reals[@]} )); then
  stale=0
  if [[ ! -f "$cache" ]]; then
    stale=1
  else
    IFS= read -r header < "$cache" || header=""
    [[ "$header" == "#names$all_names" ]] || stale=1
    for secret_file in "$SECRETS_DIR"/*; do
      [[ -f "$secret_file" && "$secret_file" -nt "$cache" ]] && { stale=1; break; }
    done
  fi
  if (( stale )); then
    _here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    _py="$(cat "$SECRETS_DIR/.meta/python" 2>/dev/null)"; [[ -x "$_py" ]] || _py=python3
    "$_py" -I "$_here/../encoded.py" "$SECRETS_DIR" >/dev/null 2>&1 || true
  fi
  if [[ -f "$cache" ]]; then
    {
      IFS= read -r _header
      while IFS=$'\t' read -r name variant; do
        [[ -n "$variant" && "$data" == *"$variant"* ]] || continue
        data="${data//"$variant"/@@SECRET:${name}@@}"
        prismor_cloak_event output redacted "${PRISMOR_CLOAK_SESSION:-}" "$name" "" Bash
      done
    } < "$cache"
  fi
fi

printf '%s' "$data"
