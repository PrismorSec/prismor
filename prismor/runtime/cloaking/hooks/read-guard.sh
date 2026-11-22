#!/usr/bin/env bash
# Prismor — cloaking PreToolUse hook (Claude Code, Read|Grep|Edit|MultiEdit matcher).
#
# The built-in Read tool has no post-hoc output-rewrite channel (unlike Bash,
# whose output decloak.sh scrubs, and MCP tools, whose output recloak-mcp.sh
# scrubs). So a secret read through the Read tool cannot be masked after the
# fact — the only way to keep it out of context is to stop the read.
#
# This hook denies a Read whose target file contains a registered secret value,
# and tells the model to reference the `@@SECRET:name@@` placeholder instead
# (which decloak.sh will substitute at execution time). Files that hold no
# registered secret are unaffected.
#
# Stdin:  Claude Code PreToolUse JSON payload (Read, Grep, Edit, MultiEdit).
# Stdout: JSON permissionDecision=deny (target holds a secret), else empty.
set -uo pipefail

SECRETS_DIR="${PRISMOR_SECRETS_DIR:-${PRISMOR_HOME:-$HOME/.prismor}/secrets}"

command -v jq >/dev/null 2>&1 || exit 0   # no jq → silent no-op; decloak fails loud

input="$(cat)"
tool_name="$(printf '%s' "$input" | jq -r '.tool_name // empty')"
[[ -d "$SECRETS_DIR" ]] || exit 0
# shellcheck source=_patterns.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_patterns.sh"   # prismor_scrubbable

_deny() {
  # shellcheck source=_ledger.sh
  source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_ledger.sh"
  prismor_cloak_event read blocked "$(printf '%s' "$input" | jq -r '.session_id // empty')" "$1" "" "$tool_name"
  jq -n --arg r "$2" \
    '{hookSpecificOutput:{hookEventName:"PreToolUse",permissionDecision:"deny",permissionDecisionReason:$r}}'
  exit 0
}

# Built-in Grep returns matching LINES in content mode, and neither it nor
# Edit's result snippet has an output-rewrite channel (PostToolUse can only
# replace MCP output). So: deny a content-mode Grep whose search scope holds a
# file with a registered secret, and an Edit/MultiEdit of such a file (its
# result echoes lines around the change). files_with_matches / count modes
# print only paths and numbers and pass.
if [[ "$tool_name" == "Grep" ]]; then
  [[ "$(printf '%s' "$input" | jq -r '.tool_input.output_mode // "files_with_matches"')" == "content" ]] || exit 0
  path="$(printf '%s' "$input" | jq -r '.tool_input.path // .cwd // empty')"
  [[ -n "$path" ]] || path="$PWD"
  [[ -e "$path" ]] || exit 0
  incl=()
  glob="$(printf '%s' "$input" | jq -r '.tool_input.glob // empty')"
  type="$(printf '%s' "$input" | jq -r '.tool_input.type // empty')"
  [[ -n "$glob" ]] && incl+=("--include=${glob##*/}")
  [[ -n "$type" ]] && incl+=("--include=*.$type")
  shopt -s nullglob
  pats=()
  for secret_file in "$SECRETS_DIR"/*; do
    [[ -f "$secret_file" ]] || continue
    real="$(cat "$secret_file")"
    prismor_scrubbable "$real" || continue
    # grep -F matches per line; a multi-line value is caught by any of its lines.
    while IFS= read -r l; do (( ${#l} >= 8 )) && pats+=("$l"); done <<< "$real"
  done
  [[ ${#pats[@]} -gt 0 ]] || exit 0
  hit="$(grep -rlIF --exclude-dir=.git --exclude-dir=node_modules ${incl[@]+"${incl[@]}"} \
    -f <(printf '%s\n' "${pats[@]}") -- "$path" 2>/dev/null | head -1)"
  [[ -n "$hit" ]] || exit 0
  _deny "" "Prismor cloaking: a content-mode Grep over '$path' would print lines of '$hit', which holds a registered secret. Use output_mode files_with_matches or count, narrow path/glob to exclude that file, or work with the value as an @@SECRET:name@@ placeholder in a Bash command (its output is scrubbed)."
fi

case "$tool_name" in Read|Edit|MultiEdit) ;; *) exit 0 ;; esac
file_path="$(printf '%s' "$input" | jq -r '.tool_input.file_path // empty')"
[[ -n "$file_path" && -f "$file_path" ]] || exit 0

# Does the target file contain any registered secret value verbatim?
shopt -s nullglob
contents=""; contents_loaded=0
for secret_file in "$SECRETS_DIR"/*; do
  [[ -f "$secret_file" ]] || continue
  name="$(basename "$secret_file")"
  real="$(cat "$secret_file")"
  prismor_scrubbable "$real" || continue
  if [[ "$real" == *$'\n'* ]]; then
    # grep -F splits a multiline value into patterns (a blank line matches
    # everything). Match the whole literal value, as scrub-stream.sh does.
    if (( ! contents_loaded )); then
      contents="$(cat -- "$file_path" 2>/dev/null)"
      contents_loaded=1
    fi
    [[ "$contents" == *"$real"* ]] || continue
  else
    grep -qF -- "$real" "$file_path" 2>/dev/null || continue
  fi
  what="Reading it"; [[ "$tool_name" == Read ]] || what="Editing it (the result shows the lines around the change)"
  _deny "$name" "Prismor cloaking: '$file_path' contains the registered secret '$name'. $what would place the raw value in context. Reference it as @@SECRET:${name}@@ in a Bash command instead — Prismor substitutes the real value at execution time and scrubs it from the output."
done

exit 0
