#!/usr/bin/env bash
# Prismor — decloak resolver, run as the CHILD of a wrapped Bash tool call.
#
# Why this exists: the PreToolUse hook has to hand Claude Code a runnable
# command, and Claude Code records the command it is handed verbatim in the
# session transcript on disk. Substituting the real secret into that string
# therefore wrote the raw value into ~/.claude/projects/*.jsonl — the exact
# leak the cloaking layer exists to prevent (the value never reached the
# model, but it did reach the disk).
#
# So the hook now hands over the command with its placeholders INTACT, and
# this script does the substitution here, inside the child process, where
# nothing is recorded.
#
# In:  $PRISMOR_CLOAK_CMD   the command text, placeholders unresolved
#      $PRISMOR_SECRETS_DIR the vault
# Out: the command's own stdout/stderr and exit status.
set -uo pipefail

SECRETS_DIR="${PRISMOR_SECRETS_DIR:-${PRISMOR_HOME:-$HOME/.prismor}/secrets}"
cmd="${PRISMOR_CLOAK_CMD:-}"
[[ -n "$cmd" ]] || exit 0

idx=0

# Same placeholder grammar as decloak.sh. An escaped colon is deliberately not
# matched, so the literal syntax can still be written.
while IFS= read -r placeholder; do
  [[ -z "$placeholder" ]] && continue
  name="${placeholder#@@SECRET:}"
  name="${name%@@}"
  secret_file="$SECRETS_DIR/$name"
  # decloak.sh already denied on a missing secret; if it vanished between the
  # hook and here, leave the placeholder alone rather than running a command
  # with an empty credential silently substituted in.
  [[ -f "$secret_file" ]] || continue

  var_name="_PRISMOR_SECRET_${idx}"
  idx=$((idx + 1))

  export "$var_name"="$(cat "$secret_file")"
  cmd="${cmd//"$placeholder"/"\"\${${var_name}}\""}"
done < <(printf '%s' "$cmd" | grep -oE '@@SECRET:[a-zA-Z0-9_-]+@@' | sort -u || true)

eval "$cmd"