#!/usr/bin/env bash
# Prismor — cloak event ledger, sourced by the hook scripts.
#
# The cloak hooks are plain bash and cannot reach the telemetry pipeline, so
# each catch is appended here as one JSON line. The Python hook drains the file
# on its next evaluated call (cloaking/ledger.py) and ships each line as a
# finding, so the console can count what was caught and redacted.
#
# A line holds labels only: where the secret was seen, what was done, the
# vault NAME (never the value), and the static pattern that matched.
#
#   prismor_cloak_event <source> <action> <session_id> [name] [pattern] [tool]
#
# source: prompt | prompt_file | tool_input | read | mcp_output | command | output
# action: redacted | blocked | used
#
# Best-effort and silent: no jq, a full ledger or a write error never affects
# the hook's own decision.

prismor_cloak_ledger_file() {
  printf '%s' "${PRISMOR_CLOAK_LEDGER:-${PRISMOR_HOME:-$HOME/.prismor}/cloak_events.jsonl}"
}

prismor_cloak_event() {
  command -v jq >/dev/null 2>&1 || return 0
  local file size
  file="$(prismor_cloak_ledger_file)"
  # ponytail: hard 1 MB cap; drops new lines while nothing drains (no enrolled sink).
  size="$(wc -c < "$file" 2>/dev/null || echo 0)"
  (( ${size//[[:space:]]/} < 1048576 )) || return 0
  mkdir -p "$(dirname "$file")" 2>/dev/null || return 0
  # One short line per append, so concurrent hooks do not interleave.
  jq -cn --arg source "$1" --arg action "$2" --arg session "${3:-}" \
    --arg name "${4:-}" --arg pattern "${5:-}" --arg tool "${6:-}" \
    --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '{ts: $ts, source: $source, action: $action, session_id: $session,
      name: $name, pattern: ($pattern | .[0:200]), tool: $tool}' \
    >> "$file" 2>/dev/null || true
}

# prismor_pattern_for <value> — the first loaded PATTERNS entry that matches
# <value>, so a catch is attributed to the rule that found it. Detection path
# only (runs after a match), never on a clean call.
prismor_pattern_for() {
  local pat
  for pat in "${PATTERNS[@]}"; do
    if printf '%s' "$1" | grep -qE "$pat" 2>/dev/null; then
      printf '%s' "$pat"
      return 0
    fi
  done
}
