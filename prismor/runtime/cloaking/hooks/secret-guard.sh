#!/usr/bin/env bash
# Prismor — cloaking PreToolUse hook (detect + vault + deny).
#
# Complements decloak.sh. Where decloak SUBSTITUTES an existing
# `@@SECRET:name@@` placeholder, this hook catches RAW secrets that the model
# emitted directly — a freshly generated key, a value read from a file, or a
# credential the model copied into a command/file/MCP arg. On a match it:
#
#   1. Vaults the raw value under a deterministic `auto_<hash>` name (only if
#      it is not already in the vault).
#   2. DENIES the tool call with a reason that names the placeholder to use
#      instead — so the raw value never reaches the JSONL transcript or the
#      upstream API, and the model can immediately retry with the placeholder.
#
# Already-cloaked values (anything present verbatim in the vault — including a
# value decloak.sh just substituted, or a manually-registered secret) are
# recognized and allowed. That makes this hook order-independent relative to
# decloak.sh and idempotent across retries.
#
# Scanned tools: Bash (.command), Write / Edit / MultiEdit / mcp__* (full
# tool_input). Configure detection patterns with `prismor cloak pattern add`.
#
# Stdin:  Claude Code PreToolUse JSON payload
# Stdout: JSON permissionDecision=deny (on a fresh raw secret), else empty.
set -uo pipefail

# shellcheck source=_patterns.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_patterns.sh"
# shellcheck source=_ledger.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_ledger.sh"

SECRETS_DIR="$(prismor_secrets_dir)"
mkdir -p "$SECRETS_DIR"
chmod 700 "$SECRETS_DIR" 2>/dev/null || true

command -v jq >/dev/null 2>&1 || exit 0

input="$(cat)"
tool_name="$(printf '%s' "$input" | jq -r '.tool_name // empty')"
[[ -n "$tool_name" ]] || exit 0
session_id="$(printf '%s' "$input" | jq -r '.session_id // empty')"

# Pick the text to scan. For Bash we scan only the command; for file-writing
# and MCP tools we scan the entire input object so we cover content,
# new_string, edits[], and arbitrary MCP arg names without per-tool knowledge.
case "$tool_name" in
  Bash)
    scan_text="$(printf '%s' "$input" | jq -r '.tool_input.command // empty')"
    kind="bash"
    ;;
  Write|Edit|MultiEdit)
    scan_text="$(printf '%s' "$input" | jq -r '.tool_input // empty | tostring')"
    kind="file"
    ;;
  mcp__*)
    scan_text="$(printf '%s' "$input" | jq -r '.tool_input // empty | tostring')"
    kind="mcp"
    ;;
  *)
    exit 0
    ;;
esac
[[ -n "$scan_text" ]] || exit 0

prismor_load_patterns
[[ "${#PATTERNS[@]}" -gt 0 ]] || exit 0

# Collect unique matches across all patterns.
matches="$(
  for pat in "${PATTERNS[@]}"; do
    printf '%s' "$scan_text" | grep -oE "$pat" || true
  done | awk 'NF && !seen[$0]++'
)"
[[ -n "$matches" ]] || exit 0

# Vault each NEW (uncloaked) match; collect placeholders to report.
reported=""
new_count=0
while IFS= read -r real_value; do
  [[ -z "$real_value" ]] && continue

  # Already in the vault (e.g. decloak just substituted it, or it was
  # registered manually) → legitimate use, do not flag.
  if prismor_value_is_cloaked "$real_value"; then
    continue
  fi

  hash="$(printf '%s' "$real_value" | shasum -a 256 | awk '{print $1}' | cut -c1-8)"
  placeholder_name="auto_${hash}"
  secret_file="$SECRETS_DIR/$placeholder_name"
  if [[ ! -f "$secret_file" ]]; then
    printf '%s' "$real_value" > "$secret_file"
    chmod 600 "$secret_file" 2>/dev/null || true
  fi
  prismor_cloak_event tool_input redacted "$session_id" "$placeholder_name" "$(prismor_pattern_for "$real_value")" "$tool_name"
  reported+="  • @@SECRET:${placeholder_name}@@"$'\n'
  new_count=$((new_count + 1))
done <<< "$matches"

# Every match was already cloaked → allow the call through untouched.
[[ "$new_count" -gt 0 ]] || exit 0

case "$kind" in
  bash) usage="Re-issue this command using the placeholder(s) below — decloak.sh resolves them to the real value at execution time and scrubs the value back out of the captured output." ;;
  file) usage="Do NOT write the literal secret to a file. Use the placeholder(s) below (or an environment-variable reference) in the file content instead." ;;
  mcp)  usage="Re-issue this tool call using the placeholder(s) below instead of the raw value." ;;
esac

reason="Prismor cloaking: detected and vaulted ${new_count} raw secret(s) in this ${tool_name} call.

The raw value was NOT executed, written, or sent to the model/API. It is now
stored under ${SECRETS_DIR} and addressable as:
${reported%$'\n'}

${usage}"

jq -n --arg r "$reason" \
  '{hookSpecificOutput:{hookEventName:"PreToolUse",permissionDecision:"deny",permissionDecisionReason:$r}}'
