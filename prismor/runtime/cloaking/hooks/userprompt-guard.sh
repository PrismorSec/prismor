#!/usr/bin/env bash
# Prismor — cloaking UserPromptSubmit hook (soft-block).
#
# Scans the user's submitted prompt for recognizable secret patterns. On a
# match, auto-cloaks the value (writes it to $PRISMOR_SECRETS_DIR with a
# hashed name) and BLOCKS the prompt with a reason that shows the sanitized
# version. The user copies the sanitized prompt and resubmits — from that
# point forward, the model only ever sees the `@@SECRET:auto_xxxxxx@@`
# placeholder, never the raw value.
#
# UserPromptSubmit hooks cannot rewrite the prompt (Claude Code exposes only
# block/add-context on this event). To avoid a manual re-paste, the sanitized
# prompt is STASHED under $PRISMOR_HOME/prompt_stash/<session_id> when we
# block; on the user's next (clean) prompt in that session the stash is
# auto-loaded via `additionalContext` and then deleted, so the model receives
# the sanitized request without the user ever copying it. Any follow-up
# message ("go", "continue", a clarification) triggers the reload.
#
# Stdin:  Claude Code UserPromptSubmit JSON payload
# Stdout: JSON with decision=block and a reason (if a secret was detected),
#         JSON with hookSpecificOutput.additionalContext (if a stashed
#         sanitized prompt is being reloaded), or empty (no-op) otherwise.
set -uo pipefail

# shellcheck source=_patterns.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_patterns.sh"
# shellcheck source=_ledger.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_ledger.sh"

SECRETS_DIR="$(prismor_secrets_dir)"
mkdir -p "$SECRETS_DIR"
chmod 700 "$SECRETS_DIR" 2>/dev/null || true

# Stash directory for sanitized-but-blocked prompts (one file per session).
STASH_DIR="${PRISMOR_PROMPT_STASH_DIR:-${PRISMOR_HOME:-$HOME/.prismor}/prompt_stash}"
# A stash older than this is ignored (and removed) rather than injected into an
# unrelated later conversation. Seconds; overridable for tests.
STASH_TTL="${PRISMOR_PROMPT_STASH_TTL:-1800}"

command -v jq >/dev/null 2>&1 || exit 0

input="$(cat)"
prompt="$(printf '%s' "$input" | jq -r '.prompt // empty')"
[[ -n "$prompt" ]] || exit 0

session_id="$(printf '%s' "$input" | jq -r '.session_id // empty' | tr -cd 'A-Za-z0-9._-')"
[[ -n "$session_id" ]] || session_id="default"
stash_file="$STASH_DIR/$session_id"

# prismor_stash_age_ok <file> — 0 if the stash is younger than STASH_TTL.
prismor_stash_age_ok() {
  local f="$1" mtime now
  # GNU form first: on BSD/macOS `stat -c` fails cleanly with empty stdout,
  # whereas GNU `stat -f` means --file-system and prints a report to stdout
  # *and* exits non-zero, so the fallback runs too and $mtime goes multi-line.
  mtime="$(stat -c %Y "$f" 2>/dev/null || stat -f %m "$f" 2>/dev/null || echo 0)"
  [[ "$mtime" =~ ^[0-9]+$ ]] || mtime=0
  now="$(date +%s)"
  [[ $(( now - mtime )) -le "$STASH_TTL" ]]
}

# prismor_emit_stash_context — if a fresh stash exists for this session, emit
# it as additionalContext (so the model receives the sanitized request) and
# delete it. Called only on the pass-through paths, never on a block.
prismor_emit_stash_context() {
  [[ -f "$stash_file" ]] || return 0
  if ! prismor_stash_age_ok "$stash_file"; then
    rm -f "$stash_file"
    return 0
  fi
  local stashed
  stashed="$(cat "$stash_file")"
  rm -f "$stash_file"
  # If the user pasted the sanitized text themselves, the current prompt
  # already carries it — no need to inject a duplicate copy.
  if [[ "$(printf '%s' "$prompt" | tr -d '[:space:]')" == "$(printf '%s' "$stashed" | tr -d '[:space:]')" ]]; then
    return 0
  fi
  local ctx
  ctx="Prismor cloaking: the user's previous prompt in this session was blocked because it contained secret(s). Those values are now registered in the Prismor vault and replaced below with @@SECRET:name@@ placeholders, which are substituted with the real values at tool-call time — use the placeholders verbatim in commands and never ask the user for the raw values. Treat the sanitized prompt below as the user's actual request; the message they just sent is a follow-up to it (attachments such as images from the blocked prompt were not carried over).

--- BEGIN SANITIZED PROMPT ---
${stashed}
--- END SANITIZED PROMPT ---"
  jq -n --arg c "$ctx" '{hookSpecificOutput: {hookEventName: "UserPromptSubmit", additionalContext: $c}}'
}

# Optional user bypass: a prompt starting with `!!allow ` (ignoring leading
# whitespace) is passed through unchanged. Useful when the user is deliberately
# discussing a secret in prose and doesn't want auto-cloaking.
trimmed="$(printf '%s' "$prompt" | sed 's/^[[:space:]]*//')"
if [[ "$trimmed" == "!!allow "* ]]; then
  prismor_emit_stash_context
  exit 0
fi

# ── @file-mention guard ───────────────────────────────────────────────────
# Claude Code expands an `@path` mention by attaching the file's raw contents
# to the model context — and it does so DOWNSTREAM of this hook, so the
# attached bytes never appear in the `.prompt` we receive and cannot be
# scrubbed after the fact. If a mentioned file holds a registered secret, the
# only way to keep the value out of context is to block the prompt here, before
# the attachment happens. (Verified: a prompt with `@secretfile` leaks the raw
# value into context; blocking at this event prevents it.)
cwd="$(printf '%s' "$input" | jq -r '.cwd // empty')"
mentions="$(printf '%s' "$prompt" | grep -oE '@[^[:space:]@]+' | sed 's/^@//' | sort -u || true)"
if [[ -n "$mentions" ]]; then
  while IFS= read -r mp; do
    [[ -z "$mp" ]] && continue
    case "$mp" in
      /*) fp="$mp" ;;
      *)  fp="${cwd:+$cwd/}$mp" ;;
    esac
    [[ -f "$fp" ]] || continue
    shopt -s nullglob
    for sf in "$SECRETS_DIR"/*; do
      [[ -f "$sf" ]] || continue
      rv="$(cat "$sf")"
      prismor_scrubbable "$rv" || continue
      if grep -qF -- "$rv" "$fp" 2>/dev/null; then
        name="$(basename "$sf")"
        prismor_cloak_event prompt_file blocked "$session_id" "$name"
        reason="Prismor cloaking: your prompt references @${mp}, and that file contains the registered secret '${name}'. Claude Code would attach its raw contents to the model context, bypassing cloaking. Remove the @-mention and reference @@SECRET:${name}@@ in a tool command instead — Prismor substitutes the real value at execution time and scrubs it from the output."
        jq -n --arg r "$reason" '{decision: "block", reason: $r}'
        exit 0
      fi
    done
  done <<< "$mentions"
fi

# ── Detection patterns ────────────────────────────────────────────────────
# Loaded from the shared single-source-of-truth file (builtin_patterns.txt)
# plus any org-specific patterns the user added via `prismor cloak pattern add`.
prismor_load_patterns
[[ "${#PATTERNS[@]}" -gt 0 ]] || { prismor_emit_stash_context; exit 0; }

# Strip already-cloaked placeholders before scanning so that @@SECRET:name@@
# syntax in the prompt never triggers a false positive match.
scan_text="$(printf '%s' "$prompt" | sed 's/@@SECRET:[^@]*@@//g')"

# Collect unique matches across all patterns.
matches="$(
  for pat in "${PATTERNS[@]}"; do
    printf '%s' "$scan_text" | grep -oE "$pat" || true
  done | awk 'NF && !seen[$0]++'
)"

# Clean prompt: pass through, reloading any stashed sanitized prompt first.
[[ -n "$matches" ]] || { prismor_emit_stash_context; exit 0; }

# ── Cloak each match ─────────────────────────────────────────────────────
sanitized="$prompt"
reported_placeholders=""
while IFS= read -r real_value; do
  [[ -z "$real_value" ]] && continue

  # Deterministic placeholder name from value hash (first 8 hex chars).
  # Same value → same placeholder across sessions (no duplicate registration).
  hash="$(printf '%s' "$real_value" | shasum -a 256 | awk '{print $1}' | cut -c1-8)"
  placeholder_name="auto_${hash}"
  placeholder="@@SECRET:${placeholder_name}@@"
  secret_file="$SECRETS_DIR/$placeholder_name"

  # Only write if new — avoid touching mtime on existing entries.
  if [[ ! -f "$secret_file" ]]; then
    printf '%s' "$real_value" > "$secret_file"
    chmod 600 "$secret_file" 2>/dev/null || true
  fi

  prismor_cloak_event prompt redacted "$session_id" "$placeholder_name" "$(prismor_pattern_for "$real_value")"

  # Substitute every occurrence of this value in the sanitized prompt.
  sanitized="${sanitized//"$real_value"/$placeholder}"
  reported_placeholders+="  • $placeholder"$'\n'
done <<< "$matches"

# ── Stash the sanitized prompt for auto-reload on the next message ───────
mkdir -p "$STASH_DIR" 2>/dev/null || true
chmod 700 "$STASH_DIR" 2>/dev/null || true
stash_hint=""
if printf '%s' "$sanitized" > "$stash_file" 2>/dev/null; then
  chmod 600 "$stash_file" 2>/dev/null || true
  stash_hint="Your original prompt was NOT sent to the model. The sanitized version
below has been saved — just send any follow-up message (e.g. \"go\") and
Prismor will load it automatically. Or paste it yourself:"
else
  stash_hint="Your original prompt was NOT sent to the model. Resubmit with the sanitized
version below (the model will resolve each placeholder at tool-call time):"
fi

# ── Emit soft-block decision ──────────────────────────────────────────────
reason="Prismor cloaking: detected secret(s) in your prompt.

Stored under ${SECRETS_DIR} as:
${reported_placeholders%$'\n'}

${stash_hint}

---
${sanitized}
---

Prefix your prompt with '!!allow ' to bypass detection for a single message."

jq -n --arg r "$reason" '{decision: "block", reason: $r}'
