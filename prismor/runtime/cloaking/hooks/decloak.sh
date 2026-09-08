#!/usr/bin/env bash
# Prismor — cloaking PreToolUse hook (Claude Code, Bash matcher).
#
# Two jobs, both aimed at keeping a real secret out of the model's context,
# the JSONL transcript, and any upstream API request:
#
#   1. DECLOAK — substitute each `@@SECRET:name@@` placeholder in the command
#      with the real value from $PRISMOR_SECRETS_DIR/<name> so the command
#      actually works when it runs locally.
#
#   2. SCRUB — wrap the command so its combined stdout/stderr is piped through
#      `scrub-stream.sh`, which masks every registered secret value back to its
#      placeholder before Claude Code records the output. This happens for
#      EVERY Bash command, not only ones that used a placeholder — so a secret
#      a command reads out of a file (`grep KEY .env`, `source .env; echo $KEY`,
#      `cat config`, an HTTP response body, ...) is masked too. That closes the
#      leak path where the raw value enters context without ever passing
#      through an `@@SECRET@@` placeholder.
#
# The scrubber reads the vault itself at runtime, so no secret value is ever
# embedded in the wrapped command string (which Claude Code records verbatim).
#
# Stdin:  Claude Code PreToolUse JSON payload.
# Stdout: JSON with hookSpecificOutput.updatedInput (command rewritten), or
#         permissionDecision=deny (a referenced secret is not registered).
#         Empty stdout = no-op (no secrets registered and no placeholder).
set -uo pipefail

_HOOK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECRETS_DIR="${PRISMOR_SECRETS_DIR:-${PRISMOR_HOME:-$HOME/.prismor}/secrets}"
SCRUBBER="$_HOOK_DIR/scrub-stream.sh"
RESOLVER="$_HOOK_DIR/decloak-exec.sh"

# Require jq — hook scripts are shell-only for speed. Fail closed if missing.
if ! command -v jq >/dev/null 2>&1; then
  printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"Prismor cloaking requires jq (brew install jq)"}}\n'
  exit 0
fi

input="$(cat)"
tool_name="$(printf '%s' "$input" | jq -r '.tool_name // empty')"
[[ "$tool_name" == "Bash" ]] || exit 0

cmd="$(printf '%s' "$input" | jq -r '.tool_input.command // empty')"
[[ -n "$cmd" ]] || exit 0

# ── 1. Decloak: validate every placeholder in the command ────────────────
# Resolution itself happens in decloak-exec.sh, in the child process. Doing it
# here would put the real value into the command string that Claude Code
# records verbatim in ~/.claude/projects/*.jsonl.
placeholders="$(printf '%s' "$cmd" | grep -oE '@@SECRET:[a-zA-Z0-9_-]+@@' | sort -u || true)"
if [[ -n "$placeholders" ]]; then
  while IFS= read -r placeholder; do
    [[ -z "$placeholder" ]] && continue
    name="${placeholder#@@SECRET:}"
    name="${name%@@}"
    secret_file="$SECRETS_DIR/$name"
    if [[ ! -f "$secret_file" ]]; then
      # Fail closed: deny rather than leaving a dangling placeholder that would
      # confuse the downstream command. The escaped form (backslash before the
      # colon) is deliberately NOT matched by the grep above, so it reaches the
      # shell verbatim and is how you write the literal syntax (docs, commit
      # messages, tests) without triggering resolution.
      jq -n --arg reason "Prismor cloaking: secret '$name' not registered. Run: prismor cloak add $name (list registered names: prismor cloak list). To write the literal placeholder syntax instead of resolving it, escape the colon: @@SECRET\:$name@@" \
        '{hookSpecificOutput:{hookEventName:"PreToolUse",permissionDecision:"deny",permissionDecisionReason:$reason}}'
      exit 0
    fi
  done <<< "$placeholders"
fi

# ── 2. Decide whether to wrap the command for output scrubbing ──────────────
# Scrub whenever there is at least one registered secret to protect, OR a
# placeholder substitution injected a real value into the command. If the
# vault is empty and no substitution happened, stay a no-op (preserves the
# original behavior for users who have not registered any secret).
have_secrets=0
shopt -s nullglob
for _f in "$SECRETS_DIR"/*; do
  [[ -f "$_f" ]] && { have_secrets=1; break; }
done

if [[ "$have_secrets" -eq 0 && -z "$placeholders" ]]; then
  exit 0
fi

# Wrap: run the command in a brace group, merge stderr into stdout, pipe
# through the scrubber, and re-raise the command's own exit status (not sed's)
# so callers that branch on exit codes still behave correctly. Only the
# scrubber path, the resolver path and the secrets-dir path are embedded —
# never a secret value, in either branch.
if [[ -n "$placeholders" ]]; then
  # Placeholders present: hand the command over unresolved and let the child
  # resolve it, so the recorded string holds placeholders and not secrets.
  runner="PRISMOR_SECRETS_DIR=$(printf '%q' "$SECRETS_DIR") PRISMOR_CLOAK_CMD=$(printf '%q' "$cmd") bash $(printf '%q' "$RESOLVER")"
else
  # Wrapped in a multiline brace group so trailing comments (# ...) or heredocs
  # (EOF) do not comment out or corrupt the closing brace.
  runner="{
$cmd
}"
fi
wrapped="$runner 2>&1 | PRISMOR_SECRETS_DIR=$(printf '%q' "$SECRETS_DIR") $(printf '%q' "$SCRUBBER"); exit \${PIPESTATUS[0]}"

new_input="$(printf '%s' "$input" | jq --arg c "$wrapped" '.tool_input | .command = $c')"
jq -n --argjson ni "$new_input" \
  '{hookSpecificOutput:{hookEventName:"PreToolUse",updatedInput:$ni}}'
