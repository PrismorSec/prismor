#!/usr/bin/env bash
# Prismor — cloaking PreToolUse hook (Claude Code, Read|Bash matcher).
#
# Closes the BOOTSTRAP gap. read-guard.sh and the decloak output scrub only
# protect values already registered in the vault — so the very first thing an
# agent does in a fresh workspace, `cat .env` or Read(.env), leaks every secret
# before any of them has a placeholder. This hook denies content access to a
# dotenv-style file WHILE it holds values missing from the vault, and the deny
# reason itself is the fix: run `prismor cloak add --env-file <path>`, which
# imports every entry as its own `@@SECRET:name@@` placeholder without the
# values ever entering model context (the CLI prints names and byte counts
# only). Once every entry is imported the guard stands down: Reads are then
# covered by read-guard.sh and Bash output by the decloak scrub.
#
# Deliberately allowed even before import:
#   * `prismor cloak ...` commands — the sanctioned ingestion path.
#   * Append-only writes (`echo K=V >> .env`) — nothing is read.
#   * Presence checks (`grep -q/-c/-l KEY .env`) — no content in the output.
#
# The "is every entry imported?" check runs in Python (env_guard.py) so it
# parses env lines exactly like `prismor cloak add --env-file` does; a bash
# re-implementation that disagreed with the importer could deny forever.
#
# Stdin:  Claude Code PreToolUse JSON payload (Read or Bash).
# Stdout: JSON permissionDecision=deny (unimported env file), else empty.
set -uo pipefail

_HOOK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# hooks/ → cloaking/ → runtime/ → prismor/ → the dir importable as `prismor`.
_PKG_ROOT="$(cd "$_HOOK_DIR/../../../.." && pwd)"

command -v jq >/dev/null 2>&1 || exit 0   # no jq → silent no-op; decloak fails loud

input="$(cat)"
tool_name="$(printf '%s' "$input" | jq -r '.tool_name // empty')"
[[ "$tool_name" == "Read" || "$tool_name" == "Bash" ]] || exit 0

cwd="$(printf '%s' "$input" | jq -r '.cwd // empty')"
[[ -n "$cwd" ]] || cwd="$PWD"

# ── env-style filename test (basename) ──────────────────────────────────────
# Matches .env, .env.production, secrets.env, prod.env.bak, ...
# Skips example/sample/template/dist files — those hold placeholders, and
# reading them is how an agent learns which keys a project needs.
_is_env_basename() {
  local base lower
  base="$(basename -- "$1")"
  lower="$(printf '%s' "$base" | tr '[:upper:]' '[:lower:]')"
  case "$lower" in
    *example*|*sample*|*template*|*dist*) return 1 ;;
  esac
  case "$lower" in
    .env|.env.*|*.env|*.env.*) return 0 ;;
  esac
  return 1
}

# ── check files with the shared Python parser; deny if any entry unimported ─
# $1 = human label for what was attempted; remaining args = existing env files.
_deny_if_unprotected() {
  local how="$1"; shift
  [[ $# -gt 0 ]] || return 0
  local report
  report="$(PYTHONPATH="$_PKG_ROOT${PYTHONPATH:+:$PYTHONPATH}" python3 -c \
    'from prismor.runtime.cloaking.env_guard import main; main()' "$@" 2>/dev/null)" || return 0
  [[ -n "$report" ]] || return 0
  local total
  total="$(printf '%s' "$report" | jq -r '.total // 0')"
  [[ "$total" -gt 0 ]] 2>/dev/null || return 0
  local file names
  file="$(printf '%s' "$report" | jq -r '.files | keys[0]')"
  names="$(printf '%s' "$report" | jq -r --arg f "$file" '.files[$f] | join(", ")')"
  reason="Prismor cloaking: $how '$file', which holds $total value(s) not yet in the cloak vault ($names) — its contents would enter the model context unprotected. First run: prismor cloak add --env-file '$file' — this imports every entry as an @@SECRET:name@@ placeholder without exposing any value (only names and byte counts are printed). Then reference values by placeholder; if you only need to know whether a key exists, use a presence check like: grep -q '^KEY=' '$file'"
  jq -n --arg r "$reason" \
    '{hookSpecificOutput:{hookEventName:"PreToolUse",permissionDecision:"deny",permissionDecisionReason:$r}}'
  exit 0
}

# ── Read: deny reads of env files with unimported entries ───────────────────
if [[ "$tool_name" == "Read" ]]; then
  file_path="$(printf '%s' "$input" | jq -r '.tool_input.file_path // empty')"
  [[ -n "$file_path" && -f "$file_path" ]] || exit 0
  _is_env_basename "$file_path" || exit 0
  _deny_if_unprotected "reading" "$file_path"
  exit 0
fi

# ── Bash: deny content-reading commands that target such files ──────────────
cmd="$(printf '%s' "$input" | jq -r '.tool_input.command // empty')"
[[ -n "$cmd" ]] || exit 0
[[ "$cmd" == *env* ]] || exit 0   # cheap fast path

# The sanctioned ingestion path (`prismor cloak add --env-file`, list, ...)
# names the file but never prints values — always allowed.
if [[ "$cmd" =~ (^|[[:space:]])([/A-Za-z0-9_.-]*/)?prismer([[:space:]]+cloak([[:space:]]|$)|$) ]]; then
  exit 0
fi

# Collect existing env-style files referenced by the command.
env_files=()
while IFS= read -r tok; do
  [[ -n "$tok" ]] || continue
  _is_env_basename "$tok" || continue
  path="$tok"
  [[ "$path" == /* || "$path" == "~"* ]] || path="$cwd/$path"
  path="${path/#\~\//$HOME/}"
  [[ -f "$path" ]] || continue
  env_files+=("$path")
done < <(printf '%s' "$cmd" | grep -oE '[A-Za-z0-9_.~/-]+' | sort -u)
[[ ${#env_files[@]} -gt 0 ]] || exit 0

# Is this command actually READING content? Appends and presence checks pass.
is_reader=0
_READERS='(^|[;&|(`[:space:]])(sudo[[:space:]]+)?(cat|bat|head|tail|less|more|most|nl|tac|strings|od|xxd|hexdump|column|paste|sort|uniq|rev|cut|tr|sed|awk|gawk|diff|cmp|source|python[0-9.]*|node|ruby|perl)([[:space:]]|$)'
_GREPPERS='(^|[;&|(`[:space:]])(sudo[[:space:]]+)?(grep|egrep|fgrep|rg|ag|ack)([[:space:]]|$)'
_PRESENCE_FLAGS='[[:space:]]-(q|c|l|L)([[:space:]]|$)|--(quiet|silent|count|files-with-matches)'
if [[ "$cmd" =~ $_READERS ]]; then
  is_reader=1
elif [[ "$cmd" =~ $_GREPPERS ]]; then
  # grep-family reads content unless invoked purely as a presence check.
  if [[ "$cmd" =~ $_PRESENCE_FLAGS ]]; then
    is_reader=0
  else
    is_reader=1
  fi
else
  # Input redirection (`... < .env`) reads without naming a reader utility.
  for f in "${env_files[@]}"; do
    base="$(basename -- "$f")"
    if [[ "$cmd" == *"<$base"* || "$cmd" == *"< $base"* \
       || "$cmd" == *"<$f"* || "$cmd" == *"< $f"* ]]; then
      is_reader=1
      break
    fi
  done
fi
[[ "$is_reader" -eq 1 ]] || exit 0

_deny_if_unprotected "this command reads" "${env_files[@]}"
exit 0
