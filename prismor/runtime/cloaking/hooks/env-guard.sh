#!/usr/bin/env bash
# Prismor — cloaking PreToolUse hook (Claude Code, Read|Bash|Grep matcher).
#
# Closes the BOOTSTRAP gap. read-guard.sh and the decloak output scrub only
# protect values already registered in the vault — so the very first thing an
# agent does in a fresh workspace, `cat .env` or Read(.env), leaks every secret
# before any of them has a placeholder. This hook denies content access to a
# dotenv-style file WHILE it holds values missing from the vault, and the deny
# reason itself is the fix: run `prismor cloak add --env-file <path>`, which
# imports every entry as its own `@@SECRET:name@@` placeholder without the
# values ever entering model context (the CLI prints names and byte counts
# only). Once every entry is imported the guard stands down for viewers: Reads
# are then covered by read-guard.sh and Bash output by the decloak scrub. It
# still denies a Bash command that sends the file anywhere else (pipe into a
# non-viewer, redirect, upload, git add, source, re-encode): the scrub only
# sees the tool output, so those would carry the real values out.
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
# Stdin:  Claude Code PreToolUse JSON payload (Read, Bash or Grep).
# Stdout: JSON permissionDecision=deny (unimported env file), else empty.
set -uo pipefail

_HOOK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# hooks/ → cloaking/ → runtime/ → prismor/ → the dir importable as `prismor`.
_PKG_ROOT="$(cd "$_HOOK_DIR/../../../.." && pwd)"

if ! command -v jq >/dev/null 2>&1; then   # fail closed: without jq this hook cannot read the call
  printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"Prismor cloaking requires jq and it is not on PATH, so this call was blocked. Install it: winget install jqlang.jq or scoop install jq (Windows), brew install jq (macOS), apt install jq (Linux). Then restart the agent."}}\n'
  exit 0
fi

input="$(cat)"
tool_name="$(printf '%s' "$input" | jq -r '.tool_name // empty')"
case "$tool_name" in Read|Bash|Grep) ;; *) exit 0 ;; esac

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
    .env|.envrc|.env.*|*.env|*.env.*) return 0 ;;
  esac
  return 1
}

# The first interpreter that can import the checker. On Windows `python3` is
# usually the Microsoft Store alias stub, which exits non-zero, so this check
# failed and the read went through.
_guard_python() {
  local c
  for c in "${PRISMOR_PYTHON:-}" python3 python; do
    [[ -n "$c" ]] || continue
    if PYTHONPATH="$_PKG_ROOT${PYTHONPATH:+:$PYTHONPATH}" "$c" -c \
        'import prismor.runtime.cloaking.env_guard' >/dev/null 2>&1; then printf '%s' "$c"; return; fi
  done
}

# ── deny from a checker report {"files": {path: [names]}, "total": N} ───────
_deny_report() {
  local how="$1" report="$2" total file names
  [[ -n "$report" ]] || return 0
  total="$(printf '%s' "$report" | jq -r '.total // 0')"
  [[ "$total" -gt 0 ]] 2>/dev/null || return 0
  file="$(printf '%s' "$report" | jq -r '.files | keys[0]')"
  names="$(printf '%s' "$report" | jq -r --arg f "$file" '.files[$f] | join(", ")')"
  reason="Prismor cloaking: $how '$file', which holds $total value(s) not yet in the cloak vault ($names) — its contents would enter the model context unprotected. First run: prismor cloak add --env-file '$file' — this imports every entry as an @@SECRET:name@@ placeholder without exposing any value (only names and byte counts are printed). Then reference values by placeholder; if you only need to know whether a key exists, use a presence check like: grep -q '^KEY=' '$file'"
  jq -n --arg r "$reason" \
    '{hookSpecificOutput:{hookEventName:"PreToolUse",permissionDecision:"deny",permissionDecisionReason:$r}}'
  exit 0
}

# $1 = human label for what was attempted; remaining args = existing env files.
_deny_if_unprotected() {
  local how="$1"; shift
  [[ $# -gt 0 ]] || return 0
  local py report
  py="$(_guard_python)"
  [[ -n "$py" ]] || return 0
  report="$(PYTHONPATH="$_PKG_ROOT${PYTHONPATH:+:$PYTHONPATH}" "$py" -c \
    'from prismor.runtime.cloaking.env_guard import main; main()' "$@" 2>/dev/null)" || return 0
  _deny_report "$how" "$report"
}

# ── Read: deny reads of env files with unimported entries ───────────────────
# The path may be a Windows spelling of the file (`.env.`, `.env::$DATA`, an 8.3
# name, `C:\x`, `/c/x`): Python resolves it. Bash only skips paths that cannot
# be an env file, to keep the hot path off Python.
if [[ "$tool_name" == "Read" ]]; then
  file_path="$(printf '%s' "$input" | jq -r '.tool_input.file_path // empty')"
  [[ -n "$file_path" ]] || exit 0
  _lc="$(printf '%s' "$file_path" | tr '[:upper:]' '[:lower:]')"
  [[ "$_lc" == *env* || -L "$file_path" ]] || exit 0
  _py="$(_guard_python)"
  [[ -n "$_py" ]] || exit 0
  report="$(PYTHONPATH="$_PKG_ROOT${PYTHONPATH:+:$PYTHONPATH}" "$_py" -c \
    'from prismor.runtime.cloaking.env_guard import read_main; read_main()' "$file_path" "$cwd" 2>/dev/null)" || exit 0
  _deny_report "reading" "$report"
  exit 0
fi

# ── Grep: a content-mode search prints matching lines of every file in scope ─
if [[ "$tool_name" == "Grep" ]]; then
  [[ "$(printf '%s' "$input" | jq -r '.tool_input.output_mode // "files_with_matches"')" == "content" ]] || exit 0
  gpath="$(printf '%s' "$input" | jq -r '.tool_input.path // empty')"   # empty, relative, C:\x or /c/x: Python resolves it against cwd
  py="$(_guard_python)"
  [[ -n "$py" ]] || exit 0
  report="$(PYTHONPATH="$_PKG_ROOT${PYTHONPATH:+:$PYTHONPATH}" "$py" -c \
    'from prismor.runtime.cloaking.env_guard import grep_main; grep_main()' "$gpath" \
    "$(printf '%s' "$input" | jq -r '.tool_input.glob // empty')" \
    "$(printf '%s' "$input" | jq -r '.tool_input.type // empty')" "$cwd" 2>/dev/null)" || exit 0
  _deny_report "a content-mode Grep would print lines of" "$report"
  exit 0
fi

# ── Bash: deny commands that read such files ────────────────────────────────
cmd="$(printf '%s' "$input" | jq -r '.tool_input.command // empty')"
[[ -n "$cmd" ]] || exit 0

# The sanctioned ingestion path (`prismor cloak add --env-file`, list, ...)
# names the file but never prints values — allowed when it is the WHOLE
# command. Anywhere-in-the-command matching let `prismor cloak list; cat .env`
# through, and #440's `prismer` spelling exempted nothing real at all.
if [[ "$cmd" =~ ^[[:space:]]*([/A-Za-z0-9_.~-]*/)?prismor[[:space:]]+cloak([[:space:]][^\;\&\|\`\$\<\>]*)?$ ]]; then
  exit 0
fi

# Cheap fast path: skip Python unless the command could name an env file —
# literally, through a glob or variable that could expand to one beside it
# (or after a cd), or through a symlink.
# Publishing commands (images, packages, releases, uploads, pushes) are always
# checked: publish_gate.py looks at what they would ship.
_publish_re='(^|[^[:alnum:]_.-])(docker|podman|buildah|npm|pnpm|yarn|bun|cargo|twine|gem|gh|git|aws|gsutil|curl|wget)([^[:alnum:]_.-]|$)'
if [[ "$cmd" != *env* && ! "$cmd" =~ $_publish_re ]]; then
  _need=0
  # (a recursive grep reads every dotfile under its directory, too)
  if [[ "$cmd" == *[\$\*\?\[\{\`]* || "$cmd" =~ grep[[:space:]].*-[[:alnum:]]*[rR]|--hidden|-uu ]]; then
    if [[ "$cmd" == *cd* ]]; then _need=1; else
      shopt -s nullglob dotglob
      for f in "$cwd"/.env* "$cwd"/*.env*; do _is_env_basename "$f" && { _need=1; break; }; done
      shopt -u nullglob dotglob
    fi
  fi
  if [[ "$_need" -eq 0 ]]; then
    read -ra _words <<< "${cmd//[;&|()<>\"\'=$'\n']/ }"
    for w in ${_words[@]+"${_words[@]}"}; do
      [[ "$w" == /* ]] || w="$cwd/$w"
      [[ -L "$w" ]] && { _need=1; break; }
    done
  fi
  [[ "$_need" -eq 1 ]] || exit 0
fi

# Which env files the command reads is decided in Python (env_guard.env_reads):
# a real shell tokenizer, deny-by-default for any command that names one
# except metadata/presence/write forms, `cd` tracking, globs, variables and
# symlinks. A path inside `ssh host '<cmd>'` is a file on the other machine.
_py="$(_guard_python)"
[[ -n "$_py" ]] || exit 0
report="$(printf '%s' "$cmd" | PYTHONPATH="$_PKG_ROOT${PYTHONPATH:+:$PYTHONPATH}" "$_py" -c \
  'from prismor.runtime.cloaking.env_guard import bash_main; bash_main()' "$cwd" 2>/dev/null)" || exit 0
unknown_env="$(printf '%s' "$report" | jq -r '.unknown // empty')"
if [[ -n "$unknown_env" ]]; then
  reason="Prismor cloaking: this command reads '$unknown_env' from a directory that can't be resolved before it runs (a variable or command substitution). Prismor can't check whether that file holds secrets missing from the cloak vault, so it is blocked. Use the file's absolute path, or import it first: prismor cloak add --env-file <absolute path>"
  jq -n --arg r "$reason" \
    '{hookSpecificOutput:{hookEventName:"PreToolUse",permissionDecision:"deny",permissionDecisionReason:$r}}'
  exit 0
fi
pub="$(printf '%s' "$report" | jq -r '.publish // empty')"
if [[ -n "$pub" ]]; then
  reason="Prismor publish gate: $pub. Nothing was published. Remove the file or value from what ships (.dockerignore, .npmignore, .gitignore, or the file list), reference secrets by placeholder or environment variable, then retry."
  jq -n --arg r "$reason" \
    '{hookSpecificOutput:{hookEventName:"PreToolUse",permissionDecision:"deny",permissionDecisionReason:$r}}'
  exit 0
fi
flow="$(printf '%s' "$report" | jq -r '.vaulted_flow // empty')"
if [[ -n "$flow" ]]; then
  reason="Prismor cloaking: this command sends the contents of '$flow' somewhere other than the tool output. Its values are in the cloak vault, but the redaction only covers what is printed back to you: piped, redirected, uploaded, committed, sourced or re-encoded, the real values would leave. Only plain viewers (cat, head, grep ...) may read it. Pass a value by placeholder instead, e.g. curl -H \"Authorization: Bearer @@SECRET:NAME@@\" ..."
  jq -n --arg r "$reason" \
    '{hookSpecificOutput:{hookEventName:"PreToolUse",permissionDecision:"deny",permissionDecisionReason:$r}}'
  exit 0
fi
_deny_report "this command reads" "$report"
exit 0
