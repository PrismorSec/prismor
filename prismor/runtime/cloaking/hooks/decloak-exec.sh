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

# Secrets bound to hosts (bindings.py) resolve only into a curl/wget/http/xh
# call to those hosts. Every shell path resolves here (Claude Code hook, MCP
# mirror, ACP proxy, Hermes), so this is the one gate. The interpreter is the
# one Prismor recorded when the binding was saved, inside the vault: a
# `python3` an agent planted on PATH could otherwise just exit 0. Anything
# missing fails closed.
if [[ -f "$SECRETS_DIR/.meta/hosts.json" && "$cmd" == *"@@SECRET:"* ]]; then
  _here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  _chk="$_here/bindings.py"; [[ -f "$_chk" ]] || _chk="$_here/../bindings.py"
  _py="$(cat "$SECRETS_DIR/.meta/python" 2>/dev/null)"
  if [[ ! -f "$_chk" || ! -x "$_py" ]]; then
    echo "prismor cloak refused: secrets are bound to hosts, but the binding check can't run (reinstall with prismor cloak install)" >&2
    exit 126
  fi
  PRISMOR_CLOAK_CMD="$cmd" "$_py" -I "$_chk" "$SECRETS_DIR" || exit 126
  # A `curl` function exported into the environment would run instead of curl.
  unset -f curl wget http https xh xhs 2>/dev/null
fi

# The secret value never enters the text that `eval` parses (#457). Each
# placeholder becomes a reference to a shell variable, written in the form
# that expands to exactly the value in the quoting context it sits in:
#   unquoted "${V}"   "double" ${V}   'single' '"${V}"'   $'ansi' '"${V}"$'
#   heredoc body ${V}   quoted heredoc: rewritten as an unquoted one whose
#   literal `\ $ backtick` are escaped, so the body still reads verbatim.
# There is no path that inlines a raw value, so a misread can only mis-expand
# a reference, never execute a secret's content. A `#` comment is copied
# through untouched: a `<<` inside one must not start a heredoc.
# Placeholder grammar matches decloak.sh; an escaped colon is not matched, so
# the literal syntax can still be written.
# ponytail: a quote scanner, not a bash parser. Misreads (e.g. `<<` inside
# $((...))) can only mis-expand a reference, never execute a secret's content.
# Cost is linear in size but quadratic in quote count (~0.2s at 1k
# quotes); placeholder commands are small, so a real tokenizer can wait.

# Load secret $1 (once) into a NON-exported variable and set $var to its name;
# the escaping keeps names injective (`_` -> `__`, `-` -> `_D`). Not exported:
# only the words that reference it see the value, not every child process
# (`curl ... && npm i x` must not hand the token to a postinstall script). A
# value a caller passed in the environment (mirror.py) is un-exported too.
# Hermes vaults auto_* names under auto_vault/. decloak.sh already denied on a
# missing secret; if it vanished since, fail so the placeholder stays as-is
# rather than running with an empty credential silently substituted in.
load() {
  var="${1//_/__}"
  var="_PRISMOR_SECRET_${var//-/_D}"
  if [[ -n "${!var+x}" ]]; then export -n "$var"; return 0; fi
  local f="$SECRETS_DIR/$1"
  [[ -f "$f" ]] || f="$SECRETS_DIR/auto_vault/$1"
  [[ -f "$f" ]] || return 1
  printf -v "$var" '%s' "$(cat "$f")"
}

# Placeholder line of a heredoc body. $2=1: the heredoc was quoted, so the
# literal text is escaped for the unquoted heredoc it is rewritten into.
# Appends to $out directly: a $(...) subshell would lose what load() sets.
hd_line() {
  local line="$1" esc="$2" lit m
  while [[ "$line" =~ $ph_re ]]; do
    m="${BASH_REMATCH[0]}"
    lit="${line%%"$m"*}"; line="${line#*"$m"}"
    [[ "$esc" == 1 ]] && lit="$(hd_esc "$lit")"
    if load "${BASH_REMATCH[1]}"; then out+="$lit\${$var}"; else out+="$lit$m"; fi
  done
  [[ "$esc" == 1 ]] && line="$(hd_esc "$line")"
  out+="$line"$'\n'
}
hd_esc() { local s="${1//\\/\\\\}"; s="${s//\$/\\\$}"; printf '%s' "${s//\`/\\\`}"; }

# Byte indexing: O(1) substrings instead of O(n) multibyte walks. Restored
# before eval so the command runs in the caller's locale.
had_lc="${LC_ALL+x}" saved_lc="${LC_ALL-}"
export LC_ALL=C

ph_re='@@SECRET:([a-zA-Z0-9_-]+)@@'
hd_re='^(-?)[[:space:]]*([^[:space:];|&<>()]+)'
out="" rest="$cmd" q="" hd="" hd_quoted="" hd_strip=""
while [[ -n "$rest" ]]; do
  # Copy the run of bytes that cannot change state, then handle one that can.
  case "$q" in
    "'") stop="[@']" ;;
    "\$'"|'"') stop="[@\\\\\"']" ;;
    *) stop="[@\\\\'\"<#"$'\n'"]" ;;
  esac
  pre="${rest%%$stop*}"
  out+="$pre"
  rest="${rest:${#pre}}"
  [[ -n "$rest" ]] || break
  c="${rest:0:1}"

  if [[ "$c" == "@" && "${rest:0:300}" =~ ^$ph_re ]]; then
    m="${BASH_REMATCH[0]}"
    if load "${BASH_REMATCH[1]}"; then
      case "$q" in
        "'")   out+="'\"\${$var}\"'" ;;
        "\$'") out+="'\"\${$var}\"\$'" ;;
        '"')   out+="\${$var}" ;;
        *)     out+="\"\${$var}\"" ;;
      esac
    else
      out+="$m"
    fi
    rest="${rest:${#m}}"
    continue
  fi

  case "$q" in
    "'") [[ "$c" == "'" ]] && q="" ;;
    "\$'"|'"')
      if [[ "$c" == "\\" ]]; then out+="${rest:0:2}"; rest="${rest:2}"; continue; fi
      [[ "$c" == "${q: -1}" ]] && q="" ;;
    *)
      case "$c" in
        "\\") out+="${rest:0:2}"; rest="${rest:2}"; continue ;;
        "'") if [[ "${out: -1}" == "\$" ]]; then q="\$'"; else q="'"; fi ;;
        '"') q='"' ;;
        "#")
          # A comment runs to the newline; nothing in it is code.
          if [[ -z "$out" || "${out: -1}" == [[:space:]\;\&\|\(\)] ]]; then
            pre="${rest%%$'\n'*}"; out+="$pre"; rest="${rest:${#pre}}"; continue
          fi ;;
        "<")
          if [[ "${rest:0:2}" == "<<" && "${rest:2:1}" != "<" && "${rest:2:300}" =~ $hd_re ]]; then
            m="${BASH_REMATCH[0]}" hd_strip="${BASH_REMATCH[1]}" hd="${BASH_REMATCH[2]}" hd_quoted=""
            if [[ "$hd" == *[\'\"\\]* ]]; then
              hd_quoted=1; hd="${hd//[\'\"\\]/}"
              # Unsure how bash reads this delimiter: don't treat it as a
              # heredoc at all (placeholders become plain references).
              if [[ ! "$hd" =~ ^[A-Za-z0-9_.-]+$ ]]; then hd=""; out+="<<"; rest="${rest:2}"; continue; fi
              # Rewrite as unquoted; hd_line escapes the body to match.
              out+="<<$hd_strip$hd"; rest="${rest:$((2 + ${#m}))}"; continue
            fi
            out+="<<"; rest="${rest:2}"; continue
          fi ;;
        $'\n')
          if [[ -n "$hd" ]]; then
            out+="$c"; rest="${rest:1}"
            # Heredoc body, line by line, up to and including the delimiter.
            # `read` over a here-string: slicing $rest per line is quadratic.
            used=0
            while IFS= read -r line; do
              used=$((used + ${#line} + 1))
              cmp="$line"; [[ -n "$hd_strip" ]] && cmp="${cmp#"${cmp%%[!$'\t']*}"}"
              if [[ "$cmp" == "$hd" ]]; then out+="$line"$'\n'; break; fi
              if [[ -n "$hd_quoted" ]]; then
                hd_line "$line" 1
              elif [[ "$line" =~ $ph_re ]]; then
                hd_line "$line" 0
              else
                out+="$line"$'\n'
              fi
            done <<<"$rest"
            rest="${rest:used}"
            hd=""
            continue
          fi ;;
      esac ;;
  esac
  out+="$c"
  rest="${rest:1}"
done

if [[ -n "$had_lc" ]]; then export LC_ALL="$saved_lc"; else unset LC_ALL; fi

eval "$out"
