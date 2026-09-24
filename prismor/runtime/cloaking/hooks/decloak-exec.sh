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

# The secret value never enters the text that `eval` parses (#457). Each
# placeholder becomes a reference to an exported variable, written in the form
# that expands to exactly the value in the quoting context it sits in:
#   unquoted "${V}"   "double" ${V}   'single' '"${V}"'   $'ansi' '"${V}"$'
#   heredoc body ${V}   quoted-heredoc body: the raw text (never expanded).
# Placeholder grammar matches decloak.sh; an escaped colon is not matched, so
# the literal syntax can still be written.
# ponytail: a quote scanner, not a bash parser. Misreads (e.g. `<<` inside
# $((...))) can only mis-expand a reference, never execute a secret's content.
# Cost is linear in size but quadratic in quote count (~0.2s at 1k
# quotes); placeholder commands are small, so a real tokenizer can wait.

# Export secret $1 (once) and set $var to its variable name; the escaping keeps
# names injective (`_` -> `__`, `-` -> `_D`). decloak.sh already denied on a
# missing secret; if it vanished since, fail so the placeholder stays as-is
# rather than running with an empty credential silently substituted in.
load() {
  var="${1//_/__}"
  var="_PRISMOR_SECRET_${var//-/_D}"
  [[ -n "${!var+x}" ]] && return 0
  [[ -f "$SECRETS_DIR/$1" ]] || return 1
  export "$var=$(cat "$SECRETS_DIR/$1")"
}

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
    *) stop="[@\\\\'\"<"$'\n'"]" ;;
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
        "<")
          if [[ "${rest:0:2}" == "<<" && "${rest:2:1}" != "<" && "${rest:2:300}" =~ $hd_re ]]; then
            hd_strip="${BASH_REMATCH[1]}" hd="${BASH_REMATCH[2]}" hd_quoted=""
            if [[ "$hd" == *[\'\"\\]* ]]; then hd_quoted=1; hd="${hd//[\'\"\\]/}"; fi
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
              lo=""
              while [[ "$line" =~ $ph_re ]]; do
                m="${BASH_REMATCH[0]}" name="${BASH_REMATCH[1]}"
                lo+="${line%%"$m"*}"; line="${line#*"$m"}"
                if [[ -n "$hd_quoted" ]]; then
                  raw=""; [[ -f "$SECRETS_DIR/$name" ]] && raw="$(cat "$SECRETS_DIR/$name")"
                  chk="$raw"; [[ -n "$hd_strip" ]] && chk="${chk//$'\t'/}"
                  # A value line equal to the delimiter would end the heredoc early.
                  if [[ -z "$raw" || $'\n'"$chk"$'\n' == *$'\n'"$hd"$'\n'* ]]; then
                    lo+="$m"
                    [[ -n "$raw" ]] && echo "prismor: $m left unresolved: its value would end the heredoc" >&2
                  else
                    lo+="$raw"
                  fi
                elif load "$name"; then
                  lo+="\${$var}"
                else
                  lo+="$m"
                fi
              done
              out+="$lo$line"$'\n'
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
