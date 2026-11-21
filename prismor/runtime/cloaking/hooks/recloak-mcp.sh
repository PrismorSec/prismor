#!/usr/bin/env bash
# Prismor — cloaking PostToolUse hook (Claude Code, mcp__.* matcher).
#
# Scrubs any registered real secret value out of MCP tool responses, replacing
# it with the corresponding `@@SECRET:name@@` placeholder before the model
# sees it. Only MCP tools support `hookSpecificOutput.updatedMCPToolOutput` —
# built-in Bash uses the in-command sed-wrap from decloak.sh instead.
#
# Stdin:  Claude Code PostToolUse JSON payload
# Stdout: JSON with hookSpecificOutput.updatedMCPToolOutput (if anything was
#         scrubbed). Empty stdout = no-op.
set -uo pipefail

SECRETS_DIR="${PRISMOR_SECRETS_DIR:-$HOME/.prismor/secrets}"

if ! command -v jq >/dev/null 2>&1; then
  exit 0  # silent no-op; decloak.sh is the one that fails loud
fi

input="$(cat)"
tool_name="$(printf '%s' "$input" | jq -r '.tool_name // empty')"
[[ "$tool_name" == mcp__* ]] || exit 0

response="$(printf '%s' "$input" | jq -c '.tool_response // empty')"
[[ -n "$response" ]] || exit 0

# A key the vault has never seen (the MCP server read it from its own store)
# would reach the model raw: vault every pattern match first, under the same
# auto_<hash> name secret-guard.sh uses, so the scrub below replaces it too.
# shellcheck source=_patterns.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_patterns.sh"
SECRETS_DIR="$(prismor_secrets_dir)"   # same vault the other hooks use (honors PRISMOR_HOME)
prismor_load_patterns
if [[ "${#PATTERNS[@]}" -gt 0 ]]; then
  _gargs=()
  for pat in "${PATTERNS[@]}"; do _gargs+=(-e "$pat"); done
  if printf '%s' "$response" | grep -qE "${_gargs[@]}" 2>/dev/null; then
    mkdir -p "$SECRETS_DIR" && chmod 700 "$SECRETS_DIR" 2>/dev/null
    while IFS= read -r v; do
      [[ -n "$v" ]] || continue
      prismor_value_is_cloaked "$v" && continue
      f="$SECRETS_DIR/auto_$(printf '%s' "$v" | shasum -a 256 | cut -c1-8)"
      [[ -f "$f" ]] || { printf '%s' "$v" > "$f"; chmod 600 "$f" 2>/dev/null; }
    done < <(for pat in "${PATTERNS[@]}"; do printf '%s' "$response" | grep -oE "$pat" || true; done | awk 'NF && !seen[$0]++')
  fi
fi

# (value, placeholder) pairs, longest value first, as JSON for jq. Built by
# perl from the vault files and handed over a /dev/fd pipe, never argv. Each
# secret is listed raw AND in its JSON-escaped form: a string field can hold
# a JSON document whose text carries `\"` / `\\` / `\n` where the secret had
# `"` / `\` / a newline. Trailing newlines are stripped from the secret file,
# matching $(cat).
_pairs() {
  SECRETS_DIR="$SECRETS_DIR" perl -MJSON::PP -e '
    my $js = JSON::PP->new->allow_nonref;   # character strings in, out
    for my $f (glob("\Q$ENV{SECRETS_DIR}\E/*")) {
      next unless -f $f && open(my $fh, "<:raw", $f);
      local $/; my $real = <$fh>; $real =~ s/\n+\z//;
      utf8::decode($real);
      # Mirrors is_scrubbable_secret() in ../runtime.py: a short single-case
      # word ("ses", "false") is config, and masking it mangled every
      # "session" and boolean in browser/MCP output.
      my $n = length $real;
      next if $real =~ m{\A[A-Za-z][A-Za-z0-9+.-]*://[A-Za-z0-9.-]+(?::[0-9]+)?/?\z};  # bare origin (#930)
      next unless $n >= 16 || ($n >= 8 && ($real =~ /[[:digit:]]|[^[:alnum:]]/ || ($real =~ /[[:lower:]]/ && $real =~ /[[:upper:]]/)));
      (my $name = $f) =~ s{.*/}{};
      my $ph = "\@\@SECRET:$name\@\@";
      push @s, [$real, $ph];
      my $esc = substr($js->encode($real), 1, -1);
      push @s, [$esc, $ph] if $esc ne $real;
    }
    print JSON::PP->new->utf8->encode([sort { length($b->[0]) <=> length($a->[0]) } @s]);
  '
}

# Scrub every string in the DECODED response (jq split/join is a literal,
# linear replace), so a secret holding `"`, `\` or a control char is matched
# as itself rather than as the escaped text `jq -r` used to print. Not bash's
# ${var//"needle"/repl}: quadratic on multi-MB responses (screenshots).
scrubbed="$(printf '%s' "$response" | jq -c --slurpfile S <(_pairs) '
  def scrub: reduce $S[0][] as $p (.; split($p[0]) | join($p[1]));
  walk(if type == "string" then scrub else . end)')" || exit 0

# Only mutate if something actually changed — avoids noisy empty mutations.
if [[ -n "$scrubbed" && "$scrubbed" != "$response" ]]; then
  # shellcheck source=_ledger.sh
  source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_ledger.sh"
  session_id="$(printf '%s' "$input" | jq -r '.session_id // empty')"
  # One event per secret whose placeholder now appears in the scrubbed output
  # but not in the original (names only; the value never leaves perl).
  while IFS= read -r ph; do
    [[ -n "$ph" && "$response" != *"$ph"* ]] || continue
    name="${ph#@@SECRET:}"
    prismor_cloak_event mcp_output redacted "$session_id" "${name%@@}" "" "$tool_name"
  done < <(printf '%s' "$scrubbed" | grep -oE '@@SECRET:[a-zA-Z0-9_-]+@@' | sort -u)
  # stdin, not --arg: a multi-MB response overflows ARG_MAX and jq never runs.
  # Same JSON type back: a string stays a string, an object stays an object.
  printf '%s' "$scrubbed" | jq -c \
    '{hookSpecificOutput:{hookEventName:"PostToolUse",updatedMCPToolOutput:.}}'
fi
