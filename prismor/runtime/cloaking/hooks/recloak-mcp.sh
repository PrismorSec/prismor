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

response="$(printf '%s' "$input" | jq -r '.tool_response // empty')"
[[ -n "$response" ]] || exit 0

# Replace every registered secret's real value with its placeholder. Literal
# match via perl's \Q...\E, so regex metacharacters in a secret are inert.
# Not bash's ${var//"needle"/repl}: it is quadratic in the response size, and
# a multi-MB MCP response (browser screenshots) pinned the hook for minutes
# per secret. Not sed: the value would be a regex there. Trailing newlines
# are stripped from the secret file, matching $(cat). Skip missing/empty.
scrubbed="$(printf '%s' "$response" | SECRETS_DIR="$SECRETS_DIR" perl -0777 -pe '
  BEGIN {
    for my $f (glob("\Q$ENV{SECRETS_DIR}\E/*")) {
      next unless -f $f && open(my $fh, "<", $f);
      local $/; my $real = <$fh>; $real =~ s/\n+\z//;
      next unless length $real;
      (my $name = $f) =~ s{.*/}{};
      push @s, [$real, "\@\@SECRET:$name\@\@"];
    }
  }
  for my $p (@s) { s/\Q$p->[0]\E/$p->[1]/g }
')"

# Only mutate if something actually changed — avoids noisy empty mutations.
if [[ "$scrubbed" != "$response" ]]; then
  # stdin, not --arg: a multi-MB response overflows ARG_MAX and jq never runs.
  printf '%s' "$scrubbed" | jq -Rs \
    '{hookSpecificOutput:{hookEventName:"PostToolUse",updatedMCPToolOutput:.}}'
fi
