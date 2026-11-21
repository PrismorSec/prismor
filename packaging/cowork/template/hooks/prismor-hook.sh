#!/bin/sh
# Cowork runs plugin hooks inside its own Linux sandbox, where no host Prismor
# install exists, so this runs the runtime bundled in vendor/. Blocking needs
# no network; console reporting needs agent.key and www.prismor.dev on the
# sandbox's allowed domains.
# The desktop app also runs synced plugins in local sessions on the user's own
# machine. vendor/ is built for Linux, and a laptop is governed by its own
# Prismor install, so step aside there instead of screening twice and
# reporting the laptop under the plugin's key.
# ponytail: OS check, so a local session on a Linux desktop still runs this.
[ "$(uname -s)" = Linux ] || exit 0
ROOT="${CLAUDE_PLUGIN_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
export PRISMOR_HOME="${CLAUDE_PLUGIN_DATA:-${TMPDIR:-/tmp}/prismor-cowork}"
mkdir -p "$PRISMOR_HOME"
cmp -s "$ROOT/policy.yaml" "$PRISMOR_HOME/policy.yaml" 2>/dev/null || cp "$ROOT/policy.yaml" "$PRISMOR_HOME/policy.yaml"
export PRISMOR_NO_UPDATE_CHECK=1 PRISMOR_NO_DEPRECATION=1 PRISMOR_PRICING_OFFLINE=1
[ -s "$ROOT/agent.key" ] && export PRISMOR_AGENT_KEY="$(cat "$ROOT/agent.key")"
export PYTHONPATH="$ROOT/vendor"
ERR="$PRISMOR_HOME/.last-stderr"
python3 -m prismor.runtime.immunity_cli hook-dispatch --agent claude --mode enforce 2>"$ERR"
rc=$?
if [ $rc -eq 2 ]; then
  # The runtime's unblock steps are CLI commands for a developer's own machine;
  # nobody can run them in a Cowork sandbox.
  sed -n '1,2p' "$ERR" >&2
  echo "This runs in a Cowork sandbox, so it can't be unblocked here. If the action is legitimate, ask your Prismor admin for an exception in the console. Do not try another way around the block." >&2
else
  cat "$ERR" >&2
fi
exit $rc
