#!/bin/bash
# End-to-end check of `prismor setup --system` on a throwaway Linux or macOS
# machine (CI runner or container). Run as root. Installs the wheel machine-
# wide, creates a standard user `dev`, and drives real Claude Code and Codex
# as that user against local mock model APIs (no credentials): destructive
# calls must be blocked with no per-user setup, and the user's ways of
# switching screening off must not work.
#
#   sudo WHEEL=dist/prismor-*.whl PYTHON=python3 scripts/e2e/system_install/run.sh
#   sudo INSTALL=pkg PKG=out/prismor-X-macos.pkg PYTHON=python3 scripts/e2e/system_install/run.sh
#
# INSTALL=pkg installs the macOS MDM package instead of a venv, the way Jamf
# would: a configuration profile (dev.prismor) carries the fleet token, and
# the postinstall enrolls against the mock control plane.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
OS=$(uname -s)
FAILS=0
ok(){ echo "  PASS $*"; }; bad(){ echo "  FAIL $*"; FAILS=$((FAILS+1)); }
step(){ echo; echo "=== $*"; }
mode_of(){ if [ "$OS" = Darwin ]; then stat -f %Lp "$1"; else stat -c %a "$1"; fi; }
owner_of(){ if [ "$OS" = Darwin ]; then stat -f %Su "$1"; else stat -c %U "$1"; fi; }
if [ "$OS" = Darwin ]; then
  SYS="/Library/Application Support/Prismor"; CLAUDE_MANAGED="/Library/Application Support/ClaudeCode/managed-settings.d/50-prismor.json"
else
  SYS=/etc/prismor; CLAUDE_MANAGED=/etc/claude-code/managed-settings.d/50-prismor.json
fi
PRISMOR=/opt/prismor/bin/prismor
INSTALL=${INSTALL:-venv}
if [ "$INSTALL" = pkg ]; then RT_PY=/opt/prismor/current/bin/python3; else RT_PY=/opt/prismor/bin/python3; fi

step "0. a standard user with Claude Code and Codex of their own"
if [ "$OS" = Darwin ]; then
  sysadminctl -addUser dev -password "Dev-$RANDOM-pw!" -home /Users/dev >/dev/null 2>&1; createhomedir -c -u dev >/dev/null 2>&1
else
  useradd -m -s /bin/bash dev
fi
DH=$(eval echo ~dev); echo "  dev home: $DH ($(id dev))"
as_dev(){ sudo -u dev -H env PATH="$DH/npm/bin:${TOOL_PATH:-}:/usr/local/bin:/usr/bin:/bin" bash -c "cd '$DH' && $1"; }
as_dev "npm i -g -s --prefix ~/npm @anthropic-ai/claude-code@latest @openai/codex@latest >/dev/null 2>&1"
echo "  $(as_dev 'claude --version') / $(as_dev 'codex --version')"
as_dev "mkdir -p ~/.codex ~/pt && printf 'model = \"mock-model\"\nmodel_provider = \"mock\"\n[model_providers.mock]\nname = \"mock\"\nbase_url = \"http://127.0.0.1:8788/v1\"\nwire_api = \"responses\"\nenv_key = \"MOCK_KEY\"\n' > ~/.codex/config.toml"
# The mocks run from this (root) shell: on macOS a background job started
# inside `sudo -u dev bash -c` dies with that sudo session.
MOCK_CMD='rm -rf ~/canary' MOCK_LOG="$DH/pt/anthropic.log" nohup $PYTHON "$HERE/mock_anthropic.py" >/tmp/mock-a.err 2>&1 &
MOCK_CMD='chmod -R 777 ~/canary' MOCK_LOG="$DH/pt/openai.log" nohup $PYTHON "$HERE/mock_openai.py" >/tmp/mock-o.err 2>&1 &
MOCK_LOG=/tmp/cp.log nohup $PYTHON "$HERE/mock_cp.py" >/tmp/mock-cp.err 2>&1 &
sleep 2
curl -s -o /dev/null -w "  mock anthropic: HTTP %{http_code}\n" http://127.0.0.1:8787/ ; curl -s -o /dev/null -w "  mock openai: HTTP %{http_code}\n" http://127.0.0.1:8788/v1/models

step "1. machine-wide install under a strict umask (as an MDM agent would)"
umask 077
if [ "$INSTALL" = pkg ]; then
  # What Jamf delivers: a configuration profile, then the package.
  # An MDM drops the profile's plist here (managed domains are read-only to
  # `defaults write`, so write the file the way mdmclient would).
  mkdir -p "/Library/Managed Preferences"
  MP="/Library/Managed Preferences/dev.prismor.plist"
  /usr/libexec/PlistBuddy -c "Add :FleetToken string fleet-ci-token" -c "Add :ApiBase string http://127.0.0.1:8790" "$MP" >/dev/null
  chmod 644 "$MP"
  installer -pkg "$PKG" -target / >/tmp/installer.log 2>&1; rc=$?
  tail -3 /var/log/prismor-install.log 2>/dev/null
else
  $PYTHON -m venv /opt/prismor && /opt/prismor/bin/pip install -q "$WHEEL" 2>&1 | grep -v notice | tail -1
  chmod -R a+rX /opt/prismor   # a venv built under umask 077 is root-only; setup refuses it otherwise
  $PRISMOR setup --system --mode enforce --recommended </dev/null; rc=$?
fi
umask 022
[ $rc -eq 0 ] && ok "install ($INSTALL)" || { bad "install ($INSTALL) exit $rc"; cat /tmp/installer.log 2>/dev/null; tail -20 /var/log/prismor-install.log 2>/dev/null; }
for f in "$CLAUDE_MANAGED" "$SYS/policy.yaml" "$SYS/system.json" "$SYS/hook-dispatch.py" /etc/codex/requirements.toml; do
  m=$(mode_of "$f" 2>/dev/null); [ "$m" = 644 ] && ok "$f 644" || bad "$f mode=$m"; done

step "2. refusals"
as_dev "$PRISMOR setup --system --mode enforce" >/tmp/o 2>&1 && bad "dev ran setup --system" || ok "non-root setup --system refused"
if [ "$INSTALL" = pkg ]; then
  $PRISMOR enroll-status >/dev/null 2>&1; [ $? -eq 0 ] && ok "enrolled by the package from the profile's fleet token" || bad "pkg did not enroll"
  grep -q "ENROLL .*ok=True" /tmp/cp.log && ok "control plane saw the enrollment" || bad "no enroll call"
  ea=$(/opt/prismor/bin/jamf-extension-attribute.sh); echo "  extension attribute: $ea"
  echo "$ea" | grep -q "<result>[0-9.]* enrolled</result>" && ok "Jamf extension attribute" || bad "extension attribute: $ea"
  [ -L /opt/prismor/current ] && ok "current -> $(readlink /opt/prismor/current)" || bad "no current symlink"
  [ "$(ls /opt/prismor/runtime/*/ | tr -d '\n')" = "$(uname -m | sed 's/aarch64/arm64/')" ] && ok "only this Mac's architecture kept" || bad "runtime arches: $(ls /opt/prismor/runtime/*/)"
  grep -q "/opt/prismor/current/bin/python3" "$CLAUDE_MANAGED" && ok "hooks run the bundled runtime" || bad "hook command: $(grep -o '"command": "[^"]*' "$CLAUDE_MANAGED" | head -1)"
else
  $PRISMOR enroll-status >/dev/null 2>&1; [ $? -eq 1 ] && ok "enroll-status exits 1 before enrollment" || bad "enroll-status exit code"
fi

reset_canary(){ rm -rf "$DH/canary"; as_dev "mkdir -m 755 ~/canary && touch ~/canary/keep"; }
blocked(){ [ -f "$DH/canary/keep" ] && [ "$(mode_of "$DH/canary")" = 755 ] && grep -q -E "Prismor blocked|blocked by PreToolUse hook" "$1"; }
run_claude(){  # $1 label, $2 dir
  reset_canary; : > "$DH/pt/anthropic.log"
  as_dev "cd '${2:-$DH}' && ANTHROPIC_BASE_URL=http://127.0.0.1:8787 ANTHROPIC_API_KEY=sk-ant-mock perl -e 'alarm shift; exec @ARGV' 180 claude -p 'clean up' --dangerously-skip-permissions --max-turns 3 </dev/null >~/pt/claude.out 2>&1"
  blocked "$DH/pt/anthropic.log" && ok "claude: $1" || { bad "claude: $1"; tail -5 "$DH/pt/claude.out"; tail -3 "$DH/pt/anthropic.log"; }
}
run_codex(){
  reset_canary; : > "$DH/pt/openai.log"
  as_dev "MOCK_KEY=x perl -e 'alarm shift; exec @ARGV' 180 codex exec --skip-git-repo-check --dangerously-bypass-approvals-and-sandbox 'clean up' </dev/null >~/pt/codex.out 2>&1"
  blocked "$DH/pt/openai.log" && ok "codex: $1" || { bad "codex: $1"; tail -5 "$DH/pt/codex.out"; tail -3 "$DH/pt/openai.log"; }
}

step "3. blocked with no per-user setup"
run_claude "managed hook"
run_codex "managed hook, no trust step"

step "4. the user tries to switch it off"
as_dev 'mkdir -p ~/.claude && echo "{\"disableAllHooks\": true}" > ~/.claude/settings.json'; run_claude "disableAllHooks"; as_dev 'rm ~/.claude/settings.json'
as_dev 'printf "\n[features]\nhooks = false\n" >> ~/.codex/config.toml'; run_codex "[features] hooks = false"
as_dev 'mkdir -p ~/.prismor && printf "version: \"1.0\"\nsettings:\n  selection: explicit\n  default_mode: observe\n" > ~/.prismor/policy.yaml'; run_claude "weak ~/.prismor/policy.yaml"
as_dev 'mkdir -p ~/repo/.prismor && cp ~/.prismor/policy.yaml ~/repo/.prismor/policy.yaml'; run_claude "weak repo .prismor/policy.yaml" "$DH/repo"
as_dev "$PRISMOR pause" >/tmp/o 2>&1; [ $? -ne 0 ] && grep -q "admin-only" /tmp/o && ok "prismor pause refused" || { bad "pause"; cat /tmp/o; }
as_dev "touch '$SYS/pause.json'" 2>/dev/null && bad "dev created pause.json" || ok "dev can't create pause.json"

step "5. admin pause reaches every user"
$PRISMOR pause --for 10m >/dev/null 2>&1
reset_canary; as_dev "ANTHROPIC_BASE_URL=http://127.0.0.1:8787 ANTHROPIC_API_KEY=sk-ant-mock perl -e 'alarm shift; exec @ARGV' 180 claude -p x --dangerously-skip-permissions --max-turns 3 </dev/null >/dev/null 2>&1"
[ ! -f "$DH/canary/keep" ] && ok "paused: the command ran" || bad "admin pause did not reach dev"
$PRISMOR resume >/dev/null 2>&1; run_claude "blocked again after resume"

step "6. device key: admin-only; users keyless; the admin sync uploads their telemetry"
[ "$INSTALL" = pkg ] || $RT_PY -c "from prismor.runtime.enterprise import identity as i; i.save_identity({'device_id':'d-ci','org_id':'o','label':'ci','device_key':'prism_dev_FAKE','api_base':'http://127.0.0.1:8790'})"
[ "$(mode_of "$SYS/identity.json")" = 600 ] && ok "identity.json 600" || bad "identity.json mode $(mode_of "$SYS/identity.json")"
as_dev "cat '$SYS/identity.json'" >/dev/null 2>&1 && bad "dev read the key" || ok "dev can't read the key"
as_dev "$PRISMOR enroll-status" >/tmp/o 2>&1; [ $? -eq 0 ] && grep -q "system install" /tmp/o && ok "dev: enrolled via system install" || { bad "dev enroll-status"; cat /tmp/o; }
run_claude "blocked while keyless"
as_dev "$RT_PY -c \"from prismor.runtime import sinks; sinks.upload_telemetry([{'id':'e-dev','verdict':'blocked'}])\""
[ -s "$DH/.prismor/telemetry-spool.jsonl" ] && ok "dev telemetry spooled" || bad "nothing spooled"
$PRISMOR system-sync || true
grep -q "auth=Bearer prism_dev_FAK" /tmp/cp.log 2>/dev/null && ok "admin sync uploaded with the key" || { bad "control plane got nothing"; cat /tmp/cp.log 2>/dev/null; }
[ ! -s "$DH/.prismor/telemetry-spool.jsonl" ] && ok "dev spool drained" || bad "spool not drained"
[ ! -e "$DH/.prismor/telemetry-spool.jsonl" ] || [ "$(owner_of "$DH/.prismor/telemetry-spool.jsonl")" = dev ] && ok "spool still dev's" || bad "spool owner $(owner_of "$DH/.prismor/telemetry-spool.jsonl")"
if [ "$OS" = Darwin ]; then launchctl print system/dev.prismor.system-sync >/dev/null 2>&1 && ok "LaunchDaemon loaded" || bad "LaunchDaemon not loaded"
elif [ -d /run/systemd/system ]; then systemctl is-active --quiet prismor-sync.timer && ok "systemd timer active" || bad "timer not active"; fi

if [ "$INSTALL" = pkg ]; then
  step "6b. upgrade: install the package again over itself"
  installer -pkg "$PKG" -target / >/tmp/installer.log 2>&1 && ok "reinstall" || bad "reinstall failed"
  run_claude "blocked after reinstall"
  [ "$(ls /opt/prismor/runtime | wc -l | tr -d ' ')" = 1 ] && ok "one runtime version on disk" || bad "runtimes: $(ls /opt/prismor/runtime)"
fi

step "7. uninstall"
if [ "$INSTALL" = pkg ]; then
  /opt/prismor/bin/prismor-uninstall >/dev/null 2>&1
  [ ! -e /opt/prismor ] && ok "/opt/prismor removed" || bad "/opt/prismor left"
  pkgutil --pkgs | grep -q dev.prismor.system && bad "package receipt left" || ok "package receipt forgotten"
else
  $PRISMOR uninstall-hooks --scope system --agent all >/dev/null 2>&1
fi
[ ! -e "$CLAUDE_MANAGED" ] && ok "Claude drop-in removed" || bad "Claude drop-in left"
[ ! -e /etc/codex/requirements.toml ] && ok "Codex requirements removed" || bad "requirements.toml left"
if [ "$OS" = Darwin ]; then launchctl print system/dev.prismor.system-sync >/dev/null 2>&1 && bad "LaunchDaemon still loaded" || ok "LaunchDaemon removed"; fi

echo; echo "FAILS=$FAILS"; [ $FAILS -eq 0 ]
