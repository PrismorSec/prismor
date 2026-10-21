# System install (Linux fleets)

`prismor setup --scope global` hooks the agents of the user who runs it. An
MDM or config-management tool runs as root, so that covers root and nobody
else. A **system install** is one root install that screens every user on the
machine, and that those users can't switch off.

```bash
# as root, from your MDM / Ansible / cloud-init script
python3 -m venv /opt/prismor
/opt/prismor/bin/pip install prismor
/opt/prismor/bin/prismor setup --system --mode enforce --recommended
/opt/prismor/bin/prismor enroll <TOKEN>          # optional: link the machine to your org
```

No user needs to run anything. The next time anyone on the machine starts
Claude Code, Codex, Cursor or Gemini CLI, its tool calls go through Prismor.

## What it writes

| Path | What |
|---|---|
| `/etc/claude-code/managed-settings.d/50-prismor.json` | Claude Code hooks. A drop-in, so an existing `managed-settings.json` is left alone. |
| `/etc/cursor/hooks.json` | Cursor enterprise hooks (merged with any already there) |
| `/etc/gemini-cli/settings.json` | Gemini CLI system settings (merged) |
| `/etc/codex/requirements.toml` | Codex managed hooks, with `[features].hooks = true` pinned and `managed_dir = "/etc/prismor"`. Added as a marked block, so an org's own requirements stay as they are. |
| `/etc/prismor/system.json` | Marks the machine as system-managed |
| `/etc/prismor/policy.yaml` | The rule selection (`--recommended` / `--enforce-rules`) |
| `/etc/prismor/hook-dispatch.py` | The launcher every user's hook runs |
| `/etc/prismor/identity.json` | The device identity, after `prismor enroll` |

All of them are root-owned and world-readable.

- **Claude Code** ranks managed settings above everything else and merges
  their hooks with the user's. A user's `"disableAllHooks": true` does not
  unload them (verified with Claude Code 2.1.306).
- **Cursor** documents enterprise hooks as highest priority, run alongside
  the user's, with any deny winning.
- **Codex** treats hooks from its system `requirements.toml` as managed:
  trusted by policy (no `/hooks` trust step per user), not disableable from
  the hook browser, and still on when a user sets `[features] hooks = false`
  (verified with codex-cli 0.163.0). If the org's file already declares
  `[features]` or `[hooks]`, TOML can't hold a second copy, so setup leaves
  the file alone, skips Codex and prints the block to merge by hand.
- **Gemini CLI** ranks system settings above user and project settings; its
  docs don't say whether hook lists merge across levels.

Other agents (Copilot CLI, Windsurf, …) have no machine-wide hook
location that Prismor writes yet; `--agents` skips them with a note, and they
still need a per-user `prismor setup --scope global`.

## What users can no longer change

Once `/etc/prismor/system.json` exists, every file that could weaken
screening is read from `/etc/prismor` instead of `~/.prismor`:

- the rule selection: a user's `~/.prismor/policy.yaml` is ignored;
- `prismor pause` / `pause-hard` / `resume`: root-only, and a root pause
  applies to every user;
- `prismor unlock` and the floor-off switches: the password is root's;
- the device identity: everyone reports as the enrolled machine.

`PRISMOR_HOME` still moves a user's working state (session store, caches),
but not these. A repo's own `.prismor/policy.yaml` still applies as a project
layer, and an org policy pulled from the console applies on top, as on any
enrolled device.

## Requirements and checks

- Linux, run as root. Setup refuses otherwise.
- The Python interpreter and the installed package must be readable by other
  users, or their agents can't start the hook. Setup refuses a venv under
  `/root` or `/home`, and one built under `umask 077` (fix:
  `chmod -R a+rX /opt/prismor`).
- Directories setup creates are 0755 and files 0644, whatever the umask. It
  re-checks that every file is reachable before it reports success.

For a detection or compliance script:

```bash
prismor enroll-status   # exit 0 = enrolled (or control plane unreachable), 1 = not enrolled / revoked
test -f /etc/prismor/system.json
```

## Remove

```bash
prismor uninstall-hooks --scope system --agent all
rm -rf /etc/prismor
```

Both run without a terminal as root.

## Limits

- Any local user can read `/etc/prismor/identity.json`, so a user could report
  to your org as this machine. Agents are blocked from reading it.
- macOS and Windows system installs are not built yet.
