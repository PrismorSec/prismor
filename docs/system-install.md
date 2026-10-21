# System install (Linux and Windows fleets)

`prismor setup --scope global` hooks the agents of the user who runs it. An
MDM or config-management tool runs as root (or SYSTEM), so that covers the
admin and nobody else. A **system install** is one admin install that screens
every user on the machine, and that those users can't switch off.

```bash
# Linux, as root (MDM / Ansible / cloud-init)
python3 -m venv /opt/prismor
/opt/prismor/bin/pip install prismor
/opt/prismor/bin/prismor setup --system --mode enforce --recommended
/opt/prismor/bin/prismor enroll <TOKEN>          # optional: link the machine to your org
```

```powershell
# Windows, elevated or as SYSTEM (Intune, SCCM, GPO startup script)
py -3 -m venv "C:\Program Files\Prismor"
& "C:\Program Files\Prismor\Scripts\pip.exe" install prismor
& "C:\Program Files\Prismor\Scripts\prismor.exe" setup --system --mode enforce --recommended
& "C:\Program Files\Prismor\Scripts\prismor.exe" enroll <TOKEN>
```

For a fleet, mint a **fleet token** in the console (Devices → Fleet token):
one token, a use limit and an expiry, redeemed by every machine the script
runs on.

No user needs to run anything. The next time anyone on the machine starts
Claude Code, Codex, Cursor or Gemini CLI, its tool calls go through Prismor.

## What it writes

| Linux | Windows | What |
|---|---|---|
| `/etc/claude-code/managed-settings.d/50-prismor.json` | `C:\Program Files\ClaudeCode\managed-settings.d\50-prismor.json` | Claude Code hooks. A drop-in, so an existing `managed-settings.json` is left alone. |
| `/etc/codex/requirements.toml` | `C:\ProgramData\OpenAI\Codex\requirements.toml` | Codex managed hooks, with `[features].hooks = true` pinned. Added as a marked block, so an org's own requirements stay as they are. |
| `/etc/cursor/hooks.json` | `C:\ProgramData\Cursor\hooks.json` | Cursor enterprise hooks (merged with any already there) |
| `/etc/gemini-cli/settings.json` | `C:\ProgramData\gemini-cli\settings.json` | Gemini CLI system settings (merged) |
| `/etc/prismor/` | `C:\ProgramData\Prismor\` | Marker (`system.json`), rule selection (`policy.yaml`), the hook launcher, the device identity and the org policy cache |
| systemd `prismor-sync.timer` | scheduled task `Prismor System Sync` (SYSTEM) | Runs `prismor system-sync` every minute |

Everything is admin-owned and readable by every user, except the device key.
On Windows, `C:\ProgramData\Prismor` gets an explicit ACL (SYSTEM and
Administrators full control, Users read): by default any user may *create*
files in a ProgramData subfolder, which here would mean writing your own
`pause.json`. The folder paths come from the Windows known-folder API, so
repointing `%ProgramData%` changes nothing.

- **Claude Code** ranks managed settings above everything else and merges
  their hooks with the user's. A user's `"disableAllHooks": true` does not
  unload them.
- **Codex** treats hooks from its system `requirements.toml` as managed:
  trusted by policy (no per-user `/hooks` trust step), and still on when a
  user sets `[features] hooks = false`. If the org's file already declares
  `[features]` or `[hooks]`, TOML can't hold a second copy, so setup leaves the
  file alone, skips Codex and prints the block to merge by hand.
- **Cursor** documents enterprise hooks as highest priority, run alongside
  the user's, with any deny winning.
- **Gemini CLI** ranks system settings above user and project settings; its
  docs don't say whether hook lists merge across levels.

Other agents (Copilot CLI, Windsurf, …) have no machine-wide hook location
that Prismor writes yet; they still need a per-user `prismor setup --scope global`.

## What users can no longer change

Once the marker exists, everything that could weaken screening is the admin's:

- **Rule selection:** a user's `~/.prismor/policy.yaml` is ignored, and so is
  a repo's `.prismor/policy.yaml` (anyone can write one), unless the admin's
  policy sets `settings.allow_project_policy: true`.
- **Pause, unlock, floor-off:** `prismor pause` / `pause-hard` / `resume` and
  the unlock password are admin-only; an admin pause applies to every user.
- **Per-agent mode:** a local `agents.yaml` can tighten an agent but can't
  switch it to `observe`.
- **Workspace scope:** no workspace can be declared personal, so org policy
  applies everywhere on the machine.
- **One-shot approvals:** a user can't approve their own agent's blocked call
  from their terminal; the block message tells them to ask an admin.
- **The device key:** readable only by root / SYSTEM and Administrators.

`PRISMOR_HOME` still moves a user's working state (session store, caches),
but none of the above.

## The device key and `system-sync`

Users' hooks can't read the key, so they never talk to the control plane.
They read a key-less `identity-public.json`, which is enough to know the
machine is enrolled and to apply the org policy, and they spool telemetry in
their own `~/.prismor`. `prismor system-sync`, run every minute by the timer
or scheduled task, pulls the signed org policy into the system folder (every
user's hook verifies the signature before applying it) and uploads every
user's spooled telemetry with the device key.

## Requirements and checks

- Linux as root, or Windows elevated / as SYSTEM. Setup refuses otherwise.
- The interpreter and package must be reachable by every user, or their
  agents can't start the hook. Setup refuses a venv under `/root`, `/home` or
  `C:\Users`, and on Linux one built under `umask 077` (fix:
  `chmod -R a+rX /opt/prismor`).
- On Linux, directories setup creates are 0755 and files 0644 whatever the
  umask; it re-checks every file before reporting success.

For a detection or compliance script:

```bash
prismor enroll-status   # exit 0 = enrolled (or control plane unreachable), 1 = not enrolled / revoked
```

## Remove

```bash
prismor uninstall-hooks --scope system --agent all   # also removes the sync timer / task
rm -rf /etc/prismor                                  # Windows: Remove-Item -Recurse C:\ProgramData\Prismor
```

Both run without a terminal as an admin.

## Limits

- macOS system installs are not built yet.
- A user who relocates `PRISMOR_HOME` spools telemetry where `system-sync`
  doesn't look; their screening is unaffected.
- Users can't file console approval or exemption requests themselves (that
  needs the key); an admin does it for them.
