# Pause, resume and login

Two machine-level commands that don't fit anywhere else: pausing enforcement
without uninstalling anything, and connecting the machine to the Prismor API
for the hosted judge.

## Pause and resume

```bash
prismor pause                    # stop blocking for 24h, keep screening and logging
prismor pause --for 2h --reason "release hotfix"
prismor pause-hard               # stop blocking until you run prismor resume
prismor resume                   # start blocking again
```

`pause` suspends **enforcement only**. The hooks stay installed and every tool
call is still screened, recorded and sent to your sinks as if the workspace were
in observe mode, so nothing goes dark and the audit trail has no gap. A blocked
call while paused shows up as a finding that would have blocked.

The non-overridable floor keeps blocking while paused: destructive commands,
secret exfiltration, remote execution, privilege escalation and Prismor's own
self-protection rules (an agent rewriting its hooks or policy). A pause is for
getting work past a rule that is in your way, not for running `rm -rf /`.

- `pause` auto-resumes after 24 hours, or after `--for` (`30m`, `2h`, `1d`). The
  expiry is checked on every hook call, so protection comes back even if nobody
  runs `prismor resume`.
- `pause-hard` has no expiry; it lasts until `prismor resume`.
- `--reason` is shown in the console next to the device.
- `prismor status` shows `Paused: yes` while a pause is active.
- State lives in `~/.prismor/pause.json` (or `$PRISMOR_HOME/pause.json`).

**Agents can't pause Prismor.** `prismor pause`, `pause-hard` and `resume` are
self-protected: an agent that runs them is blocked, unless you have opened an
unlock window with `prismor unlock`. Run them yourself in a terminal.

**Enrolled devices.** An admin can pause or resume a device from the console.
The command arrives in the signed policy:

- An org pause wins outright; `prismor resume` can't lift it.
- An org resume clears a local pause that is older than it, so an admin can
  bring back a machine they have no shell on. A later local `prismor pause`
  still applies.
- While paused, the device keeps sending a heartbeat on each prompt, so the
  console shows it as *paused* rather than idle.

To stop screening entirely for one agent, uninstall its hooks instead
(`prismor uninstall-hooks --agent <name>`).

## Login: the hosted judge

```bash
prismor login                    # opens a browser to approve this machine
prismor login --no-browser       # print the approval link instead
prismor login --set-judge        # also make the Prismor API this workspace's judge
```

`prismor login` connects this machine to the Prismor API with a device sign-in:
the CLI shows a short code, you approve that code in a browser where you're
signed in to Prismor, and the CLI receives a device key. The long device code it
polls with is never displayed.

The connection gives you the hosted [semantic judge](semantic-guard.md)
(`semantic_guard.provider: prismor`), with 1,000 free verdicts a month. To use
it in a workspace, pass `--set-judge`, or pick **Prismor API** as the judge in
`prismor setup`. `prismor status` shows how many verdicts are left this month.

| Flag | Effect |
|---|---|
| `--no-browser` | Print the approval link instead of opening a browser |
| `--label NAME` | Name shown for this machine (default: the hostname) |
| `--api-base URL` | Control-plane base URL (default: `$PRISMOR_API_BASE`) |
| `--force` | Replace the identity already stored on this machine |
| `--set-judge` | Also set `semantic_guard.provider: prismor` for this workspace |

Running `prismor login` on a machine that is already connected prints its
organization and remaining verdicts instead of signing in again.

Login stores the device key as this machine's identity, in the same file
`prismor enroll` uses (`~/.prismor/identity.json`, mode 0600), under your
account's organization. The machine is then connected like an enrolled device:
`prismor enroll-status` shows it and `prismor logout` removes it. To put a
machine under a team's organization with a token an admin minted, use
`prismor enroll <token>` instead; see
[Connecting to the platform](connecting-to-the-platform.md).

See also: [CLI reference](cli-reference.md) · [Semantic Guard](semantic-guard.md).
