# Installation

Full detail behind the three methods in the [README Quick Start](../README.md#quick-start), plus the less-common paths.

| | Platform | Install | Notes |
|---|---|---|---|
| <img src="https://svgl.app/library/apple.svg" width="16" height="16" alt=""> | macOS | curl, pip, clone | everything supported |
| <img src="https://svgl.app/library/linux.svg" width="16" height="16" alt=""> | Linux | curl, pip, clone | everything supported |
| <img src="https://svgl.app/library/windows.svg" width="16" height="16" alt=""> | Windows | pip | hooks, policy and audit trail; [see below](#windows) |

## Curl

```bash
curl -sSL https://prismor.dev/install | sh
```

Detects your environment and uses the right install method automatically.

## Skill (zero-interrupt setup)

Point your agent at [`SKILL.md`](../SKILL.md). It is a standing instruction file: the agent reads it at session start, checks whether Prismor is installed, and follows the decision tree throughout the session without pausing your workflow.

For Claude Code, add to your `CLAUDE.md`:

```markdown
Read `SKILL.md` and follow its instructions for runtime security.
```

Or via raw URL (works in any agent config file: CLAUDE.md, AGENTS.md, .cursorrules, .windsurfrules):

```markdown
Read `https://raw.githubusercontent.com/PrismorSec/prismor/main/SKILL.md` and follow its instructions.
```

See [`SKILL.md`](../SKILL.md) for the full decision tree and hard rules.

## Pip

```bash
pip install prismor
prismor setup          # interactive onboarding wizard
```

`prismor setup` lets you pick enforcement mode, choose which rules block (enforce mode starts with nothing selected and the safety floor marked *recommended*), select agents, optionally enable secret cloaking, and optionally set an unlock password for the agent self-edit window. Pass `--non-interactive` to skip the TUI (`--recommended` or `--enforce-rules id1,id2` picks the blocking set). See [Choosing what blocks](cli-reference.md#choosing-what-blocks).

**Installing through an agent.** When a coding agent (Claude Code, Codex, Cursor, Gemini CLI) runs a bare `prismor setup`, there is no terminal for the wizard, so setup installs nothing and prints the wizard's questions with the exact flags for each answer. The agent asks you, then runs the `--non-interactive` command. Scripts outside an agent, such as a cloud start hook, still install with defaults, and any explicit flag skips the questions.

## Git clone + wizard

```bash
pip3 install pyyaml                          # on Debian/Ubuntu use: sudo apt install python3-yaml
git clone https://github.com/PrismorSec/prismor.git ~/.prismor
PRISMOR_MODE=enforce PRISMOR_CLOAK=1 bash ~/.prismor/scripts/init.sh .
```

If you are testing from a source checkout on a machine that already has a
different `prismor` install, use the repo shim for health checks:

```bash
python3 ~/.prismor/bin/prismor --version
python3 ~/.prismor/bin/prismor status
```

That path forces imports to resolve to the checked-out runtime instead of a
stale package earlier on `sys.path`.

> On externally-managed Pythons (PEP 668 — Ubuntu 23.04+, Homebrew) `pip3 install` refuses to run; install PyYAML from your system package manager instead (`sudo apt install python3-yaml`, `brew install pyyaml`, …). `init.sh` will tell you if it's missing.

This installs enforce-mode Prismor hooks and the Cloak prevention layer. To register a secret, run `prismor cloak add stripe_key` and enter the value when prompted. To import an entire dotenv file at once, run `prismor cloak add --env-file .env`. Claude/Hermes can auto-decloak placeholders at the tool boundary. Codex hooks are block-only, so run placeholder commands through `prismor cloak run -- <command>`.

### Codex needs a one-time trust step

Codex refuses to run a hook until you have trusted it, and it records that consent
per hook in `~/.codex/config.toml`. Until then the hooks Prismor installed are
written, `prismor status` can list them, and **nothing is screened**: Codex logs
each hook event and skips the command. Verified against codex-cli 0.145.0.

After `prismor setup` or `prismor install-hooks --agent codex`, open `codex`
interactively once in the workspace and accept the hook-trust prompt. For headless
or CI runs, pass `codex exec --dangerously-bypass-hook-trust`. `prismor status` and
`prismor doctor` say when the hooks are still untrusted, and the install prints
the same warning.

Prefer the interactive wizard? Drop the env vars:

```bash
bash ~/.prismor/scripts/init.sh .
```

## Windows

<img src="https://svgl.app/library/windows.svg" width="16" height="16" alt=""> Install with pip and run the wizard — the curl installer and `init.sh` are
shell scripts and are not the path here:

```powershell
pip install prismor
prismor setup
```

CI runs `prismor setup` on `windows-latest`, and the enforcement path is
verified end to end on Windows Server 2022 with Claude Code: setup exits 0, the
hook fires in a real session, a floor rule blocks, and the audit trail is
written and signed.

What is different under the hood:

- **Hooks run through a shim.** Agent configs store a hook as a *shell string*,
  and the shell on Windows is `cmd.exe`, which has no `VAR=value cmd` syntax.
  `prismor setup` writes `hook-dispatch.py` into `$PRISMOR_HOME` and registers
  `"<python>" "<shim>" hook-dispatch ...` — the one command shape `sh` and
  `cmd.exe` both accept. The shim does the `sys.path` fix-up the old
  `PYTHONPATH` prefix did, so hooks survive a launcher that strips user
  site-packages. If you edit hooks by hand, keep that shape: a broken hook
  fails *open* (agents treat hook failure as non-blocking), which reads as
  "installed" while screening nothing.
- **Threat-feed signatures need the `cryptography` extra.** There is no
  `openssl` to shell out to, so install `pip install "prismor[signing]"` — the
  same extra that signs the [audit trail](audit-trail.md). Without it, setup
  reports the verification as skipped rather than failed.

Not yet on Windows:

- **[Cloak](sweep-and-cloak.md)** — its hooks are bash scripts registered by
  path, so `cmd.exe` cannot run them. Use it from WSL or Git Bash.
