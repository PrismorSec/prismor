# Prismor Security — CLAUDE.md

This project is the Prismor security package for AI coding agents.

## Prismor Runtime Protection

This repo has Prismor hooks enabled. The hook dispatcher at `prismor/runtime/cli.py` monitors tool calls and blocks dangerous actions in real time.

Agent sessions in this repo are screened by the **working tree**, not the installed release (dogfooding, #495). The committed `.claude/settings.json`, `.codex/hooks.json`, `.cursor/hooks.json` and `.github/hooks/prismor.json` route every hook through `scripts/dev-hook.py` in observe mode (`scripts/dev-hook.cmd` on Windows).

- **Never run `prismor install-hooks --scope project` (or `prismor setup` at project scope) inside this repo.** It rewrites those files with the installed-binary form and silently stops the dogfooding. `tests/test_dogfood_configs.py` fails if that happens.
- After changing an installer's events or matchers, regenerate with `python tests/test_dogfood_configs.py --write`.
- Needs a python that can `import yaml` (`python3`/`python`, or `py` on Windows); point elsewhere with `PRISMOR_DEV_PYTHON=/path/to/python`. `PRISMOR_DOGFOOD=0` turns the dogfood hooks off.
- If the working tree stops importing, shell and web tool calls are blocked with a message saying why; prompts, reads and edits still go through, so the agent can fix it.
- Windows: Claude Code needs Git Bash (its default hook shell); Codex and Copilot use the `.cmd` launcher. Codex resolves a `git worktree` to the main checkout, so in a worktree its dogfood hooks are not loaded.

## Cloaking (secret prevention)

The `prismor/runtime/cloaking/` subsystem is Prismor's prevention layer for secret leaks. Real secret values live under `~/.prismor/secrets/` and are referenced in tool calls as `@@SECRET:<name>@@`. When editing this subsystem, treat it as security-sensitive code and never print, log, or narrate real secret values — use the placeholder form in all examples and prose. See [`prismor/runtime/cloaking/README.md`](./prismor/runtime/cloaking/README.md) for the full design and [`AGENTS.md`](./AGENTS.md#cloaking-secret-prevention-layer) for editing guidelines.

## Working in This Repo

- The `advisories/` directory contains the signed threat feed — do not manually edit it. Use the pipeline scripts.
- The `prismor/runtime/` directory is the runtime policy engine. Changes to `policies.py` affect what gets blocked in enforce mode.
- The `pipeline/` directory contains the NVD fetch/merge/sign automation. The schema at `pipeline/schemas/threat-object.schema.json` is the source of truth for feed structure.
- Run `python3 scripts/upgrade_feed.py` after pipeline changes to retroactively improve existing advisories.
- Run `bash scripts/verify_feed.sh` to verify feed signature integrity.
- Public key for signature verification is at `keys/public.pub`.
