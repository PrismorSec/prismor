# Transcript Ingest — reconstructing what your agents already did

Prismor's detection engine is time-agnostic. `PolicyEngine.evaluate` takes an
event and returns findings; it has no notion of whether that event arrived from
a live hook a millisecond ago or from a file written three weeks ago. Until now
the only thing that fed it was the hook dispatcher, so Prismor's knowledge
started the moment you ran `install-hooks`.

Every supported agent already writes a complete record of what it did to disk.
`prismor analyze-history` reads those records, replays them through the same
pipeline live tool calls take, and tells you what your policy would have done.

```bash
prismor analyze-history                      # last 30 days, all agents
prismor analyze-history --since 90d
prismor analyze-history --agent claude,codex
prismor analyze-history --coverage           # sessions that ran unmonitored
prismor analyze-history --show destructive-command
```

## What it answers

**"What has my agent been doing?"** — A first run populates the dashboard with
real history instead of an empty page. Reconstructed sessions are stored with
`source=transcript` and appear in `prismor sessions` and `prismor dashboard`.

**"What breaks if I turn enforce on?"** — The report separates what your policy
would **block** from what it would **warn** on, per rule, with recency. The
block set is computed by calling `hooks.should_block` — the exact function the
live dispatcher calls — so it cannot drift from real enforcement.

**"Did anything run while Prismor wasn't watching?"** — `--coverage` compares
sessions on disk against sessions Prismor captured live. The difference is
activity that executed ungoverned.

**"How do I test rules against real behaviour?"** — `--export-corpus DIR`
writes redacted, labelled fixtures: events that fired a rule become positives,
events that fired nothing become negatives.

## How it works

```
transcript file
  -> adapter             the only per-agent code: records -> hook payloads
  -> normalize_payload   the live normalizer, unchanged
  -> PolicyEngine        the live engine, unchanged
  -> should_block        the live enforcement decision, unchanged
  -> save_session_snapshot
```

Adapters deliberately do not construct events. They synthesize the same
*hook-shaped payloads* the live dispatcher receives and hand them to
`hooks.normalize_payload`. Replayed events are therefore structurally identical
to live ones, and replayed detection cannot diverge from live detection.

## Agent coverage

A concrete path means an adapter is implemented. **Verified** means it has been
run against real transcripts.

| Agent | Location | Status |
|---|---|---|
| Claude Code | `$CLAUDE_CONFIG_DIR/projects/**/*.jsonl` | Verified — 91 sessions / 101 MB |
| Codex | `$CODEX_HOME/sessions/**/rollout-*.jsonl` | Verified — envelope and non-JSON tool arguments |
| Hermes | `$HERMES_HOME/sessions/**/*.jsonl` | **Unverified** — contract-tested only; no Hermes transcripts were available |
| Everything else | — | Not yet implemented; see below |

Run with `--strict` to exit non-zero when a non-empty transcript produces zero
events. That is the failure mode that matters: a sweep that looks successful
and silently protects nothing.

### Adding an agent

An adapter answers three questions — where the files live, which files are
yours, and how one record becomes zero or more payloads. Most are about forty
lines. Subclass `JsonlAdapter`, implement `roots()` and `record_to_payloads()`,
and register it in `prismor/runtime/transcripts/adapters/__init__.py`.

Two rules that are easy to get wrong:

- **Emit pre-action events only.** `should_block` early-returns via
  `_is_pre_action`, so a payload labelled with a post-action name makes the
  would-block report read zero.
- **Map onto canonical tool names.** The normalizers dispatch on `Bash`,
  `Read`, `Write`, `Edit`, `apply_patch`, `WebFetch`. Translate the agent's
  native names.

## Safety properties

**Replayed sessions never collide with live ones.** The store is
INSERT-OR-REPLACE keyed on `session_id`, and a Claude transcript carries the
*same* id the live hooks used. Every replayed session is namespaced
`replay:<agent>:<id>`, so a sweep cannot overwrite real enforcement history.

**Re-running is free.** Session ids are stable, so a second sweep replaces its
own rows rather than duplicating them.

**Sweeps leave no residue.** Evaluating events makes the engine write
per-session taint files; the driver removes the ones it created.

**The semantic guard is off during a sweep.** It is opt-in generally, but a
user who enabled it would otherwise fire one LLM call per uncertain event
across their entire history. Pass `--semantic` to allow it.

**Secrets are scrubbed.** Persisted events go through `_recloak_event` inside
`save_session_snapshot`. Corpus export bypasses the store, so it scrubs
explicitly: enrolled secrets by value, home paths, secret-shaped tokens by
pattern, and the raw upstream payload is dropped entirely.

## Limits

- **It cannot recover what an agent never persisted.** Reconstruction reads
  what is on disk; it is not disk or memory acquisition.
- **Findings are rule matches, not proof of compromise.** A replayed finding
  says a rule matched a recorded action, nothing more.
- **Coverage gaps are evidence, not intent.** A session with no live record is
  consistent with hooks being removed, a different workspace, or a re-install.
  The report says what is missing and when; it does not assert why.
- **`--coverage` compares against one workspace's store.** Sessions captured
  under a different workspace read as gaps.

## Flags

| Flag | Default | Meaning |
|---|---|---|
| `--agent` | all | Comma-separated adapters to run |
| `--since` | `30d` | Window by file mtime; `all` for everything |
| `--max-events` | 50000 | Ceiling per sweep |
| `--no-persist` | off | Report only; do not write to the store |
| `--coverage` | off | Ungoverned-session audit |
| `--export-corpus DIR` | — | Write redacted rule fixtures |
| `--show RULE` | — | List the individual calls behind a rule |
| `--strict` | off | Exit non-zero on a silent adapter |
| `--semantic` | off | Allow the semantic guard to run |
| `--json` | off | Machine-readable output |

To evaluate one session file without a sweep, use `prismor analyze --input
<file>` (reports findings; does not write to the store).
