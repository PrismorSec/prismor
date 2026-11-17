# Learning (Adaptive Rules)

Prismor logs every session. The learning engine mines that history to **propose
new rules, flag false positives, and catch evasion** — turning the patterns you
actually see into policy you can accept with one command. Nothing is applied
automatically: it surfaces candidates and you decide.

Implementation: [`prismor/runtime/learning.py`](../prismor/runtime/learning.py).

---

## How it works

```mermaid
flowchart TD
    DB[("session history<br/>.prismor/prismor.db")]
    DB --> MP["mine_patterns<br/>repeated blocked / near-miss commands<br/>seen ≥ min-support times"]
    DB --> FP["track_false_positives<br/>rules dismissed ≥ fp-threshold times<br/>→ 'this rule may be too noisy'"]
    DB --> RR["propose_rule_refinements<br/>tweaks to existing rules"]
    MP --> R["prismor learn → report of candidates"]
    FP --> R
    RR --> R
    R -->|"--apply &lt;id&gt;"| A["append to<br/>.prismor/policy.yaml"]
    R -->|"--reject &lt;id&gt;"| X["discard"]
```

Three signals feed the report:

| Signal | What it surfaces |
|---|---|
| **Pattern mining** | Commands that recur across sessions and look risky but aren't yet covered — proposed as new candidate rules with a confidence score and support count. |
| **False positives** | Existing rules you keep dismissing (in `observe` mode, a skip is recorded). Past a threshold, the rule is flagged as too noisy. |
| **Refinements** | Suggested adjustments to existing rules. |

There is also **evasion detection**: when a shell command *passes* but is
structurally similar to one a rule previously blocked, the dispatcher flags it as
a possible bypass attempt — catching `r''m -rf` style obfuscation of a known-bad
command.

Staged-execution detection blocks scripts downloaded earlier in the session,
including downloads saved through redirects or `tee`. It warns when a script's
artifact provenance records untrusted content, including content copied from a
tool response or inherited from another session. Ordinary agent-authored helper
scripts do not trigger this warning. The separate warning for transferring an
in-session file with `scp` or `rsync` is unchanged.

---

## Why a human stays in the loop

Auto-applying mined rules would let noise and one-off commands ossify into
policy. The learning engine instead proposes; you review confidence, support
count, and a sample before accepting. Accepted rules are appended to your
project's `.prismor/policy.yaml`, so they're version-controlled and
shareable like any other rule.

---

## Commands

```bash
# Run the full analysis and print a report
prismor learn
prismor learn --min-support 5      # require 5 occurrences before proposing
prismor learn --fp-threshold 10    # flag a rule after 10 dismissals
prismor learn --json               # machine-readable

# Review and act on candidates
prismor learn --candidates         # list pending candidate rules with ids
prismor learn --apply <id>         # accept → appends to project policy.yaml
prismor learn --reject <id>        # discard a candidate
```

| Flag | Default | Effect |
|---|---|---|
| `--min-support` | 3 | Minimum occurrences before a pattern becomes a candidate. |
| `--fp-threshold` | 5 | Dismissal count at which a rule is flagged as a false positive. |
| `--candidates` | — | List pending candidates instead of re-mining. |
| `--apply <id>` | — | Accept a candidate into `.prismor/policy.yaml`. |
| `--reject <id>` | — | Reject a candidate. |
| `--json` | — | Emit raw JSON. |
| `--console` | — | First pull reviewers' true/false-positive labels from the org console (enrolled machines). |

---

## Learning from reviewer labels

On an enrolled machine, local dismissals are only a weak signal: in observe
mode nobody decided anything. A reviewer's label on the org console is a
decision, so `prismor learn --console` pulls those labels first.

1. A block prints its event id and a console link:

   ```text
   Looks like a false positive? Agent: run `prismor report-fp evt_… --reason "<why it is safe>"`,
   then give the user this link to confirm or reject it: https://…/admin/sessions/…?event=evt_…
   Do not work around the block while you wait.
   ```

2. The agent runs `prismor report-fp <event-id> --reason "…"` and gives the
   user the link. The report only **asks**: it puts the event in the console's
   *Reported by agent* queue. Nothing is unblocked, and no learner reads it.
   The agent that was blocked is the last party that should decide the block
   was wrong. A prompt injection could make it say so.
3. An admin opens the link and marks the event **True positive** or **False
   positive** under *Verdict*. The same control is on the review page, which
   also has a *Reported by agent* filter.
4. `prismor learn --console` pulls the labels on this device's events and joins
   them to the local command by event id. The command never leaves a redacted
   device, so only the device can turn a label into a rule.
   - A confirmed **false positive** flags the rule from the first label, with
     the command that was blocked, and recommends a narrow allowlist entry.
   - A confirmed **true positive** pins the rule. It is still listed if it is
     noisy, but the advice is to narrow its pattern, never to lower or allow it.

```bash
prismor report-fp evt_0123 --reason "reads CLAUDE.md, does not write it"
prismor learn --console
```

---

## A typical loop

1. Run agents for a while in `observe` or `enforce` mode — sessions accumulate.
2. `prismor learn` surfaces a recurring `psql … prod` command you keep stopping.
3. `prismor learn --candidates` shows it as candidate `#4` (confidence 80%, support 6).
4. `prismor learn --apply 4` appends the rule to your project policy.
5. `prismor policy show` confirms it's now active; commit the policy file.

After applying, validate and re-check:

```bash
prismor policy validate .prismor/policy.yaml
prismor policy show
```

---

## See also

- [Prismor](prismor-runtime.md) — the policy engine candidates are applied to
- [Dashboard](dashboard.md) — browse the session history learning draws from
- [CLI Reference](cli-reference.md) — all commands at a glance
