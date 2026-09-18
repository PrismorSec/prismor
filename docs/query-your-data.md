# Query Your Data

Every tool call Prismor screens is written to one local SQLite store. The
dashboard reads it; so can you, and so can your agent. This page is the map:
where the store is, what is in it, the questions people actually ask it, and
how to turn what you find into a policy change.

```bash
prismor query --path                       # where the store is
prismor query --schema                     # tables and columns
prismor query "SELECT … "                  # run a read-only statement
prismor docs query-your-data               # this page, in the terminal
```

`prismor query` is the sanctioned door. It opens the file read-only, accepts
only `SELECT` / `WITH` / `EXPLAIN`, caps output at 200 rows (`--limit 0` to
lift), and passes every string cell through the same cloak and data-boundary
redactor that screens tool results. Output is JSON by default; `--format table`
for a terminal, `--format jsonl` for piping. The store is also protected by
policy: the default rules block `sqlite3 … DELETE/UPDATE/DROP`, `.dump`, and
`rm`/`mv`/`tee` against `prismor.db`, so an agent can read the history but
cannot rewrite it.

## Ask your agent

The dashboard's Docs tab has an **Ask your agent** button that copies a prompt
with the real store path filled in. Paste it into Claude Code, Codex, or any
hooked agent and finish the last line:

> Prismor keeps a local SQLite audit store of every governed tool call at
> `~/.prismor/prismor.db`. Read it with `prismor query "<SELECT …>"` — it is
> read-only and output is redacted. `prismor query --schema` lists the tables;
> `prismor docs query-your-data` has the schema and example queries.
> Then answer: **what got blocked this week, and is any of it a false positive?**

The bundled skill (`prismor setup` installs it to `.claude/skills/`) teaches
the same thing, so an agent with the skill loaded does not need the prompt.

## Where the store is

| Layout | Path |
|---|---|
| Current | `$PRISMOR_HOME/prismor.db` (default `~/.prismor/prismor.db`), shared by every workspace |
| Older per-workspace | `~/.prismor/workspaces/<id>/prismor.db`, or `<workspace>/.prismor/prismor.db` |

`prismor query --workspace <path>` opens a workspace-scoped store where one
exists. The dashboard merges old per-workspace stores into the shared one on
first read, so the shared store is normally the whole history.

## Schema

The tables that matter for policy work:

| Table | One row per | Key columns |
|---|---|---|
| `sessions` | agent session | `session_id`, `agent`, `agent_name`, `source` (`hook` live, `transcript` replayed), `workspace_path`, `started_at`, `updated_at`, `risk_score`, `findings_count`, `summary_json` |
| `events` | tool call seen by a hook | `id`, `session_id`, `ts`, `type` (`shell`, `file_read`, `file_write`, `network`, `mcp` …), `agent_event` (`PreToolUse` / `PostToolUse`), `command_text`, `path_text`, `url_text`, `content_text`, `raw_json` (the full hook payload) |
| `findings` | rule match on an event | `finding_id`, `session_id`, `event_index` (→ `events.id`), `severity`, `category`, `title`, `evidence` (the matched text), `enrichment_json` |
| `supply_chain_events` | package install screened | `ts`, `ecosystem`, `package_name`, `package_version`, `install_cmd`, `verdict`, `score`, `signals_json`, `ioc_id` |
| `messages` | transcript turn (when transcripts are ingested) | `session_id`, `seq`, `role`, `model`, `tool_name`, `content_text`, `tokens_in`, `tokens_out` |
| `token_usage` | model call | `session_id`, `ts`, `model`, `input_tokens`, `output_tokens`, `cache_read_tokens`, `cache_creation_tokens` |
| `tool_output_size` | tool result | `session_id`, `ts`, `agent`, `tool_name`, `size_chars`, `approx_tokens` |
| `candidate_rules` | rule proposed by learning | `proposed_at`, `status`, `rule_json`, `confidence`, `support_count`, `sample_evidence` |
| `dismissals` | finding marked not-a-problem | `session_id`, `rule_id`, `evidence`, `dismissed_at`, `reason` |
| `evasion_attempts` | retry that looked like it was routing around a block | `session_id`, `blocked_rule_id`, `blocked_command`, `evading_command`, `similarity_score` |
| `staged_executions` | file written then executed | `session_id`, `category`, `created_path`, `executing_command` |

`findings.enrichment_json` is where the decision lives. Its keys:

| Key | Meaning |
|---|---|
| `ruleId` | the policy rule that matched — the id you override or exempt |
| `action` | what the rule asked for: `block`, `warn`, `step_up`, `log` |
| `mode` | the mode the workspace was in: `enforce` or `observe` |
| `pattern` | the regex that fired |
| `source` | `runtime` (built-in), `project`, `org` |
| `feedMatches` | advisory-feed hits, for supply-chain findings |

A finding was actually stopped only when `action = 'block'` **and**
`mode = 'enforce'`. In observe mode the same finding is recorded and the call
proceeds, which is exactly what makes the store useful for tuning before you
flip to enforce.

## Questions people ask it

**What was blocked in the last 7 days, and by which rule?**

```sql
SELECT date(s.updated_at) AS day, s.agent,
       json_extract(f.enrichment_json, '$.ruleId') AS rule_id,
       f.severity, f.title, count(*) AS n
FROM findings f JOIN sessions s USING (session_id)
WHERE json_extract(f.enrichment_json, '$.action') = 'block'
  AND json_extract(f.enrichment_json, '$.mode') = 'enforce'
  AND s.updated_at >= datetime('now', '-7 days')
GROUP BY 1, 2, 3 ORDER BY n DESC
```

**Which rules fire most, and would they block if I switched to enforce?**

```sql
SELECT json_extract(enrichment_json, '$.ruleId') AS rule_id,
       json_extract(enrichment_json, '$.action') AS action,
       category, count(*) AS n
FROM findings
GROUP BY 1, 2, 3 ORDER BY n DESC LIMIT 20
```

**Show me the evidence behind one rule, so I can judge false positives.**

```sql
SELECT s.agent, s.workspace_path, f.evidence
FROM findings f JOIN sessions s USING (session_id)
WHERE json_extract(f.enrichment_json, '$.ruleId') = 'db-access'
ORDER BY s.updated_at DESC LIMIT 30
```

**Everything one session did, in order.**

```sql
SELECT id, ts, type, agent_event,
       coalesce(command_text, path_text, url_text) AS what
FROM events WHERE session_id = '<session_id>' ORDER BY id
```

**Findings for that session, joined to the call that caused them.**

```sql
SELECT f.severity, f.title, f.evidence, e.command_text
FROM findings f LEFT JOIN events e ON e.id = f.event_index
WHERE f.session_id = '<session_id>' ORDER BY f.event_index
```

**Package installs that scored badly.**

```sql
SELECT ts, ecosystem, package_name, package_version, verdict, score, ioc_id
FROM supply_chain_events WHERE verdict <> 'allowed' ORDER BY ts DESC LIMIT 20
```

**Which agents, which workspaces, how risky.**

```sql
SELECT agent, workspace_path, count(*) AS sessions,
       round(avg(risk_score)) AS avg_risk, sum(findings_count) AS findings
FROM sessions GROUP BY 1, 2 ORDER BY findings DESC
```

**Did an agent try to route around a block?**

```sql
SELECT detected_at, blocked_rule_id, blocked_command, evading_command, similarity_score
FROM evasion_attempts ORDER BY detected_at DESC LIMIT 20
```

**What did the learning loop propose, and what has been dismissed?**

```sql
SELECT proposed_at, status, confidence, support_count,
       json_extract(rule_json, '$.id') AS rule_id
FROM candidate_rules ORDER BY proposed_at DESC;

SELECT rule_id, count(*) AS dismissed FROM dismissals GROUP BY 1 ORDER BY 2 DESC
```

## From a finding to a policy change

Once a query tells you a rule is noisy, or a gap is real, the change goes in
`.prismor/policy.yaml` (project) or `~/.prismor/policy.yaml` (global), keyed by
the `ruleId` you just pulled out of `enrichment_json`. Rules in the
non-overridable floor cannot be disabled locally; see
[Policy layers and exemptions](policy-layers-and-exemptions.md) for the
signed, time-boxed route.

```yaml
rules:
  # A rule whose evidence was all false positives in your workspace
  - id: db-access
    enabled: false

  # Same rule, kept, but downgraded from block to warn while you watch it
  - id: path-traversal
    action: warn

  # A gap the store showed you: add a rule for it
  - id: block-prod-db
    severity: CRITICAL
    category: db_access
    title: Block production database access
    event_types: [shell]
    fields: [command]
    patterns: ["psql.*prod", "mysql.*production"]
    action: block

allowlists:
  # Suppress one matched string without touching the rule
  - rule_id: secret-exfiltration
    patterns: ["curl https://api.internal.example.com/health"]
```

Then replay the change before you trust it:

```bash
prismor policy validate .prismor/policy.yaml
prismor ingest --discover --since 30d      # re-score history under the new policy
prismor query "SELECT json_extract(enrichment_json,'$.ruleId') r, count(*) FROM findings GROUP BY 1 ORDER BY 2 DESC"
```

`prismor learn` does the mining side of this automatically and writes its
proposals to `candidate_rules`; see [Learning](learning.md).

## Reading the file directly

Nothing stops a human from opening the store with `sqlite3` or a GUI. If you
do, open it read-only so a stray statement cannot alter enforcement history:

```bash
sqlite3 "file:$HOME/.prismor/prismor.db?mode=ro" "SELECT count(*) FROM findings"
```

Note that a raw read skips the redaction `prismor query` applies. Event rows
carry the literal command and content text the agent used, so treat the file
as sensitive and prefer `prismor query` when the reader is an agent.

The dashboard's JSON API (`GET /api/sessions`, `/api/findings`, `/api/events`,
`/api/stats`, …) is a third route, loopback-only, and returns the same rows
already paginated; see [Dashboard](dashboard.md#api).

---

## See also

- [Dashboard](dashboard.md) — the views built on this store
- [Learning](learning.md) — mining the store for new rules
- [Policy layers and exemptions](policy-layers-and-exemptions.md) — where a change is allowed to land
- [Transcript Ingest](transcript-ingest.md) — filling the store with pre-install history
