# Coverage Before Accuracy

*Placing an LLM Judge in a Runtime Prompt-Injection Guard for AI Coding Agents*
([PDF](semantic_judge_coverage.pdf))

Where an LLM judge sits matters more than which judge it is. Behind the shipped regex gate the
best judge blocked 34% of injections; scoring every text it blocked all of them. Within a text,
only the first 3000 characters reached the judge, which hid every payload planted deeper in a
document. Telling the judge where the text came from, what the user asked, or what the workspace
is bought nothing.

## Synthetic corpus

- `data/make_corpus.py` — seeded generator for the 120-item labelled corpus (`data/corpus.jsonl`):
  72 injections built from 8 goals x 8 phrasings x 8 carriers, and 48 hard negatives that use the
  same vocabulary for a human reader.
- `data/variants_eval.py` — judges the corpus, and the same injections buried in 8-20k-character
  documents, under a chosen prompt, provenance line and truncation strategy.
- `data/summary.json`, `data/fig_data.json` — the aggregates behind every table and figure.
  Per-item verdicts are not committed: they are tens of thousands of JSON lines and the harness
  regenerates them.
- `data/judge_prompt.txt`, `data/judge_prompt_short.txt` — the judge prompts compared in the paper.

## Live agent scenarios

`data/st3ve_scenario.sh` and `data/st3ve_scenarios2.sh` build four families of real agent sessions
under the guard's hooks — a code repository, web fetches, ticket triage and log debugging — with
harmless payloads planted on five routes. `data/st3ve_export.py` exports the captured events.

- `data/labels.json` — one row per captured text: scenario, event type, file name, size and label.
  **The captured text itself is not published**; the scenario scripts regenerate it.
- `data/ctx_eval.py` — the context ablation (none / heuristic / source / task / both / workspace).
- `data/ctx_cli_eval.py` — the same ablation judged by the Claude Code CLI on a host subscription.
- `data/ctx_rescore.py`, `data/compare_judges.py` — corrected-label scoring and the judge comparison.

## Real-machine counts

`data/band.json` and `data/volume.json` hold aggregate counts from one developer laptop: how many
texts the layer would judge, how long they are, and where they fall on the heuristic score. Counts
only — no session content.

## Rebuild

```bash
python3 data/analyze.py         # metrics -> data/summary.json (needs regenerated rows)
python3 aggregate_figures.py    # rows -> data/fig_data.json
python3 gen_figures.py      # figures 1-5
python3 gen_figures2.py     # figures 6-7
python3 build_paper.py      # semantic_judge_coverage.pdf
```

Re-running the judges needs `JUDGE_API_KEY` (OpenAI) for the API judges, or a logged-in Claude Code
or Codex CLI for the subscription judges. Only synthetic text was ever sent to an external service.
