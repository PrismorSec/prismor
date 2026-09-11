# Coverage Before Accuracy

*Placing an LLM Judge in a Runtime Prompt-Injection Guard for AI Coding Agents* ([PDF](semantic_judge_coverage.pdf))

- `data/make_corpus.py`: seeded generator for the 120-item labelled corpus (`data/corpus.jsonl`).
- `data/rows_*.json`: per-item verdicts for every judge run, with heuristic scores, latency and token usage.
- `data/analyze.py`: metrics (`data/summary.json`) from the rows.
- `data/band.json`, `data/volume.json`: aggregate counts from one developer machine. No session text.
- `gen_figures.py`, `build_paper.py`: figures and PDF (`matplotlib`, `reportlab`).

```bash
python3 data/analyze.py && python3 gen_figures.py && python3 build_paper.py
```
