"""Boil the per-item verdicts down to the numbers the figures need.

The per-item rows are derived data: large, and regenerable by re-running the harness.
This writes data/fig_data.json so the figures (and anyone rebuilding the paper) need
only a few hundred bytes of aggregates instead of tens of thousands of JSON lines.
"""
import glob
import json
import os

S = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(S, "data")
ROWS = os.environ.get("ROWS_DIR", DATA)          # where the raw rows_*.json still live


def rows(name):
    return json.load(open(os.path.join(ROWS, name)))


def blocked(rs, label=1, thresh=0.75):
    sel = [r for r in rs if r["label"] == label]
    return round(100 * sum(1 for r in sel if (r.get("risk") or 0) >= thresh) / len(sel), 1) if sel else 0.0


out = {}

# Figure 4: heuristic detection per phrasing, from the main-branch heuristic scores.
EV = ["plain", "polite", "authority", "system_note", "classifier_note", "base64", "spanish", "paraphrase"]
heur = rows("rows_heur_main.json")
out["heuristic_by_evasion"] = {}
for e in EV:
    rs = [r for r in heur if r["label"] and r["evasion"] == e]
    out["heuristic_by_evasion"][e] = round(100 * sum(1 for r in rs if r["heur"] >= 0.75) / len(rs), 1) if rs else 0.0

# Figure 6: truncation strategy on long documents.
out["truncation"] = {}
for tag in ("gpt-56-luna", "gpt-4o-mini"):
    out["truncation"][tag] = {s: blocked(rows(f"rows_v_{tag}_full_long_{s}.json"))
                              for s in ("head", "headtail", "chunks")}

# Figure 7: context ablation on the captured events, with the corrected labels.
label = {r["id"]: r["label"] for r in (json.loads(l) for l in open(os.path.join(DATA, "labels.jsonl")))}
out["context"] = {}
for tag in ("gpt-56-luna", "gpt-4o-mini"):
    per = {}
    for ctx in ("none", "heur", "src", "task", "src_task", "full"):
        path = os.path.join(ROWS, f"rows_ctx_{tag}_{ctx}.json")
        if not os.path.exists(path):
            continue
        rs = [dict(r, label=label[r["id"]]) for r in rows(f"rows_ctx_{tag}_{ctx}.json")
              if label.get(r["id"]) is not None]
        per[ctx] = blocked(rs)
    out["context"][tag] = per

json.dump(out, open(os.path.join(DATA, "fig_data.json"), "w"), indent=1)
print("wrote data/fig_data.json:", {k: len(v) for k, v in out.items()})
