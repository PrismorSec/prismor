"""Figures 6 and 7: how much of the text the judge sees, and what else it is told."""
import json
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

BASE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(BASE, "data")
OUT = os.path.join(BASE, "figs")
BLUE, RED, GREEN, ORANGE, GREY = "#2060cc", "#cc3030", "#208040", "#cc7020", "#888888"
plt.rcParams.update({"font.family": "serif", "font.size": 8, "axes.spines.top": False,
                     "axes.spines.right": False, "axes.titlesize": 9, "legend.frameon": False})


def rows(name):
    return json.load(open(os.path.join(DATA, name)))


def blocked(rs, label=1):
    sel = [r for r in rs if r["label"] == label]
    return 100 * sum(1 for r in sel if (r.get("risk") or 0) >= 0.75) / len(sel)


def save(fig, name):
    fig.tight_layout()
    fig.savefig(os.path.join(OUT, name), dpi=300)
    plt.close(fig)


# ── Figure 6: truncation strategy on long documents ─────────────────────────
STRATS = [("head", "first 3000 chars\n(before)"), ("headtail", "head + tail"), ("chunks", "every 3000-char\nwindow")]
fig, ax = plt.subplots(figsize=(5.5, 2.5))
w = 0.38
FIG = rows("fig_data.json")
for j, (model, tag, colour) in enumerate([("gpt-5.6-luna", "gpt-56-luna", BLUE), ("gpt-4o-mini", "gpt-4o-mini", GREEN)]):
    vals = [FIG["truncation"][tag][s] for s, _ in STRATS]
    bars = ax.bar([i + (j - 0.5) * w for i in range(len(STRATS))], vals, w, color=colour, label=model)
    for b in bars:
        ax.text(b.get_x() + b.get_width() / 2, b.get_height() + 2, f"{b.get_height():.0f}", ha="center", fontsize=7)
ax.set_xticks(range(len(STRATS)))
ax.set_xticklabels([n for _, n in STRATS])
ax.set_ylabel("Injections blocked (%)")
ax.set_ylim(0, 118)
ax.legend(loc="upper left", fontsize=7)
save(fig, "fig6_truncation.png")

# ── Figure 7: context ablation on real captured events ──────────────────────
# Labels corrected the same way ctx_rescore does: the agent's own echo call and the
# head-truncated read of the injected document are excluded.
CTX = [("none", "text only"), ("heur", "+ heuristic\n(ships today)"), ("src", "+ source"),
       ("task", "+ task"), ("src_task", "+ source\n+ task"), ("full", "+ source + task\n+ workspace")]
fig, ax = plt.subplots(figsize=(5.5, 2.6))
for j, (model, tag, colour) in enumerate([("gpt-5.6-luna", "gpt-56-luna", BLUE), ("gpt-4o-mini", "gpt-4o-mini", GREEN)]):
    xs, vals = [], []
    for i, (c, _) in enumerate(CTX):
        if c not in FIG["context"][tag]:
            continue
        xs.append(i + (j - 0.5) * w)
        vals.append(FIG["context"][tag][c])
    bars = ax.bar(xs, vals, w, color=colour, label=model)
    for b in bars:
        ax.text(b.get_x() + b.get_width() / 2, b.get_height() + 2, f"{b.get_height():.0f}", ha="center", fontsize=7)
ax.set_xticks(range(len(CTX)))
ax.set_xticklabels([n for _, n in CTX], fontsize=7)
ax.set_ylabel("Planted injections\nblocked (%)")
ax.set_ylim(0, 118)
ax.legend(loc="lower left", fontsize=7)
save(fig, "fig7_context.png")
print("wrote fig6_truncation.png, fig7_context.png")
