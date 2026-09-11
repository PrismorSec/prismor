"""Figures for the hosted-judge paper, from scratchpad/judge/{summary,band,volume}.json."""
import json, os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

J = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data") + "/"
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "figs")
BLUE, RED, GREEN, ORANGE, GREY = "#2060cc", "#cc3030", "#208040", "#cc7020", "#888888"
plt.rcParams.update({"font.family": "serif", "font.size": 8, "axes.spines.top": False,
                     "axes.spines.right": False, "axes.titlesize": 9, "legend.frameon": False})
S = json.load(open(J + "summary.json"))
band = json.load(open(J + "band.json"))

JUDGES = [("openai_gpt-5.6-luna_hardened", "gpt-5.6-luna"), ("openai_gpt-4o-mini_hardened", "gpt-4o-mini"),
          ("openai_gpt-4.1-nano_hardened", "gpt-4.1-nano"), ("cli_codex_hardened", "Codex CLI*"),
          ("cli_claude_seq", "Claude Code CLI*")]


def save(fig, name):
    fig.tight_layout()
    fig.savefig(os.path.join(OUT, name), dpi=300)
    plt.close(fig)


# Fig 1: judge alone, TPR and FPR (block)
fig, ax = plt.subplots(figsize=(5.5, 2.5))
x = range(len(JUDGES))
tpr = [S[k]["judge_alone"]["tpr_block"] * 100 for k, _ in JUDGES]
fpr = [S[k]["judge_alone"]["fpr_block"] * 100 for k, _ in JUDGES]
w = 0.38
b1 = ax.bar([i - w / 2 for i in x], tpr, w, color=BLUE, label="Injections blocked (TPR)")
b2 = ax.bar([i + w / 2 for i in x], fpr, w, color=RED, label="Benign blocked (FPR)")
for bars in (b1, b2):
    for b in bars:
        ax.text(b.get_x() + b.get_width() / 2, b.get_height() + 1.5, f"{b.get_height():.0f}", ha="center", fontsize=6.5)
ax.set_xticks(list(x)); ax.set_xticklabels([n for _, n in JUDGES])
ax.set_ylabel("% of cases"); ax.set_ylim(0, 112)
ax.legend(loc="upper center", ncol=2, fontsize=7, bbox_to_anchor=(0.5, 1.16))
save(fig, "fig1_judge_alone.png")

# Fig 2: gated pipeline vs judge-every-text, TPR
fig, ax = plt.subplots(figsize=(5.5, 2.5))
alone = [S[k]["judge_alone"]["tpr_block"] * 100 for k, _ in JUDGES[:3]]
piped = [S[k]["pipeline"]["tpr_block"] * 100 for k, _ in JUDGES[:3]]
heur = S["heur_main"]["heuristic"]["tpr_block"] * 100
x = range(3)
b1 = ax.bar([i - w / 2 for i in x], piped, w, color=GREY, label="Judge only in band [0.30, 0.75)")
b2 = ax.bar([i + w / 2 for i in x], alone, w, color=GREEN, label="Judge every text (low_threshold 0)")
ax.axhline(heur, color=ORANGE, ls="--", lw=1)
ax.text(2.45, heur + 2, f"heuristics alone {heur:.0f}%", color=ORANGE, ha="right", fontsize=6.5)
for bars in (b1, b2):
    for b in bars:
        ax.text(b.get_x() + b.get_width() / 2, b.get_height() + 1.5, f"{b.get_height():.0f}", ha="center", fontsize=6.5)
ax.set_xticks(list(x)); ax.set_xticklabels([n for _, n in JUDGES[:3]])
ax.set_ylabel("Injections blocked (%)"); ax.set_ylim(0, 112)
ax.legend(loc="upper center", ncol=2, fontsize=7, bbox_to_anchor=(0.5, 1.16))
save(fig, "fig2_gate_bottleneck.png")

# Fig 3: latency
fig, ax = plt.subplots(figsize=(5.5, 2.5))
names = [n for _, n in JUDGES]
p50 = [S[k]["latency_p50"] for k, _ in JUDGES]
p95 = [S[k]["latency_p95"] for k, _ in JUDGES]
x = range(len(JUDGES))
ax.bar([i - w / 2 for i in x], p50, w, color=BLUE, label="p50")
ax.bar([i + w / 2 for i in x], p95, w, color=ORANGE, label="p95")
ax.set_yscale("log"); ax.set_ylabel("Seconds per verdict (log)")
for i, (a, b) in enumerate(zip(p50, p95)):
    ax.text(i - w / 2, a * 1.1, f"{a:.1f}", ha="center", fontsize=6.5)
    ax.text(i + w / 2, b * 1.1, f"{b:.1f}", ha="center", fontsize=6.5)
ax.set_xticks(list(x)); ax.set_xticklabels(names); ax.legend(loc="upper left", fontsize=7)
ax.set_ylim(0.5, 120)
save(fig, "fig3_latency.png")

# Fig 4: block rate by evasion
EV = ["plain", "polite", "authority", "system_note", "classifier_note", "base64", "spanish", "paraphrase"]
fig, ax = plt.subplots(figsize=(5.5, 2.6))
rows = json.load(open(J + "rows_heur_main.json"))
heur_ev = []
for e in EV:
    rs = [r for r in rows if r["label"] and r["evasion"] == e]
    heur_ev.append(100 * sum(r["heur"] >= 0.75 for r in rs) / len(rs))
series = [("Heuristics (main)", heur_ev, ORANGE)]
for (k, n), c in zip(JUDGES[:3], (BLUE, GREEN, GREY)):
    vals = []
    for e in EV:
        a, b = S[k]["block_by_evasion"][e].split("/")
        vals.append(100 * int(a) / int(b))
    series.append((n, vals, c))
w4 = 0.2
for j, (n, vals, c) in enumerate(series):
    ax.bar([i + (j - 1.5) * w4 for i in range(len(EV))], vals, w4, color=c, label=n)
ax.set_xticks(range(len(EV))); ax.set_xticklabels([e.replace("_", "\n") for e in EV], fontsize=7)
ax.set_ylabel("Injections blocked (%)"); ax.set_ylim(0, 118)
ax.legend(ncol=4, loc="upper center", fontsize=6.5, bbox_to_anchor=(0.5, 1.13))
save(fig, "fig4_by_evasion.png")

# Fig 5: where real ingested texts land on the heuristic
fig, ax = plt.subplots(figsize=(5.5, 2.2))
labels = ["< 0.30\n(never judged)", "0.30 - 0.75\n(judged)", ">= 0.75\n(blocked, not judged)"]
vals = [band["<0.30"], band["0.30-0.75"], band[">=0.75"]]
bars = ax.barh(labels[::-1], vals[::-1], color=[RED, BLUE, GREY][::-1])
for b, v in zip(bars, vals[::-1]):
    ax.text(v * 1.15, b.get_y() + b.get_height() / 2, f"{v:,} ({100 * v / band['distinct']:.1f}%)", va="center", fontsize=7)
ax.set_xscale("log"); ax.set_xlim(10, 200000); ax.set_xlabel(f"Distinct real ingested texts (n = {band['distinct']:,}, log)")
save(fig, "fig5_real_band.png")
print(sorted(os.listdir(OUT)))
