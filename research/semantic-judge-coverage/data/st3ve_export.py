"""Export the captured events with every context field the judge could be given.

Run on st3ve; writes ~/judgectx/events.json. Labels come from the planted marker, so
no manual judgement is involved: a text carrying CTXPROBE is a positive. Scenario
names come from the id ranges in boundaries.json (the repo scenario is whatever
falls outside them).
"""
import json
import os
import sqlite3

MARK = "CTXPROBE"
ROOT = os.path.expanduser("~/judgectx")
DB = f"{ROOT}/home/prismor.db"
OUT = f"{ROOT}/events.json"
BOUND = f"{ROOT}/boundaries.json"

bounds = json.load(open(BOUND)) if os.path.exists(BOUND) else []


def scenario_of(eid):
    for b in bounds:
        if b["min_id"] <= eid <= b["max_id"]:
            return b["scenario"]
    return "code_repo"


c = sqlite3.connect(f"file:{DB}?mode=ro", uri=True, timeout=60)
cols = [r[1] for r in c.execute("pragma table_info(events)")]
task = {}
for sid, raw in c.execute("select session_id, raw_json from events where type='prompt' order by id"):
    try:
        d = json.loads(raw or "{}")
    except ValueError:
        continue
    if d.get("prompt") and sid not in task:
        task[sid] = str(d["prompt"])[:400]

rows = []
for r in c.execute(f"select {','.join(cols)} from events order by id"):
    e = dict(zip(cols, r))
    try:
        d = json.loads(e.get("raw_json") or "{}")
    except ValueError:
        d = {}
    text = "\n".join(str(d[k]) for k in ("prompt", "response", "content", "stdout", "stderr") if d.get(k)).strip()
    if len(text) < 12:
        continue
    rows.append({
        "id": e["id"],
        "scenario": scenario_of(e["id"]),
        "session": e["session_id"],
        "type": e["type"],
        "agent_event": e.get("agent_event") or d.get("agent_event") or "",
        "tool": d.get("tool") or d.get("tool_name") or "",
        "path": e.get("path_text") or d.get("path") or "",
        "url": e.get("url_text") or d.get("url") or "",
        "command": (e.get("command_text") or d.get("command") or "")[:300],
        "task": task.get(e["session_id"], ""),
        "label": int(MARK in text),
        "chars": len(text),
        "text": text,
    })

json.dump(rows, open(OUT, "w"), indent=1)
print(f"{len(rows)} texts ({sum(r['label'] for r in rows)} planted) -> {OUT}")
by = {}
for r in rows:
    k = (r["scenario"], r["type"])
    by.setdefault(k, [0, 0])
    by[k][0] += 1
    by[k][1] += r["label"]
for (s, t), (n, p) in sorted(by.items()):
    print(f"  {s:15} {t:14} n={n:4d} planted={p}")
