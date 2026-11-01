"""Turn benchmark results into a summary table and a chart.

Run: python bench/report.py   (after run_bench.py)
Writes bench/results/summary.md and docs/attack-success.png
"""
import json
from collections import defaultdict
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

HERE = Path(__file__).parent
rows = [json.loads(line) for f in sorted((HERE / "results").glob("*.jsonl")) for line in f.open()]


def pct(rs, key):
    return 100 * sum(r[key] for r in rs) / len(rs) if rs else 0.0


groups = defaultdict(list)
for r in rows:
    groups[(r["model"], r["arch"], r["mode"])].append(r)

models = sorted({r["model"] for r in rows})
archs = ["single", "team"]

lines = ["| Model | Agents | Protection | Attack success | Normal tasks done | Tasks done under attack | Gateway time per run |",
         "| --- | --- | --- | --- | --- | --- | --- |"]
for model in models:
    for arch in archs:
        for mode in ("none", "patient-zero"):
            rs = groups[(model, arch, mode)]
            if not rs:
                continue
            attacks = [r for r in rs if r["kind"] == "attack"]
            benign = [r for r in rs if r["kind"] == "benign"]
            ms = sum(r["gateway_ms"] for r in rs) / len(rs)
            a = sum(r["attacked"] for r in attacks)
            b = sum(r["completed"] for r in benign)
            u = sum(r["completed"] for r in attacks)
            lines.append(
                f"| {model} | {arch} | {'Patient Zero' if mode != 'none' else 'None'} | "
                f"{a}/{len(attacks)} ({pct(attacks, 'attacked'):.0f}%) | {b}/{len(benign)} ({pct(benign, 'completed'):.0f}%) | "
                f"{u}/{len(attacks)} ({pct(attacks, 'completed'):.0f}%) | {ms:.0f} ms |")

# Attack success per scenario, all models and designs combined
scen = defaultdict(lambda: {"none": [], "patient-zero": []})
for r in rows:
    if r["kind"] == "attack":
        scen[(r["scenario"], r["category"])][r["mode"]].append(r["attacked"])
lines += ["", "| Attack | Type | Success without protection | Success with Patient Zero |",
          "| --- | --- | --- | --- |"]
for (sid, cat), modes in sorted(scen.items(), key=lambda x: int(x[0][0][1:])):
    n, p = modes["none"], modes["patient-zero"]
    lines.append(f"| {sid} | {cat} | {sum(n)}/{len(n)} | {sum(p)}/{len(p)} |")

(HERE / "results" / "summary.md").write_text("\n".join(lines) + "\n")
print("\n".join(lines))

# ------------------------------------------------------------------ chart
labels, none_vals, pz_vals = [], [], []
for model in models:
    for arch in archs:
        n = [r for r in groups[(model, arch, "none")] if r["kind"] == "attack"]
        p = [r for r in groups[(model, arch, "patient-zero")] if r["kind"] == "attack"]
        if n and p:
            labels.append(f"{model}\n{'single agent' if arch == 'single' else 'agent team'}")
            none_vals.append(pct(n, "attacked"))
            pz_vals.append(pct(p, "attacked"))

fig, ax = plt.subplots(figsize=(10, 4.8), dpi=150)
x = range(len(labels))
w = 0.38
b1 = ax.bar([i - w / 2 for i in x], none_vals, w, label="No protection", color="#b8b8b8")
b2 = ax.bar([i + w / 2 for i in x], pz_vals, w, label="Patient Zero", color="#1f6feb")
for bars in (b1, b2):
    for bar in bars:
        ax.annotate(f"{bar.get_height():.0f}%", (bar.get_x() + bar.get_width() / 2, bar.get_height()),
                    ha="center", va="bottom", fontsize=9, xytext=(0, 2), textcoords="offset points")
ax.set_xticks(list(x))
ax.set_xticklabels(labels, fontsize=8.5)
ax.set_ylabel("Attacks that succeeded (%)")
ax.set_title("Prompt-injection attacks that succeeded, with and without Patient Zero", fontsize=11, loc="left")
ax.spines[["top", "right"]].set_visible(False)
ax.legend(frameon=False)
ax.set_ylim(0, max(none_vals + [10]) * 1.2)
fig.tight_layout()
out = HERE.parent / "docs" / "attack-success.png"
out.parent.mkdir(exist_ok=True)
fig.savefig(out)
print(f"\nChart saved to {out}")
