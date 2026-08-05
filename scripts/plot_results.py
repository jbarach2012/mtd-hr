"""Reproduce the paper's figures from a run's summary.json.

Generates:
  * ablation bar/line chart (Table 7 / Fig. 8): MTTC and encryption rate as
    components are disabled,
  * encryption-rate comparison vs prior methods (Fig. 3).

Usage:
    python scripts/plot_results.py --summary outputs/default/summary.json \
        --outdir figures
"""

from __future__ import annotations

import argparse
import json
import os

# Prior-method encryption success rates reported in the paper (Fig. 3).
PRIOR_ENCRYPTION = {
    "Punitha & Preetha": 22.7,
    "Singh et al.": 35.0,
    "Hyder et al.": 28.5,
    "Lee & Park": 25.6,
}


def plot_ablation(summary, outdir):
    import matplotlib.pyplot as plt

    full = summary["full_system"]
    abl = summary["ablations"]
    labels = ["Full System", "No IP Hop", "No Container Mut", "No Node Reassign"]
    keys = [None, "without_ip_hop", "without_container_mutation",
            "without_node_reassignment"]
    mttc = [full["mttc"]] + [abl[k]["mttc"] for k in keys[1:]]
    enc = [full["encryption_rate"] * 100] + [abl[k]["encryption_rate"] * 100
                                             for k in keys[1:]]

    fig, ax1 = plt.subplots(figsize=(8, 4.5))
    x = range(len(labels))
    ax1.bar(x, mttc, color="#9ecae1", label="MTTC (s)")
    ax1.set_ylabel("MTTC (s)")
    ax1.set_xticks(list(x))
    ax1.set_xticklabels(labels, rotation=20, ha="right")
    ax2 = ax1.twinx()
    ax2.plot(x, enc, color="#238b45", marker="o", label="Encryption rate (%)")
    ax2.set_ylabel("Encryption rate (%)")
    ax1.set_title("Impact of MTD component removal (ablation)")
    fig.tight_layout()
    p = os.path.join(outdir, "ablation.png")
    fig.savefig(p, dpi=200)
    plt.close(fig)
    print("Wrote", p)


def plot_encryption_comparison(summary, outdir):
    import matplotlib.pyplot as plt

    ours = summary["full_system"]["encryption_rate"] * 100
    names = list(PRIOR_ENCRYPTION.keys()) + ["Ours (MTD-HR)"]
    vals = list(PRIOR_ENCRYPTION.values()) + [ours]
    colors = ["#66c2a5"] * len(PRIOR_ENCRYPTION) + ["#d53e4f"]

    fig, ax = plt.subplots(figsize=(8, 4.5))
    bars = ax.bar(range(len(vals)), vals, color=colors)
    ax.set_xticks(range(len(names)))
    ax.set_xticklabels(names, rotation=20, ha="right")
    ax.set_ylabel("Encryption success rate (%)")
    ax.set_title("Ransomware encryption rate across methods")
    for b, v in zip(bars, vals):
        ax.text(b.get_x() + b.get_width() / 2, v + 0.4, f"{v:.1f}",
                ha="center", fontsize=8)
    fig.tight_layout()
    p = os.path.join(outdir, "encryption_comparison.png")
    fig.savefig(p, dpi=200)
    plt.close(fig)
    print("Wrote", p)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--summary", required=True)
    parser.add_argument("--outdir", default="figures")
    args = parser.parse_args()

    os.makedirs(args.outdir, exist_ok=True)
    with open(args.summary) as fh:
        summary = json.load(fh)
    plot_ablation(summary, args.outdir)
    plot_encryption_comparison(summary, args.outdir)


if __name__ == "__main__":
    main()
