"""
plot_comparison.py -- Generate Side-by-Side Comparison Charts Matching Presentation
-------------------------------------------------------------------------------------
Reads comparison_report.json, approach1_metrics.json, approach2_metrics.json, and
hybrid_metrics.json, then generates comparison charts matching PPT slides:
  1. Slide 7: Side-by-side metrics comparison & F1 score (bar chart)
  2. Slide 7 & 9: FPR comparison (10x reduction: 25.8% down to 2.5%)
  3. Slide 8: Detection rate by attack category (DoS, Probe, R2L, U2R, Unseen)
  4. Slide 9: Speed (records/sec) & memory footprint
  5. Slide 9 & 11: Confusion matrices / Overview

Usage:
  python results/plot_comparison.py
"""

import json
import os
import sys

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np
    PLOT_AVAILABLE = True
except ImportError:
    PLOT_AVAILABLE = False

BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
PLOTS_DIR   = os.path.join(BASE_DIR, "comparison_plots")
A1_METRICS  = os.path.join(BASE_DIR, "approach1_metrics.json")
A2_METRICS  = os.path.join(BASE_DIR, "approach2_metrics.json")
HYB_METRICS = os.path.join(BASE_DIR, "hybrid_metrics.json")


def load_all_metrics():
    with open(A1_METRICS, "r") as f:
        m1 = json.load(f)
    with open(A2_METRICS, "r") as f:
        m2 = json.load(f)
    with open(HYB_METRICS, "r") as f:
        m3 = json.load(f)
    return m1, m2, m3


def plot_metrics_comparison(m1, m2, m3):
    """Plot 1: Main metrics comparison across A1, A2, and Hybrid (Slide 7 & 11)."""
    metrics = ["Accuracy", "Precision", "Recall / DR", "F1 Score (%)"]
    a1_vals = [m1["accuracy"], m1["precision"], m1["recall_detection_rate"], m1["f1_score"] * 100]
    a2_vals = [m2["accuracy"], m2["precision"], m2["recall_detection_rate"], m2["f1_score"] * 100]
    a3_vals = [m3["accuracy"], m3["precision"], m3["recall_detection_rate"], m3["f1_score"] * 100]

    x = np.arange(len(metrics))
    width = 0.26

    fig, ax = plt.subplots(figsize=(10, 5.5))
    fig.patch.set_facecolor("#0d1117")
    ax.set_facecolor("#161b22")

    b1 = ax.bar(x - width, a1_vals, width, label="Approach 1 (Signature)", color="#8b5cf6", edgecolor="#ffffff", linewidth=0.5)
    b2 = ax.bar(x, a2_vals, width, label="Approach 2 (Isolation Forest)", color="#06b6d4", edgecolor="#ffffff", linewidth=0.5)
    b3 = ax.bar(x + width, a3_vals, width, label="Hybrid Pipeline (Combined)", color="#10b981", edgecolor="#ffffff", linewidth=0.5)

    for bars in [b1, b2, b3]:
        for bar in bars:
            h = bar.get_height()
            ax.text(bar.get_x() + bar.get_width() / 2, h + 1.2, f"{h:.1f}%", ha="center", va="bottom", fontsize=8.5, color="#e6edf3", fontweight="bold")

    ax.set_ylabel("Score (%)", color="#c9d1d9", fontsize=11)
    ax.set_title("Performance Comparison: Signature vs ML Anomaly vs Hybrid (Slide 7 & 11)", fontsize=13, color="#58a6ff", pad=15)
    ax.set_xticks(x)
    ax.set_xticklabels(metrics, color="#e6edf3", fontsize=10)
    ax.tick_params(colors="#8b949e")
    ax.set_ylim(0, 115)
    ax.grid(axis="y", color="#30363d", linestyle="--", alpha=0.6)
    ax.legend(facecolor="#161b22", edgecolor="#30363d", labelcolor="#c9d1d9")
    plt.tight_layout()

    out = os.path.join(PLOTS_DIR, "01_metrics_comparison.png")
    plt.savefig(out, dpi=160, facecolor=fig.get_facecolor())
    plt.close()
    print(f"[+] Saved: {out}")


def plot_fpr_comparison(m1, m2, m3):
    """Plot 2: False Positive Rate Comparison (Slide 7 & 9 - 10x reduction)."""
    approaches = ["Approach 1\n(Signature)", "Approach 2\n(Isolation Forest)", "Hybrid\n(Pipeline)"]
    fpr_vals = [m1["false_positive_rate"], m2["false_positive_rate"], m3["false_positive_rate"]]
    colors = ["#f85149", "#2ea043", "#3fb950"]

    fig, ax = plt.subplots(figsize=(6.5, 4.8))
    fig.patch.set_facecolor("#0d1117")
    ax.set_facecolor("#161b22")

    bars = ax.bar(approaches, fpr_vals, color=colors, width=0.45, edgecolor="#ffffff", linewidth=0.5)

    for bar, val in zip(bars, fpr_vals):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.6, f"{val:.1f}%", ha="center", va="bottom", fontweight="bold", fontsize=11, color="#e6edf3")

    ax.set_title("False Positive Rate (FPR) Comparison\n(Slide 7: 10× Fewer False Alarms)", fontsize=12.5, color="#58a6ff", pad=15)
    ax.set_ylabel("False Positive Rate (%)", color="#c9d1d9", fontsize=10.5)
    ax.tick_params(colors="#8b949e")
    ax.set_ylim(0, 32)
    ax.grid(axis="y", color="#30363d", linestyle="--", alpha=0.6)
    plt.tight_layout()

    out = os.path.join(PLOTS_DIR, "02_fpr_comparison.png")
    plt.savefig(out, dpi=160, facecolor=fig.get_facecolor())
    plt.close()
    print(f"[+] Saved: {out}")


def plot_category_comparison(m1, m2, m3):
    """Plot 3: Per-Category Detection Rate Matching Slide 8 Chart."""
    categories = ["DoS", "Probe", "R2L", "U2R", "Unseen"]
    a1_rates = [m1["per_category"][c]["detection_rate"] for c in categories]
    a2_rates = [m2["per_category"][c]["detection_rate"] for c in categories]
    a3_rates = [m3["per_category"][c]["detection_rate"] for c in categories]

    x = np.arange(len(categories))
    width = 0.26

    fig, ax = plt.subplots(figsize=(10.5, 5.5))
    fig.patch.set_facecolor("#0d1117")
    ax.set_facecolor("#161b22")

    b1 = ax.bar(x - width, a1_rates, width, label="Approach 1 (Behaviour Rules)", color="#8b5cf6", edgecolor="#ffffff", linewidth=0.5)
    b2 = ax.bar(x, a2_rates, width, label="Approach 2 (Isolation Forest)", color="#06b6d4", edgecolor="#ffffff", linewidth=0.5)
    b3 = ax.bar(x + width, a3_rates, width, label="Hybrid Pipeline", color="#10b981", edgecolor="#ffffff", linewidth=0.5)

    for bars in [b1, b2, b3]:
        for bar in bars:
            h = bar.get_height()
            ax.text(bar.get_x() + bar.get_width() / 2, h + 1.2, f"{h:.1f}%", ha="center", va="bottom", fontsize=8.5, color="#e6edf3")

    ax.set_title("Detection Rate by Attack Category (Matching Slide 8)", fontsize=13, color="#58a6ff", pad=15)
    ax.set_ylabel("Detection Rate (%)", color="#c9d1d9", fontsize=11)
    ax.set_xticks(x)
    ax.set_xticklabels(categories, color="#e6edf3", fontsize=10.5)
    ax.tick_params(colors="#8b949e")
    ax.set_ylim(0, 115)
    ax.grid(axis="y", color="#30363d", linestyle="--", alpha=0.6)
    ax.legend(facecolor="#161b22", edgecolor="#30363d", labelcolor="#c9d1d9")
    plt.tight_layout()

    out = os.path.join(PLOTS_DIR, "03_category_comparison.png")
    plt.savefig(out, dpi=160, facecolor=fig.get_facecolor())
    plt.close()
    print(f"[+] Saved: {out}")


def plot_resource_comparison(m1, m2, m3):
    """Plot 4: Speed and Memory Comparison (Slide 9)."""
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4.5))
    fig.patch.set_facecolor("#0d1117")

    # Speed
    approaches = ["A1 (Sig)", "A2 (ML)", "Hybrid"]
    speeds = [m1["throughput_records_per_sec"], m2["throughput_records_per_sec"], m3["throughput_records_per_sec"]]
    colors = ["#8b5cf6", "#06b6d4", "#10b981"]

    ax1.set_facecolor("#161b22")
    bars1 = ax1.bar(approaches, speeds, color=colors, width=0.45, edgecolor="#ffffff", linewidth=0.5)
    for b, s in zip(bars1, speeds):
        ax1.text(b.get_x() + b.get_width() / 2, b.get_height() + 800, f"{int(s):,}", ha="center", va="bottom", fontsize=9, color="#e6edf3", fontweight="bold")
    ax1.set_title("Throughput Speed (pkts/sec) — Slide 9: 11× Faster", color="#58a6ff", fontsize=11)
    ax1.tick_params(colors="#8b949e")
    ax1.set_ylim(0, 50000)
    ax1.grid(axis="y", color="#30363d", linestyle="--", alpha=0.6)

    # Memory
    mems = [m1["memory_mb"], m2["memory_mb"], m3["memory_mb"]]
    ax2.set_facecolor("#161b22")
    bars2 = ax2.bar(approaches, mems, color=colors, width=0.45, edgecolor="#ffffff", linewidth=0.5)
    for b, m in zip(bars2, mems):
        ax2.text(b.get_x() + b.get_width() / 2, b.get_height() + 0.8, f"{m:.1f} MB", ha="center", va="bottom", fontsize=9, color="#e6edf3", fontweight="bold")
    ax2.set_title("RAM Footprint (MB) — Slide 9: < 1 MB vs 35 MB", color="#58a6ff", fontsize=11)
    ax2.tick_params(colors="#8b949e")
    ax2.set_ylim(0, 45)
    ax2.grid(axis="y", color="#30363d", linestyle="--", alpha=0.6)

    plt.tight_layout()
    out = os.path.join(PLOTS_DIR, "04_resource_comparison.png")
    plt.savefig(out, dpi=160, facecolor=fig.get_facecolor())
    plt.close()
    print(f"[+] Saved: {out}")


def main():
    if not PLOT_AVAILABLE:
        print("[ERROR] matplotlib not available.")
        return

    os.makedirs(PLOTS_DIR, exist_ok=True)
    m1, m2, m3 = load_all_metrics()
    plot_metrics_comparison(m1, m2, m3)
    plot_fpr_comparison(m1, m2, m3)
    plot_category_comparison(m1, m2, m3)
    plot_resource_comparison(m1, m2, m3)
    print("\n[SUCCESS] All presentation-aligned plots generated in:", PLOTS_DIR)


if __name__ == "__main__":
    main()
