"""
visualize_results.py — Plot Approach 1 Results for Report
----------------------------------------------------------
Reads results/approach1_metrics.json and results/approach1_alerts.jsonl
and generates publication-quality charts for the CNS project report.

Charts generated:
  1. Confusion Matrix Heatmap
  2. Alert Severity Distribution (Bar Chart)
  3. Top Attack Types Detected (Horizontal Bar)
  4. Metrics Summary Bar Chart (Accuracy, Precision, Recall, F1)
  5. Alerts Over Time (Time Series)

Requirements: pip install matplotlib seaborn pandas
"""

import json
import os
import sys
from collections import Counter

try:
    import matplotlib
    matplotlib.use("Agg")          # Headless rendering (no GUI needed)
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    import seaborn as sns
    import numpy as np
    PLOT_AVAILABLE = True
except ImportError:
    PLOT_AVAILABLE = False
    print("[WARN] matplotlib/seaborn not installed. Install with: pip install matplotlib seaborn")

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR     = os.path.join(os.path.dirname(__file__), "..", "results")
METRICS_FILE = os.path.join(BASE_DIR, "approach1_metrics.json")
ALERTS_FILE  = os.path.join(BASE_DIR, "approach1_alerts.jsonl")
PLOTS_DIR    = os.path.join(BASE_DIR, "approach1_plots")


def load_metrics() -> dict:
    with open(METRICS_FILE) as f:
        return json.load(f)


def load_alerts() -> list[dict]:
    alerts = []
    with open(ALERTS_FILE) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    alerts.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return alerts


def ensure_output_dir():
    os.makedirs(PLOTS_DIR, exist_ok=True)


# ─────────────────────────────────────────────────────────────────────────────
# Plot 1: Confusion Matrix
# ─────────────────────────────────────────────────────────────────────────────

def plot_confusion_matrix(metrics: dict):
    tp = metrics["true_positives"]
    fp = metrics["false_positives"]
    tn = metrics["true_negatives"]
    fn = metrics["false_negatives"]

    if (tp + fp + tn + fn) == 0:
        print("[SKIP] No ground-truth data — skipping confusion matrix.")
        return

    cm = np.array([[tn, fp], [fn, tp]])

    fig, ax = plt.subplots(figsize=(6, 5))
    sns.heatmap(
        cm, annot=True, fmt="d", cmap="Blues",
        xticklabels=["Predicted Normal", "Predicted Attack"],
        yticklabels=["Actual Normal",    "Actual Attack"],
        linewidths=1, linecolor="white",
        ax=ax, cbar=True, annot_kws={"size": 14, "weight": "bold"}
    )
    ax.set_title("Confusion Matrix — Approach 1 (Signature-Based)", fontsize=13, pad=12)
    ax.set_ylabel("Actual Class", fontsize=11)
    ax.set_xlabel("Predicted Class", fontsize=11)
    plt.tight_layout()

    path = os.path.join(PLOTS_DIR, "01_confusion_matrix.png")
    plt.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[+] Saved: {path}")


# ─────────────────────────────────────────────────────────────────────────────
# Plot 2: Alert Severity Distribution
# ─────────────────────────────────────────────────────────────────────────────

def plot_severity_distribution(metrics: dict):
    counts = metrics.get("severity_counts", {})
    if not counts or sum(counts.values()) == 0:
        print("[SKIP] No alerts — skipping severity chart.")
        return

    labels = list(counts.keys())
    values = [counts.get(l, 0) for l in labels]
    colors = {"HIGH": "#e74c3c", "MEDIUM": "#f39c12", "LOW": "#3498db"}
    bar_colors = [colors.get(l, "#95a5a6") for l in labels]

    fig, ax = plt.subplots(figsize=(6, 4))
    bars = ax.bar(labels, values, color=bar_colors, edgecolor="white", width=0.5)

    for bar, val in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.5,
                str(val), ha="center", va="bottom", fontweight="bold")

    ax.set_title("Alert Severity Distribution — Approach 1", fontsize=13)
    ax.set_xlabel("Severity Level")
    ax.set_ylabel("Number of Alerts")
    ax.set_ylim(0, max(values) * 1.2 + 1)
    plt.tight_layout()

    path = os.path.join(PLOTS_DIR, "02_severity_distribution.png")
    plt.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[+] Saved: {path}")


# ─────────────────────────────────────────────────────────────────────────────
# Plot 3: Top Attack Types
# ─────────────────────────────────────────────────────────────────────────────

def plot_top_attacks(alerts: list[dict], top_n: int = 12):
    if not alerts:
        print("[SKIP] No alerts — skipping attack type chart.")
        return

    rule_counts = Counter(a["rule"] for a in alerts)
    top = rule_counts.most_common(top_n)

    labels = [t[0] for t in top]
    values = [t[1] for t in top]

    fig, ax = plt.subplots(figsize=(8, max(4, len(labels) * 0.45)))
    bars = ax.barh(labels[::-1], values[::-1], color="#2ecc71", edgecolor="white")

    for bar, val in zip(bars, values[::-1]):
        ax.text(bar.get_width() + 0.3, bar.get_y() + bar.get_height() / 2,
                str(val), va="center", fontsize=9)

    ax.set_title(f"Top {top_n} Detected Attack Types — Approach 1", fontsize=13)
    ax.set_xlabel("Number of Detections")
    plt.tight_layout()

    path = os.path.join(PLOTS_DIR, "03_top_attack_types.png")
    plt.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[+] Saved: {path}")


# ─────────────────────────────────────────────────────────────────────────────
# Plot 4: Metrics Summary Bar Chart
# ─────────────────────────────────────────────────────────────────────────────

def plot_metrics_summary(metrics: dict):
    if (metrics["true_positives"] + metrics["false_positives"] +
            metrics["true_negatives"] + metrics["false_negatives"]) == 0:
        print("[SKIP] No ground-truth metrics — skipping metrics chart.")
        return

    labels = ["Accuracy", "Precision", "Recall\n(Detection Rate)", "F1 Score × 100"]
    values = [
        metrics["accuracy"],
        metrics["precision"],
        metrics["recall_detection_rate"],
        metrics["f1_score"] * 100,
    ]

    colors = ["#3498db", "#2ecc71", "#e74c3c", "#9b59b6"]

    fig, ax = plt.subplots(figsize=(7, 4))
    bars = ax.bar(labels, values, color=colors, edgecolor="white", width=0.5)

    for bar, val in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.5,
                f"{val:.1f}%", ha="center", va="bottom", fontweight="bold")

    ax.set_title("Performance Metrics — Approach 1 (Signature-Based)", fontsize=13)
    ax.set_ylabel("Score (%)")
    ax.set_ylim(0, 115)
    ax.axhline(y=100, color="grey", linestyle="--", alpha=0.4)
    plt.tight_layout()

    path = os.path.join(PLOTS_DIR, "04_metrics_summary.png")
    plt.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[+] Saved: {path}")


# ─────────────────────────────────────────────────────────────────────────────
# Plot 5: FPR vs Detection Rate Comparison (for report)
# ─────────────────────────────────────────────────────────────────────────────

def plot_fpr_vs_detection(metrics: dict):
    """Side-by-side bar comparing FPR and Detection Rate."""
    dr  = metrics.get("recall_detection_rate", 0)
    fpr = metrics.get("false_positive_rate", 0)

    fig, ax = plt.subplots(figsize=(5, 4))
    bars = ax.bar(
        ["Detection Rate\n(Higher is better)", "False Positive Rate\n(Lower is better)"],
        [dr, fpr],
        color=["#27ae60", "#e74c3c"], width=0.4, edgecolor="white"
    )

    for bar, val in zip(bars, [dr, fpr]):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.5,
                f"{val:.1f}%", ha="center", va="bottom", fontweight="bold")

    ax.set_title("Detection Rate vs False Positive Rate\n(Approach 1 — Signature-Based)", fontsize=12)
    ax.set_ylabel("Percentage (%)")
    ax.set_ylim(0, 115)
    plt.tight_layout()

    path = os.path.join(PLOTS_DIR, "05_dr_vs_fpr.png")
    plt.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[+] Saved: {path}")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    if not PLOT_AVAILABLE:
        print("[ERROR] Cannot generate plots — matplotlib and seaborn are required.")
        print("        Install: sudo pacman -S python-matplotlib python-seaborn")
        sys.exit(1)

    if not os.path.isfile(METRICS_FILE):
        print(f"[ERROR] Metrics file not found: {METRICS_FILE}")
        print("        Run ids_signature.py or traffic_simulator.py first.")
        sys.exit(1)

    ensure_output_dir()

    print(f"\n[*] Loading metrics from: {METRICS_FILE}")
    metrics = load_metrics()

    alerts = []
    if os.path.isfile(ALERTS_FILE):
        print(f"[*] Loading alerts from:  {ALERTS_FILE}")
        alerts = load_alerts()

    print(f"[*] Generating plots in: {PLOTS_DIR}\n")

    plot_confusion_matrix(metrics)
    plot_severity_distribution(metrics)
    plot_top_attacks(alerts)
    plot_metrics_summary(metrics)
    plot_fpr_vs_detection(metrics)

    print(f"\n[✓] All plots saved to: {PLOTS_DIR}")
    print("    Use these in your CNS project report!\n")


if __name__ == "__main__":
    main()
