"""
visualize_results_a2.py -- Plot Approach 2 Results for Report
---------------------------------------------------------------
Reads results/approach2_metrics.json and generates publication-quality
charts for the CNS project report.

Charts generated:
  1. Confusion Matrix Heatmap
  2. Per-Category Detection Rates (DoS, Probe, R2L, U2R)
  3. Metrics Summary Bar Chart
  4. Detection Rate vs FPR
  5. Anomaly Score Distribution

Requirements: pip install matplotlib seaborn numpy
"""

import json
import os
import sys

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import seaborn as sns
    import numpy as np
    PLOT_AVAILABLE = True
except ImportError:
    PLOT_AVAILABLE = False
    print("[WARN] matplotlib/seaborn not installed.")

# -- Paths ---------------------------------------------------------------------
BASE_DIR     = os.path.join(os.path.dirname(__file__), "..", "results")
METRICS_FILE = os.path.join(BASE_DIR, "approach2_metrics.json")
ALERTS_FILE  = os.path.join(BASE_DIR, "approach2_alerts.jsonl")
PLOTS_DIR    = os.path.join(BASE_DIR, "approach2_plots")


def load_metrics() -> dict:
    with open(METRICS_FILE) as f:
        return json.load(f)


def ensure_output_dir():
    os.makedirs(PLOTS_DIR, exist_ok=True)


# -- Plot 1: Confusion Matrix -------------------------------------------------

def plot_confusion_matrix(metrics: dict):
    tp = metrics["true_positives"]
    fp = metrics["false_positives"]
    tn = metrics["true_negatives"]
    fn = metrics["false_negatives"]

    if (tp + fp + tn + fn) == 0:
        print("[SKIP] No data for confusion matrix.")
        return

    cm = np.array([[tn, fp], [fn, tp]])

    fig, ax = plt.subplots(figsize=(6, 5))
    sns.heatmap(
        cm, annot=True, fmt="d", cmap="Purples",
        xticklabels=["Predicted Normal", "Predicted Attack"],
        yticklabels=["Actual Normal", "Actual Attack"],
        linewidths=1, linecolor="white",
        ax=ax, cbar=True, annot_kws={"size": 14, "weight": "bold"}
    )
    ax.set_title("Confusion Matrix -- Approach 2 (ML Anomaly)", fontsize=13, pad=12)
    ax.set_ylabel("Actual Class", fontsize=11)
    ax.set_xlabel("Predicted Class", fontsize=11)
    plt.tight_layout()

    path = os.path.join(PLOTS_DIR, "01_confusion_matrix.png")
    plt.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[+] Saved: {path}")


# -- Plot 2: Per-Category Detection Rates --------------------------------------

def plot_per_category(metrics: dict):
    cat_data = metrics.get("per_category", {})
    if not cat_data:
        print("[SKIP] No per-category data.")
        return

    categories = list(cat_data.keys())
    detection_rates = [cat_data[c]["detection_rate"] for c in categories]
    totals = [cat_data[c]["total"] for c in categories]

    fig, ax = plt.subplots(figsize=(8, 5))
    colors = ["#e74c3c", "#3498db", "#f39c12", "#9b59b6"]
    bars = ax.bar(categories, detection_rates,
                  color=colors[:len(categories)], edgecolor="white", width=0.5)

    for bar, val, total in zip(bars, detection_rates, totals):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1,
                f"{val:.1f}%\n({total})", ha="center", va="bottom",
                fontweight="bold", fontsize=9)

    ax.set_title("Detection Rate by Attack Category -- Approach 2", fontsize=13)
    ax.set_ylabel("Detection Rate (%)")
    ax.set_ylim(0, 115)
    ax.axhline(y=100, color="grey", linestyle="--", alpha=0.3)
    plt.tight_layout()

    path = os.path.join(PLOTS_DIR, "02_per_category_detection.png")
    plt.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[+] Saved: {path}")


# -- Plot 3: Metrics Summary ---------------------------------------------------

def plot_metrics_summary(metrics: dict):
    labels = ["Accuracy", "Precision", "Recall\n(Detection Rate)", "F1 Score x 100"]
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

    ax.set_title("Performance Metrics -- Approach 2 (ML Anomaly)", fontsize=13)
    ax.set_ylabel("Score (%)")
    ax.set_ylim(0, 115)
    ax.axhline(y=100, color="grey", linestyle="--", alpha=0.4)
    plt.tight_layout()

    path = os.path.join(PLOTS_DIR, "03_metrics_summary.png")
    plt.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[+] Saved: {path}")


# -- Plot 4: Detection Rate vs FPR ---------------------------------------------

def plot_dr_vs_fpr(metrics: dict):
    dr = metrics.get("recall_detection_rate", 0)
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

    ax.set_title("Detection Rate vs False Positive Rate\n(Approach 2 -- ML Anomaly)", fontsize=12)
    ax.set_ylabel("Percentage (%)")
    ax.set_ylim(0, 115)
    plt.tight_layout()

    path = os.path.join(PLOTS_DIR, "04_dr_vs_fpr.png")
    plt.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[+] Saved: {path}")


# -- Plot 5: Anomaly Score Distribution ----------------------------------------

def plot_score_distribution():
    """Plot anomaly score distribution for true attacks vs normal."""
    if not os.path.isfile(ALERTS_FILE):
        print("[SKIP] No alerts file for score distribution.")
        return

    scores_attack = []
    scores_normal = []

    with open(ALERTS_FILE) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                score = rec.get("anomaly_score")
                gt = rec.get("ground_truth")
                if score is not None and gt is not None:
                    if gt == 1:
                        scores_attack.append(score)
                    else:
                        scores_normal.append(score)
            except json.JSONDecodeError:
                pass

    if not scores_attack and not scores_normal:
        print("[SKIP] No score data for distribution plot.")
        return

    fig, ax = plt.subplots(figsize=(8, 4))

    if scores_attack:
        ax.hist(scores_attack, bins=50, alpha=0.6, color="#e74c3c",
                label=f"True Attacks ({len(scores_attack)})", density=True)
    if scores_normal:
        ax.hist(scores_normal, bins=50, alpha=0.6, color="#3498db",
                label=f"False Alarms ({len(scores_normal)})", density=True)

    ax.set_title("Anomaly Score Distribution -- Approach 2", fontsize=13)
    ax.set_xlabel("Anomaly Score (lower = more anomalous)")
    ax.set_ylabel("Density")
    ax.legend()
    plt.tight_layout()

    path = os.path.join(PLOTS_DIR, "05_score_distribution.png")
    plt.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[+] Saved: {path}")


# -- Main ----------------------------------------------------------------------

def main():
    if not PLOT_AVAILABLE:
        print("[ERROR] Cannot generate plots -- matplotlib and seaborn required.")
        sys.exit(1)

    if not os.path.isfile(METRICS_FILE):
        print(f"[ERROR] Metrics file not found: {METRICS_FILE}")
        print("        Run ids_anomaly.py --train --test first.")
        sys.exit(1)

    ensure_output_dir()

    print(f"\n[*] Loading metrics from: {METRICS_FILE}")
    metrics = load_metrics()

    print(f"[*] Generating plots in: {PLOTS_DIR}\n")

    plot_confusion_matrix(metrics)
    plot_per_category(metrics)
    plot_metrics_summary(metrics)
    plot_dr_vs_fpr(metrics)
    plot_score_distribution()

    print(f"\n[+] All plots saved to: {PLOTS_DIR}")
    print("    Use these in your CNS project report!\n")


if __name__ == "__main__":
    main()
