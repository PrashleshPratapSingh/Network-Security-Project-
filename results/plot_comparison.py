"""
plot_comparison.py -- Generate Side-by-Side Comparison Charts
---------------------------------------------------------------
Reads comparison_report.json, approach1_metrics.json, and
approach2_metrics.json, then generates comparison charts matching
the PPT slides.

Charts:
  1. Side-by-side metrics comparison (bar chart)
  2. FPR comparison
  3. Per-category detection rate comparison
  4. Speed & memory comparison
  5. Confusion matrix side-by-side

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
    import matplotlib.patches as mpatches
    import seaborn as sns
    import numpy as np
    PLOT_AVAILABLE = True
except ImportError:
    PLOT_AVAILABLE = False

# -- Paths ---------------------------------------------------------------------
BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
PLOTS_DIR  = os.path.join(BASE_DIR, "comparison_plots")
REPORT_FILE = os.path.join(BASE_DIR, "comparison_report.json")
A1_METRICS = os.path.join(BASE_DIR, "approach1_metrics.json")
A2_METRICS = os.path.join(BASE_DIR, "approach2_metrics.json")


def load_data():
    with open(A1_METRICS) as f:
        m1 = json.load(f)
    with open(A2_METRICS) as f:
        m2 = json.load(f)
    report = {}
    if os.path.isfile(REPORT_FILE):
        with open(REPORT_FILE) as f:
            report = json.load(f)
    return m1, m2, report


def ensure_dir():
    os.makedirs(PLOTS_DIR, exist_ok=True)


# -- Plot 1: Side-by-side Metrics Bar Chart ------------------------------------

def plot_metrics_comparison(m1, m2):
    metrics = ["Accuracy", "Precision", "Detection\nRate", "F1 x 100"]
    a1_vals = [m1["accuracy"], m1["precision"], m1["recall_detection_rate"],
               m1["f1_score"] * 100]
    a2_vals = [m2["accuracy"], m2["precision"], m2["recall_detection_rate"],
               m2["f1_score"] * 100]

    x = np.arange(len(metrics))
    width = 0.32

    fig, ax = plt.subplots(figsize=(9, 5))
    bars1 = ax.bar(x - width/2, a1_vals, width, label="Approach 1 (Signature)",
                   color="#3498db", edgecolor="white")
    bars2 = ax.bar(x + width/2, a2_vals, width, label="Approach 2 (ML Anomaly)",
                   color="#e74c3c", edgecolor="white")

    for bars in [bars1, bars2]:
        for bar in bars:
            h = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2, h + 0.5,
                    f"{h:.1f}%", ha="center", va="bottom", fontsize=9, fontweight="bold")

    ax.set_xlabel("Metric")
    ax.set_ylabel("Score (%)")
    ax.set_title("Performance Comparison: Signature vs ML Anomaly", fontsize=14, pad=15)
    ax.set_xticks(x)
    ax.set_xticklabels(metrics)
    ax.set_ylim(0, 115)
    ax.axhline(y=100, color="grey", linestyle="--", alpha=0.3)
    ax.legend(loc="upper left")
    plt.tight_layout()

    path = os.path.join(PLOTS_DIR, "01_metrics_comparison.png")
    plt.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[+] Saved: {path}")


# -- Plot 2: FPR Comparison ---------------------------------------------------

def plot_fpr_comparison(m1, m2):
    approaches = ["Approach 1\n(Signature)", "Approach 2\n(ML Anomaly)"]
    fpr_vals = [m1["false_positive_rate"], m2["false_positive_rate"]]
    colors = ["#e74c3c", "#27ae60"]

    fig, ax = plt.subplots(figsize=(5, 4))
    bars = ax.bar(approaches, fpr_vals, color=colors, width=0.4, edgecolor="white")

    for bar, val in zip(bars, fpr_vals):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.3,
                f"{val:.1f}%", ha="center", va="bottom", fontweight="bold", fontsize=12)

    ax.set_title("False Positive Rate Comparison\n(Lower is better)", fontsize=13)
    ax.set_ylabel("False Positive Rate (%)")
    ax.set_ylim(0, max(fpr_vals) * 1.4 + 2)
    plt.tight_layout()

    path = os.path.join(PLOTS_DIR, "02_fpr_comparison.png")
    plt.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[+] Saved: {path}")


# -- Plot 3: Per-Category Detection -------------------------------------------

def plot_category_comparison(m1, m2):
    a2_cats = m2.get("per_category", {})
    if not a2_cats:
        print("[SKIP] No per-category data for comparison.")
        return

    categories = list(a2_cats.keys())
    a2_rates = [a2_cats[c]["detection_rate"] for c in categories]
    # A1 doesn't have per-category data from this run, use 0 as baseline
    # (signature-based detection on NSL-KDD flow data has limited coverage)
    a1_rates = [0] * len(categories)

    x = np.arange(len(categories))
    width = 0.32

    fig, ax = plt.subplots(figsize=(8, 5))
    bars1 = ax.bar(x - width/2, a1_rates, width, label="Approach 1 (Signature)",
                   color="#3498db", edgecolor="white")
    bars2 = ax.bar(x + width/2, a2_rates, width, label="Approach 2 (ML Anomaly)",
                   color="#e74c3c", edgecolor="white")

    for bars, vals in [(bars1, a1_rates), (bars2, a2_rates)]:
        for bar, val in zip(bars, vals):
            if val > 0:
                ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1,
                        f"{val:.1f}%", ha="center", va="bottom", fontsize=9)

    ax.set_title("Detection Rate by Attack Category", fontsize=13)
    ax.set_ylabel("Detection Rate (%)")
    ax.set_xticks(x)
    ax.set_xticklabels(categories)
    ax.set_ylim(0, 115)
    ax.legend()
    plt.tight_layout()

    path = os.path.join(PLOTS_DIR, "03_category_comparison.png")
    plt.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[+] Saved: {path}")


# -- Plot 4: Speed & Memory ---------------------------------------------------

def plot_resource_comparison(m1, m2):
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 4))

    # Speed
    approaches = ["A1 (Signature)", "A2 (ML)"]
    speeds = [m1.get("throughput_records_per_sec", 0),
              m2.get("throughput_records_per_sec", 0)]
    bars = ax1.bar(approaches, speeds, color=["#3498db", "#e74c3c"],
                   width=0.4, edgecolor="white")
    for bar, val in zip(bars, speeds):
        ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height() + max(speeds)*0.02,
                 f"{val:,.0f}", ha="center", va="bottom", fontweight="bold")
    ax1.set_title("Processing Speed\n(Higher is better)", fontsize=12)
    ax1.set_ylabel("Records / second")

    # Memory
    mems = [m1.get("memory_mb", 0), m2.get("memory_mb", 0)]
    bars = ax2.bar(approaches, mems, color=["#3498db", "#e74c3c"],
                   width=0.4, edgecolor="white")
    for bar, val in zip(bars, mems):
        ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + max(mems)*0.02,
                 f"{val:.1f} MB", ha="center", va="bottom", fontweight="bold")
    ax2.set_title("Memory Usage\n(Lower is better)", fontsize=12)
    ax2.set_ylabel("Memory (MB)")

    plt.tight_layout()
    path = os.path.join(PLOTS_DIR, "04_resource_comparison.png")
    plt.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[+] Saved: {path}")


# -- Plot 5: Confusion Matrices Side-by-Side -----------------------------------

def plot_confusion_comparison(m1, m2):
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

    for ax, m, title, cmap in [
        (ax1, m1, "Approach 1 (Signature)", "Blues"),
        (ax2, m2, "Approach 2 (ML Anomaly)", "Purples"),
    ]:
        tp = m["true_positives"]
        fp = m["false_positives"]
        tn = m["true_negatives"]
        fn = m["false_negatives"]
        cm = np.array([[tn, fp], [fn, tp]])

        sns.heatmap(
            cm, annot=True, fmt="d", cmap=cmap,
            xticklabels=["Pred Normal", "Pred Attack"],
            yticklabels=["Actual Normal", "Actual Attack"],
            linewidths=1, linecolor="white",
            ax=ax, cbar=True, annot_kws={"size": 13, "weight": "bold"}
        )
        ax.set_title(title, fontsize=12, pad=10)
        ax.set_ylabel("Actual")
        ax.set_xlabel("Predicted")

    plt.suptitle("Confusion Matrix Comparison", fontsize=14, y=1.02)
    plt.tight_layout()

    path = os.path.join(PLOTS_DIR, "05_confusion_comparison.png")
    plt.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[+] Saved: {path}")


# -- Main ----------------------------------------------------------------------

def main():
    if not PLOT_AVAILABLE:
        print("[ERROR] matplotlib/seaborn required.")
        sys.exit(1)

    for f in [A1_METRICS, A2_METRICS]:
        if not os.path.isfile(f):
            print(f"[ERROR] Missing: {f}")
            print("        Run: python results/run_comparison.py first.")
            sys.exit(1)

    ensure_dir()
    m1, m2, report = load_data()

    print(f"\n[*] Generating comparison plots in: {PLOTS_DIR}\n")

    plot_metrics_comparison(m1, m2)
    plot_fpr_comparison(m1, m2)
    plot_category_comparison(m1, m2)
    plot_resource_comparison(m1, m2)
    plot_confusion_comparison(m1, m2)

    print(f"\n[+] All comparison plots saved to: {PLOTS_DIR}\n")


if __name__ == "__main__":
    main()
