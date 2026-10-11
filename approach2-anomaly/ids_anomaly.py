"""
ids_anomaly.py -- Main Entry Point: ML Anomaly-Based Network IDS
------------------------------------------------------------------
Approach 2 for the CNS project. Uses Isolation Forest to detect
network intrusions by learning what "normal" looks like and
flagging outliers.

Supports two modes:
  1. TRAIN mode  -- Train Isolation Forest on normal traffic
  2. TEST mode   -- Evaluate on test set with full metrics

Usage:
  python ids_anomaly.py --train                    # Train the model
  python ids_anomaly.py --test                     # Evaluate on KDDTest+
  python ids_anomaly.py --train --test             # Train then test
  python ids_anomaly.py --test --contamination 0.03  # Custom threshold

Requirements:
  pip install -r requirements.txt
"""

import argparse
import os
import sys
import time

# -- Path setup ----------------------------------------------------------------
sys.path.insert(0, os.path.dirname(__file__))

from feature_extractor import (
    prepare_training_data,
    prepare_test_data,
    load_encoders,
)
from anomaly_detector import AnomalyDetector


def main():
    parser = argparse.ArgumentParser(
        description="ML Anomaly-Based Network IDS (Approach 2) -- Isolation Forest",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Train the Isolation Forest model:
  python ids_anomaly.py --train

  # Evaluate on NSL-KDD test set:
  python ids_anomaly.py --test

  # Train and test in one go:
  python ids_anomaly.py --train --test

  # Use a different contamination (false-alarm budget):
  python ids_anomaly.py --train --test --contamination 0.03

  # Run multiple times for reliability:
  python ids_anomaly.py --test --runs 5
        """,
    )

    parser.add_argument("--train", action="store_true",
                        help="Train the Isolation Forest model on normal traffic")
    parser.add_argument("--test", action="store_true",
                        help="Evaluate on the NSL-KDD test set")
    parser.add_argument("--contamination", type=float, default=0.05,
                        help="Anomaly contamination rate / false-alarm budget (default: 0.05)")
    parser.add_argument("--n-estimators", type=int, default=200,
                        help="Number of isolation trees (default: 200)")
    parser.add_argument("--runs", type=int, default=1,
                        help="Number of repeated evaluation runs (default: 1)")

    args = parser.parse_args()

    if not args.train and not args.test:
        parser.print_help()
        print("\n[!] Specify --train, --test, or both.")
        sys.exit(1)

    print_banner()

    detector = AnomalyDetector(
        contamination=args.contamination,
        n_estimators=args.n_estimators,
    )

    # -- Train -----------------------------------------------------------------
    if args.train:
        X_train, encoders = prepare_training_data()
        train_stats = detector.train(X_train)
        print(f"\n[TRAIN] Training stats: {train_stats}")

    # -- Test ------------------------------------------------------------------
    if args.test:
        if not args.train:
            detector.load()

        encoders = load_encoders()
        X_test, y_test, attack_types, attack_categories, df_test = prepare_test_data(encoders)

        all_metrics = []
        for run_i in range(args.runs):
            if args.runs > 1:
                print(f"\n--- Run {run_i + 1}/{args.runs} ---")

            metrics = detector.evaluate(
                X_test, y_test,
                attack_types=attack_types,
                attack_categories=attack_categories,
            )
            all_metrics.append(metrics)

        # Average metrics if multiple runs
        if args.runs > 1:
            avg = _average_metrics(all_metrics)
            print(f"\n[AVG] Over {args.runs} runs:")
            print(f"  Accuracy:       {avg['accuracy']:.2f}%")
            print(f"  Precision:      {avg['precision']:.2f}%")
            print(f"  Detection Rate: {avg['recall_detection_rate']:.2f}%")
            print(f"  F1 Score:       {avg['f1_score']:.4f}")
            print(f"  FPR:            {avg['false_positive_rate']:.2f}%")
            detector.save_metrics(avg)
        else:
            detector.save_metrics(metrics)

        # Save alert-level log
        y_pred = detector.predict(X_test)
        scores = detector.predict_scores(X_test)
        detector.save_alerts(X_test, y_test, y_pred, scores, attack_types)

    print("\n[*] Done.")


def _average_metrics(all_metrics: list) -> dict:
    """Average numeric metrics across multiple runs."""
    keys = ["accuracy", "precision", "recall_detection_rate", "f1_score",
            "false_positive_rate", "true_positives", "false_positives",
            "true_negatives", "false_negatives"]
    avg = {}
    for k in keys:
        vals = [m[k] for m in all_metrics if k in m]
        avg[k] = round(sum(vals) / len(vals), 4) if vals else 0
    # Copy non-numeric fields from last run
    last = all_metrics[-1]
    for k in last:
        if k not in avg:
            avg[k] = last[k]
    avg["num_runs"] = len(all_metrics)
    return avg


def print_banner():
    print("""
  ============================================================
  |   NETWORK INTRUSION DETECTION SYSTEM -- APPROACH 2       |
  |         ML Anomaly Detection (Isolation Forest)          |
  ============================================================
""")


if __name__ == "__main__":
    main()
