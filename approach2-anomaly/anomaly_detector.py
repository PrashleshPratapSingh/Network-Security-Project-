"""
anomaly_detector.py -- Isolation Forest Anomaly Detection Engine
-----------------------------------------------------------------
Core ML engine for Approach 2. Trains an Isolation Forest on normal
traffic only, then classifies test traffic as normal or anomalous.

Key design decisions (matching PPT):
  - Trained on NORMAL traffic only (semi-supervised)
  - contamination = 0.05 (5% false-alarm budget)
  - Alert threshold tunable via contamination parameter
"""

import os
import sys
import time
import json
import numpy as np
import joblib
import psutil

from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report,
)

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(BASE_DIR)
MODEL_DIR   = os.path.join(BASE_DIR, "models")
RESULTS_DIR = os.path.join(PROJECT_DIR, "results")

MODEL_PATH  = os.path.join(MODEL_DIR, "isolation_forest.joblib")


class AnomalyDetector:
    """Isolation Forest-based anomaly detector for network traffic."""

    def __init__(self, contamination: float = 0.05, n_estimators: int = 200,
                 random_state: int = 42):
        """
        Args:
            contamination: Expected proportion of anomalies (false-alarm budget)
            n_estimators:  Number of isolation trees
            random_state:  Random seed for reproducibility
        """
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.random_state = random_state
        self.model = None
        self._train_time = 0.0
        self._train_samples = 0

    def train(self, X_normal: np.ndarray) -> dict:
        """
        Train Isolation Forest on normal traffic only.

        Args:
            X_normal: Feature matrix of NORMAL traffic only

        Returns:
            dict with training stats
        """
        print(f"[TRAIN] Training Isolation Forest on {X_normal.shape[0]:,} normal samples...")
        print(f"        Features: {X_normal.shape[1]} | Trees: {self.n_estimators} | "
              f"Contamination: {self.contamination}")

        self.model = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            random_state=self.random_state,
            n_jobs=-1,          # Use all CPU cores
            max_samples="auto",
        )

        start = time.time()
        self.model.fit(X_normal)
        self._train_time = time.time() - start
        self._train_samples = X_normal.shape[0]

        print(f"[TRAIN] Done in {self._train_time:.2f}s")

        # Save model
        os.makedirs(MODEL_DIR, exist_ok=True)
        joblib.dump(self.model, MODEL_PATH)
        model_size = os.path.getsize(MODEL_PATH) / (1024 * 1024)
        print(f"[TRAIN] Model saved: {MODEL_PATH} ({model_size:.1f} MB)")

        return {
            "train_samples": self._train_samples,
            "train_time_seconds": round(self._train_time, 2),
            "model_size_mb": round(model_size, 1),
            "n_estimators": self.n_estimators,
            "contamination": self.contamination,
        }

    def load(self):
        """Load a previously trained model."""
        if not os.path.isfile(MODEL_PATH):
            print(f"[ERROR] No trained model found at: {MODEL_PATH}")
            print("        Run training first: python ids_anomaly.py --train")
            sys.exit(1)
        self.model = joblib.load(MODEL_PATH)
        print(f"[INFO] Loaded model from {MODEL_PATH}")

    def predict(self, X: np.ndarray) -> np.ndarray:
        """
        Predict anomalies.

        Args:
            X: Feature matrix (n_samples, n_features)

        Returns:
            Binary predictions: 0 = normal, 1 = attack/anomaly
        """
        if self.model is None:
            self.load()

        # Isolation Forest returns: 1 = normal (inlier), -1 = anomaly (outlier)
        raw_preds = self.model.predict(X)
        # Convert: -1 -> 1 (attack), 1 -> 0 (normal)
        return (raw_preds == -1).astype(int)

    def predict_scores(self, X: np.ndarray) -> np.ndarray:
        """
        Get anomaly scores (lower = more anomalous).

        Returns:
            Anomaly scores for each sample
        """
        if self.model is None:
            self.load()
        return self.model.decision_function(X)

    def evaluate(self, X_test: np.ndarray, y_test: np.ndarray,
                 attack_types: np.ndarray = None,
                 attack_categories: np.ndarray = None) -> dict:
        """
        Full evaluation: predict on test set, compute all metrics.

        Returns:
            dict with accuracy, precision, recall, F1, FPR, confusion matrix,
            per-category breakdown, timing, and resource usage
        """
        print(f"\n[TEST] Evaluating on {X_test.shape[0]:,} test records...")

        # Predict
        start = time.time()
        y_pred = self.predict(X_test)
        predict_time = time.time() - start

        # Core metrics
        tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
        accuracy  = accuracy_score(y_test, y_pred) * 100
        precision = precision_score(y_test, y_pred, zero_division=0) * 100
        recall    = recall_score(y_test, y_pred, zero_division=0) * 100
        f1        = f1_score(y_test, y_pred, zero_division=0)
        fpr       = fp / (fp + tn) * 100 if (fp + tn) > 0 else 0.0

        metrics = {
            "total_packets": int(len(y_test)),
            "total_alerts": int(tp + fp),
            "true_positives": int(tp),
            "false_positives": int(fp),
            "true_negatives": int(tn),
            "false_negatives": int(fn),
            "accuracy": round(accuracy, 2),
            "precision": round(precision, 2),
            "recall_detection_rate": round(recall, 2),
            "f1_score": round(f1, 4),
            "false_positive_rate": round(fpr, 2),
            "predict_time_seconds": round(predict_time, 2),
            "throughput_records_per_sec": round(len(y_test) / predict_time, 0) if predict_time > 0 else 0,
            "severity_counts": {"HIGH": int(tp), "MEDIUM": int(fp), "LOW": 0},
        }

        # Resource usage
        proc = psutil.Process(os.getpid())
        metrics["memory_mb"] = round(proc.memory_info().rss / (1024 * 1024), 1)

        # Per-category detection rates
        if attack_categories is not None:
            cat_metrics = {}
            for cat in np.unique(attack_categories):
                if cat == "Normal":
                    continue
                mask = attack_categories == cat
                if mask.sum() == 0:
                    continue
                cat_recall = recall_score(y_test[mask], y_pred[mask], zero_division=0)
                cat_metrics[cat] = {
                    "total": int(mask.sum()),
                    "detected": int(y_pred[mask].sum()),
                    "detection_rate": round(cat_recall * 100, 1),
                }
            metrics["per_category"] = cat_metrics

        # Unseen attack analysis (attacks in test but not in train)
        if attack_types is not None:
            # Track which attack types the model detects
            attack_mask = y_test == 1
            detected_mask = y_pred == 1
            unique_attacks = np.unique(attack_types[attack_mask])

            attack_type_metrics = {}
            for at in unique_attacks:
                at_mask = attack_types == at
                if at_mask.sum() == 0:
                    continue
                at_detected = y_pred[at_mask].sum()
                at_total = y_test[at_mask].sum()
                attack_type_metrics[at] = {
                    "total": int(at_mask.sum()),
                    "detected": int(at_detected),
                    "detection_rate": round(at_detected / at_mask.sum() * 100, 1) if at_mask.sum() > 0 else 0,
                }
            metrics["per_attack_type"] = attack_type_metrics

        # Print summary
        print(f"\n{'='*60}")
        print(f"  NIDS -- APPROACH 2 (ML ANOMALY) -- RESULTS SUMMARY")
        print(f"{'='*60}")
        print(f"  Total Records    : {metrics['total_packets']:,}")
        print(f"  Total Alerts     : {metrics['total_alerts']:,}")
        print(f"  True Positives   : {tp:,}")
        print(f"  False Positives  : {fp:,}")
        print(f"  True Negatives   : {tn:,}")
        print(f"  False Negatives  : {fn:,}")
        print(f"  Accuracy         : {accuracy:.2f}%")
        print(f"  Precision        : {precision:.2f}%")
        print(f"  Detection Rate   : {recall:.2f}%")
        print(f"  F1 Score         : {f1:.4f}")
        print(f"  False Positive Rate : {fpr:.2f}%")
        print(f"  Predict Time     : {predict_time:.2f}s")
        print(f"  Memory Usage     : {metrics['memory_mb']} MB")
        print(f"{'='*60}\n")

        return metrics

    def save_metrics(self, metrics: dict):
        """Save metrics JSON to results directory."""
        os.makedirs(RESULTS_DIR, exist_ok=True)
        metrics["generated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        path = os.path.join(RESULTS_DIR, "approach2_metrics.json")
        with open(path, "w") as f:
            json.dump(metrics, f, indent=2)
        print(f"[INFO] Metrics saved to: {path}")

    def save_alerts(self, X_test: np.ndarray, y_test: np.ndarray,
                    y_pred: np.ndarray, scores: np.ndarray,
                    attack_types: np.ndarray = None):
        """Save alert-level JSONL log (matching Approach 1 format)."""
        os.makedirs(RESULTS_DIR, exist_ok=True)
        path = os.path.join(RESULTS_DIR, "approach2_alerts.jsonl")

        count = 0
        with open(path, "w") as f:
            for i in range(len(y_pred)):
                if y_pred[i] == 1:  # Alert triggered
                    record = {
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                        "rule": "Anomaly Detection",
                        "severity": "HIGH" if y_test[i] == 1 else "MEDIUM",
                        "src_ip": "test_record",
                        "dst_ip": "test_record",
                        "protocol": "N/A",
                        "match_type": "anomaly",
                        "anomaly_score": round(float(scores[i]), 4),
                        "ground_truth": int(y_test[i]),
                        "attack_type": str(attack_types[i]) if attack_types is not None else "unknown",
                        "description": f"Anomaly detected (score: {scores[i]:.4f})",
                    }
                    f.write(json.dumps(record) + "\n")
                    count += 1

        print(f"[INFO] {count:,} alerts saved to: {path}")
