"""
alert_logger.py — Alert Logging & Metrics Tracking for NIDS Approach 1
-----------------------------------------------------------------------
Handles:
  - Console printing (color-coded by severity)
  - Writing alerts to a log file (JSON Lines format)
  - Tracking TP/FP/FN metrics when ground-truth labels are available
  - Generating a final metrics summary
"""

import os
import json
import time
from signature_matcher import Alert

# ── Default log file path ─────────────────────────────────────────────────────
LOG_DIR  = os.path.join(os.path.dirname(__file__), "..", "results")
LOG_FILE = os.path.join(LOG_DIR, "approach1_alerts.jsonl")
METRICS_FILE = os.path.join(LOG_DIR, "approach1_metrics.json")


class AlertLogger:
    """
    Collects alerts, prints them, and writes them to a JSONL log file.
    Also tracks TP/FP/FN when ground-truth labels are provided.
    """

    def __init__(self, log_file: str = LOG_FILE, verbose: bool = True):
        self.log_file    = log_file
        self.verbose     = verbose
        self._alerts: list[Alert] = []

        # Metrics counters
        self._tp = 0   # True Positive  — attack detected, was actually attack
        self._fp = 0   # False Positive — attack detected, was actually normal
        self._tn = 0   # True Negative  — no alert, was actually normal
        self._fn = 0   # False Negative — no alert, was actually attack
        self._total_packets = 0

        # Alert severity counts
        self._severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}

        # Ensure log directory exists
        os.makedirs(LOG_DIR, exist_ok=True)

        # Open log file in append mode
        self._log_fh = open(self.log_file, "a")

        if self.verbose:
            _print_banner()

    # ── Core logging ──────────────────────────────────────────────────────────

    def log(self, alerts: list[Alert], ground_truth: int | None = None):
        """
        Log a list of alerts from one packet.

        Args:
            alerts:       List of Alert objects (empty = no match)
            ground_truth: 1 = packet was an attack, 0 = normal, None = unknown
        """
        self._total_packets += 1
        detected = len(alerts) > 0

        # Update confusion matrix counters if we have ground truth
        if ground_truth is not None:
            if detected and ground_truth == 1:
                self._tp += 1
            elif detected and ground_truth == 0:
                self._fp += 1
            elif not detected and ground_truth == 0:
                self._tn += 1
            elif not detected and ground_truth == 1:
                self._fn += 1

        # Log each alert
        for alert in alerts:
            self._alerts.append(alert)
            self._severity_counts[alert.severity] = \
                self._severity_counts.get(alert.severity, 0) + 1

            # Print to console
            if self.verbose:
                print(str(alert))

            # Write to JSONL file
            record = alert.to_dict()
            if ground_truth is not None:
                record["ground_truth"] = ground_truth
            self._log_fh.write(json.dumps(record) + "\n")
            self._log_fh.flush()

    def log_normal(self, ground_truth: int | None = None):
        """Call this when a packet produced NO alerts (used for FN/TN tracking)."""
        self.log([], ground_truth=ground_truth)

    # ── Metrics ───────────────────────────────────────────────────────────────

    def get_metrics(self) -> dict:
        """Calculate and return all performance metrics."""
        tp, fp, tn, fn = self._tp, self._fp, self._tn, self._fn

        precision   = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall      = tp / (tp + fn) if (tp + fn) > 0 else 0.0   # = Detection Rate
        f1          = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
        accuracy    = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0.0
        fpr         = fp / (fp + tn) if (fp + tn) > 0 else 0.0   # False Positive Rate

        return {
            "total_packets":    self._total_packets,
            "total_alerts":     len(self._alerts),
            "true_positives":   tp,
            "false_positives":  fp,
            "true_negatives":   tn,
            "false_negatives":  fn,
            "accuracy":         round(accuracy * 100, 2),
            "precision":        round(precision * 100, 2),
            "recall_detection_rate": round(recall * 100, 2),
            "f1_score":         round(f1, 4),
            "false_positive_rate": round(fpr * 100, 2),
            "severity_counts":  self._severity_counts,
        }

    def print_summary(self):
        """Print a formatted metrics summary to console."""
        m = self.get_metrics()
        has_gt = (self._tp + self._fp + self._tn + self._fn) > 0

        print("\n" + "═" * 60)
        print("  NIDS — APPROACH 1 (SIGNATURE-BASED) — RESULTS SUMMARY")
        print("═" * 60)
        print(f"  Total Packets Analysed : {m['total_packets']}")
        print(f"  Total Alerts Generated : {m['total_alerts']}")
        print(f"  HIGH severity alerts   : {m['severity_counts'].get('HIGH', 0)}")
        print(f"  MEDIUM severity alerts : {m['severity_counts'].get('MEDIUM', 0)}")
        print(f"  LOW severity alerts    : {m['severity_counts'].get('LOW', 0)}")

        if has_gt:
            print(f"\n  ── Metrics (with ground truth) ──────────────────────")
            print(f"  True  Positives  (TP) : {m['true_positives']}")
            print(f"  False Positives  (FP) : {m['false_positives']}")
            print(f"  True  Negatives  (TN) : {m['true_negatives']}")
            print(f"  False Negatives  (FN) : {m['false_negatives']}")
            print(f"\n  Accuracy              : {m['accuracy']}%")
            print(f"  Precision             : {m['precision']}%")
            print(f"  Detection Rate/Recall : {m['recall_detection_rate']}%")
            print(f"  F1 Score              : {m['f1_score']}")
            print(f"  False Positive Rate   : {m['false_positive_rate']}%")

        print(f"\n  Log file: {self.log_file}")
        print("═" * 60 + "\n")

    def save_metrics(self):
        """Save metrics JSON to results directory."""
        m = self.get_metrics()
        m["generated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        with open(METRICS_FILE, "w") as f:
            json.dump(m, f, indent=2)
        print(f"[INFO] Metrics saved to: {METRICS_FILE}")

    def close(self):
        """Flush and close the log file."""
        self._log_fh.flush()
        self._log_fh.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


# ── Banner ────────────────────────────────────────────────────────────────────

def _print_banner():
    banner = r"""
  ╔═══════════════════════════════════════════════════════╗
  ║   NETWORK INTRUSION DETECTION SYSTEM — APPROACH 1    ║
  ║         Signature-Based Detection Engine              ║
  ╚═══════════════════════════════════════════════════════╝
"""
    print(banner)
