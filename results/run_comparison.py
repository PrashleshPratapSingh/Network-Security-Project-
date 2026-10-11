"""
run_comparison.py -- Run Both Approaches on NSL-KDD & Compare
---------------------------------------------------------------
Executes Approach 1 (Signature-based) and Approach 2 (Isolation Forest)
on the same NSL-KDD test set, measures timing and memory, and outputs
a unified comparison report.

Usage:
  python results/run_comparison.py
"""

import json
import os
import sys
import time
import csv
import psutil
import numpy as np

# -- Path setup ----------------------------------------------------------------
BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(BASE_DIR)
A1_DIR      = os.path.join(PROJECT_DIR, "approach1-signature")
A2_DIR      = os.path.join(PROJECT_DIR, "approach2-anomaly")
DATASET_DIR = os.path.join(PROJECT_DIR, "datasets")
RESULTS_DIR = BASE_DIR

sys.path.insert(0, A1_DIR)
sys.path.insert(0, A2_DIR)

TEST_CSV = os.path.join(DATASET_DIR, "KDDTest+.csv")
TRAIN_CSV = os.path.join(DATASET_DIR, "KDDTrain+.csv")


def run_approach1_on_nslkdd() -> dict:
    """Run Approach 1 (Signature-based) on NSL-KDD test set."""
    from signature_matcher import match_packet
    from alert_logger import AlertLogger

    print("\n" + "=" * 60)
    print("  Running APPROACH 1 (Signature-Based) on NSL-KDD Test Set")
    print("=" * 60 + "\n")

    if not os.path.isfile(TEST_CSV):
        print(f"[ERROR] Test CSV not found: {TEST_CSV}")
        print("        Run: python datasets/download_nslkdd.py")
        sys.exit(1)

    log_path = os.path.join(RESULTS_DIR, "approach1_alerts.jsonl")

    # Clear old alerts
    if os.path.isfile(log_path):
        open(log_path, "w").close()

    tp = fp = tn = fn = 0
    total = 0
    severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}

    proc = psutil.Process(os.getpid())
    mem_before = proc.memory_info().rss

    start = time.time()

    with open(TEST_CSV, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            total += 1

            # Map NSL-KDD columns to Approach 1 packet format
            proto_map = {"tcp": "TCP", "udp": "UDP", "icmp": "ICMP"}
            protocol = proto_map.get(row.get("protocol_type", "").lower(), "TCP")

            # Map service to port numbers
            service_port = _service_to_port(row.get("service", ""))

            parsed = {
                "src_ip": "0.0.0.0",
                "dst_ip": "0.0.0.0",
                "protocol": protocol,
                "src_port": 0,
                "dst_port": service_port,
                "flags": _map_nslkdd_flags(row.get("flag", "")),
                "payload": "",
                "size": int(float(row.get("src_bytes", 0) or 0)),
                "raw_summary": f"{protocol} -> port {service_port}",
            }

            gt = int(row.get("label", 0))
            alerts = match_packet(parsed)
            detected = len(alerts) > 0

            if detected and gt == 1:
                tp += 1
            elif detected and gt == 0:
                fp += 1
            elif not detected and gt == 0:
                tn += 1
            elif not detected and gt == 1:
                fn += 1

            for a in alerts:
                severity_counts[a.severity] = severity_counts.get(a.severity, 0) + 1

    elapsed = time.time() - start
    mem_after = proc.memory_info().rss
    mem_used = (mem_after - mem_before) / (1024 * 1024)

    # Calculate metrics
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    accuracy = (tp + tn) / total * 100 if total > 0 else 0
    fpr_val = fp / (fp + tn) * 100 if (fp + tn) > 0 else 0

    metrics = {
        "total_packets": total,
        "total_alerts": tp + fp,
        "true_positives": tp,
        "false_positives": fp,
        "true_negatives": tn,
        "false_negatives": fn,
        "accuracy": round(accuracy, 2),
        "precision": round(precision * 100, 2),
        "recall_detection_rate": round(recall * 100, 2),
        "f1_score": round(f1, 4),
        "false_positive_rate": round(fpr_val, 2),
        "wall_time_seconds": round(elapsed, 2),
        "throughput_records_per_sec": round(total / elapsed, 0) if elapsed > 0 else 0,
        "memory_mb": round(mem_used, 1),
        "severity_counts": severity_counts,
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }

    # Save
    with open(os.path.join(RESULTS_DIR, "approach1_metrics.json"), "w") as f:
        json.dump(metrics, f, indent=2)

    _print_metrics("APPROACH 1 (Signature-Based)", metrics)
    return metrics


def run_approach2_on_nslkdd() -> dict:
    """Run Approach 2 (Isolation Forest) on NSL-KDD test set."""
    from feature_extractor import prepare_training_data, prepare_test_data, load_encoders
    from anomaly_detector import AnomalyDetector

    print("\n" + "=" * 60)
    print("  Running APPROACH 2 (ML Anomaly) on NSL-KDD Test Set")
    print("=" * 60 + "\n")

    # Check if model exists; if not, train first
    from anomaly_detector import MODEL_PATH
    detector = AnomalyDetector(contamination=0.05, n_estimators=200)

    if not os.path.isfile(MODEL_PATH):
        print("[INFO] No trained model found. Training now...")
        X_train, encoders = prepare_training_data()
        detector.train(X_train)
    else:
        detector.load()

    encoders = load_encoders()
    X_test, y_test, attack_types, attack_categories, df_test = prepare_test_data(encoders)

    proc = psutil.Process(os.getpid())

    metrics = detector.evaluate(
        X_test, y_test,
        attack_types=attack_types,
        attack_categories=attack_categories,
    )

    # Save
    detector.save_metrics(metrics)

    # Save alerts
    y_pred = detector.predict(X_test)
    scores = detector.predict_scores(X_test)
    detector.save_alerts(X_test, y_test, y_pred, scores, attack_types)

    return metrics


def generate_comparison_report(m1: dict, m2: dict):
    """Generate the head-to-head comparison JSON and print it."""
    print("\n" + "=" * 60)
    print("  HEAD-TO-HEAD COMPARISON")
    print("=" * 60)

    comparisons = [
        ("Accuracy (%)", m1.get("accuracy", 0), m2.get("accuracy", 0), "higher"),
        ("Precision (%)", m1.get("precision", 0), m2.get("precision", 0), "higher"),
        ("Detection Rate / Recall (%)", m1.get("recall_detection_rate", 0),
         m2.get("recall_detection_rate", 0), "higher"),
        ("F1 Score", m1.get("f1_score", 0), m2.get("f1_score", 0), "higher"),
        ("False Positive Rate (%)", m1.get("false_positive_rate", 0),
         m2.get("false_positive_rate", 0), "lower"),
        ("Speed (records/sec)", m1.get("throughput_records_per_sec", 0),
         m2.get("throughput_records_per_sec", 0), "higher"),
        ("Memory (MB)", m1.get("memory_mb", 0), m2.get("memory_mb", 0), "lower"),
    ]

    report = {"approach1": m1, "approach2": m2, "comparisons": []}

    for name, v1, v2, better_dir in comparisons:
        if better_dir == "higher":
            winner = "A1" if v1 > v2 else ("A2" if v2 > v1 else "Tie")
        else:
            winner = "A1" if v1 < v2 else ("A2" if v2 < v1 else "Tie")

        report["comparisons"].append({
            "metric": name, "approach1": v1, "approach2": v2, "winner": winner
        })

        marker = "<--" if winner == "A1" else ("  -->" if winner == "A2" else "  ==")
        print(f"  {name:35s}  A1: {v1:>10}  |  A2: {v2:>10}  {marker} {winner}")

    # Unseen attack detection comparison
    # A1 doesn't do unseen attacks well; A2 uses anomaly detection
    a2_cat = m2.get("per_category", {})
    if a2_cat:
        print(f"\n  Per-Category Detection Rates (Approach 2):")
        for cat, data in a2_cat.items():
            print(f"    {cat:10s}: {data['detection_rate']:.1f}% ({data['detected']}/{data['total']})")

    report["generated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")

    # Save
    report_path = os.path.join(RESULTS_DIR, "comparison_report.json")
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\n[INFO] Comparison report saved to: {report_path}")

    return report


def _print_metrics(title: str, m: dict):
    print(f"\n  -- {title} --")
    print(f"  Accuracy         : {m.get('accuracy', 0):.2f}%")
    print(f"  Precision        : {m.get('precision', 0):.2f}%")
    print(f"  Detection Rate   : {m.get('recall_detection_rate', 0):.2f}%")
    print(f"  F1 Score         : {m.get('f1_score', 0):.4f}")
    print(f"  FPR              : {m.get('false_positive_rate', 0):.2f}%")
    print(f"  Time             : {m.get('wall_time_seconds', 0):.2f}s")
    print(f"  Memory           : {m.get('memory_mb', 0):.1f} MB")


def _service_to_port(service: str) -> int:
    """Map NSL-KDD service names to common port numbers."""
    service_ports = {
        "http": 80, "http_443": 443, "https": 443,
        "ftp": 21, "ftp_data": 20, "ssh": 22, "telnet": 23,
        "smtp": 25, "domain": 53, "domain_u": 53,
        "pop_3": 110, "imap4": 143,
        "netbios_ns": 137, "netbios_dgm": 138, "netbios_ssn": 139,
        "snmp": 161, "ldap": 389,
        "finger": 79, "auth": 113, "login": 513, "shell": 514,
        "printer": 515, "whois": 43, "nntp": 119,
        "ntp_u": 123, "klogin": 543, "kshell": 544,
        "ecr_i": 0, "eco_i": 0, "tim_i": 0, "urp_i": 0,
        "private": 0, "other": 0, "IRC": 6667,
        "X11": 6000, "Z39_50": 210, "sunrpc": 111,
        "bgp": 179, "csnet_ns": 105, "ctf": 84,
        "daytime": 13, "discard": 9, "echo": 7,
        "exec": 512, "gopher": 70, "hostnames": 101,
        "iso_tsap": 102, "link": 87, "mtp": 57,
        "name": 42, "netstat": 15, "pm_dump": 0,
        "pop_2": 109, "remote_job": 71, "rje": 77,
        "sql_net": 1521, "supdup": 95, "systat": 11,
        "time": 37, "uucp": 540, "uucp_path": 117,
        "vmnet": 175, "courier": 530, "harvest": 0,
        "aol": 5190, "http_2784": 2784, "http_8001": 8001,
        "tftp_u": 69, "red_i": 0, "urh_i": 0,
    }
    return service_ports.get(service.lower().strip(), 0)


def _map_nslkdd_flags(flag: str) -> str:
    """Map NSL-KDD flag values to TCP flag letters."""
    flag_map = {
        "SF": "SA",    # SYN+ACK (normal connection)
        "S0": "S",     # SYN only (connection attempt)
        "REJ": "R",    # RST (rejected)
        "RSTR": "R",
        "RSTO": "R",
        "S1": "SA",
        "S2": "SA",
        "S3": "SA",
        "SH": "S",
        "OTH": "",
    }
    return flag_map.get(flag.strip(), "")


def main():
    print("\n" + "=" * 60)
    print("  NIDS -- COMPARATIVE ANALYSIS")
    print("  Approach 1 (Signature) vs Approach 2 (ML Anomaly)")
    print("=" * 60)

    # Run both approaches
    m1 = run_approach1_on_nslkdd()
    m2 = run_approach2_on_nslkdd()

    # Generate comparison
    generate_comparison_report(m1, m2)

    print("\n[*] Comparison complete. Run plot_comparison.py to generate charts.\n")


if __name__ == "__main__":
    main()
