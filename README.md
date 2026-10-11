# Network Intrusion Detection System (NIDS): Signatures vs. Anomalies

A comparative study and implementation of **Signature-Based** and **Machine Learning Anomaly-Based (Isolation Forest)** Network Intrusion Detection Systems for Cryptography & Network Security (CNS) Project-Based Learning.

[![Python Version](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue)](https://www.python.org/)
[![Status](https://img.shields.io/badge/status-completed-brightgreen)]()
[![Dataset](https://img.shields.io/badge/dataset-NSL--KDD-orange)](https://www.unb.ca/cic/datasets/nsl.html)

---

## 📌 Project Overview

Perimeter firewalls allow permissible traffic but cannot verify whether connections carry exploit payloads or exhibit abusive patterns. This project builds and comparatively evaluates two NIDS architectures evaluated on the canonical **NSL-KDD benchmark (22,544 test records, 17 unseen attack types)** and a **19-scenario synthetic packet simulator**:

1. **Approach 1 — Signature-Based NIDS:** 23 pattern-matching rules covering port scans, SYN/UDP/ICMP floods, brute-force logins, and web exploits (SQLi, XSS, Path Traversal).
2. **Approach 2 — ML Anomaly-Based NIDS:** Semi-supervised **Isolation Forest** trained exclusively on normal traffic with a 5% false-alarm budget ($\alpha = 0.05$) to isolate outliers across multi-dimensional feature space.
3. **Unified Real-Time Dashboard:** Flask + Server-Sent Events (SSE) web interface with live alert feeds, metric cards, and side-by-side comparison charts.

---

## 📊 Key Results at a Glance

| Performance Dimension | Approach 1 (Signature) | Approach 2 (Isolation Forest) | Advantage |
|---|---|---|---|
| **False Positive Rate (FPR)** | 25.8% | **2.5%** | **A2 (10× Fewer False Alarms)** |
| **Precision** | 78.4% | **97.0%** | **A2 (97% of Alerts are Real Attacks)** |
| **Detection Rate (Recall)** | **82.1%** | 76.8% | **A1 (High on Known Signatures)** |
| **F1-Score** | 0.802 | **0.814** | **A2** |
| **Zero-Day / Unseen Attacks** | 19.9% | **63.5%** | **A2 (3× Better Generalization)** |
| **Web & Payload Exploits** | **100.0%** | 3.2% | **A1 (Deep Regex Inspection)** |
| **Speed / Throughput** | **~42,000 pkts/s** | ~3,800 pkts/s | **A1 (11× Faster Execution)** |
| **Memory Footprint** | **< 1 MB** | ~35 MB | **A1 (Minimal Overhead)** |
| **Explainability** | **Explicit Rule ID** | Anomaly Score | **A1 (Direct Root Cause Attribution)** |

> **Key Takeaway:** Approach 2 is the superior standalone automated defense engine due to its 10× lower false alarm rate and 3× higher zero-day detection rate. However, a **sequential hybrid pipeline** achieves the ultimate defense (**F1-Score 83.4%**).

---

## 🗂️ Project Directory Structure

```text
.
├── approach1-signature/          # Approach 1: Signature-Based NIDS
│   ├── signatures.py             # 23 Snort-style detection rules
│   ├── signature_matcher.py      # Packet & rate-limit matching engine
│   ├── packet_parser.py          # Unified packet & flow normalizer
│   ├── alert_logger.py           # Alert logging & confusion matrix aggregator
│   ├── traffic_simulator.py      # 19 realistic traffic scenario generators
│   ├── ids_signature.py          # CLI entry point for Approach 1
│   └── visualize_results.py      # Matplotlib visualizer for Approach 1
├── approach2-anomaly/            # Approach 2: ML Anomaly-Based NIDS
│   ├── anomaly_detector.py       # Isolation Forest anomaly engine
│   ├── feature_extractor.py      # Categorical encoding & standard scaling
│   ├── ids_anomaly.py            # CLI entry point (train / test / evaluate)
│   ├── visualize_results_a2.py   # Confusion matrix & ROC visualizer
│   └── requirements.txt          # Approach 2 dependencies
├── dashboard/                    # Real-Time Web Dashboard (Flask + SSE)
│   ├── app.py                    # Multi-threaded server (A1 & A2 live engines)
│   ├── templates/index.html      # Responsive glassmorphic UI
│   └── static/                   # CSS styling, Chart.js, and SSE client
├── datasets/                     # Dataset Directory
│   ├── download_nslkdd.py        # Automated NSL-KDD downloader & converter
│   ├── KDDTrain+.csv             # NSL-KDD Training Set (125,973 records)
│   └── KDDTest+.csv              # NSL-KDD Test Set (22,544 records)
├── results/                      # Evaluation & Comparison Artifacts
│   ├── run_comparison.py         # Head-to-head comparison runner
│   ├── plot_comparison.py        # PPT-matched 5 comparison charts generator
│   ├── comparison_report.json    # Machine-readable evaluation report
│   ├── approach1_metrics.json    # Approach 1 metrics artifact
│   └── approach2_metrics.json    # Approach 2 metrics artifact
├── report/                       # Project Documentation
│   └── README.md                 # Complete academic report matching PPT & PBL
├── NIDS_Project_Presentation.pptx # Project presentation slide deck
└── README.md                     # Repository documentation
```

---

## 🚀 Quick Start Guide

### 1. Installation
Clone repository and install dependencies:
```bash
git clone https://github.com/PrashleshPratapSingh/Network-Security-Project-.git
cd Network-Security-Project-
pip install -r approach2-anomaly/requirements.txt
```

### 2. Prepare Dataset
Download and preprocess NSL-KDD dataset (if not already downloaded):
```bash
python datasets/download_nslkdd.py
```

### 3. Run Approach 1 (Signature-Based)
```bash
# Run simulator with 300 packets (40% attack ratio)
python approach1-signature/ids_signature.py --mode simulator --packets 300

# Run evaluation on NSL-KDD test set
python approach1-signature/ids_signature.py --mode csv --input datasets/KDDTest+.csv
```

### 4. Run Approach 2 (ML Isolation Forest)
```bash
# Train on normal traffic and evaluate on test set
python approach2-anomaly/ids_anomaly.py --train --test

# Run multi-run evaluation (5 repeated runs)
python approach2-anomaly/ids_anomaly.py --test --runs 5
```

### 5. Run Head-to-Head Comparative Study
Execute both approaches sequentially on the exact same 22,544 test records and generate side-by-side comparison charts:
```bash
# Run automated comparison
python results/run_comparison.py

# Generate comparison plots (saved to results/comparison_plots/)
python results/plot_comparison.py
```

### 6. Launch Real-Time Dashboard
Start the unified interactive dashboard:
```bash
python dashboard/app.py
```
Open **`http://localhost:5000`** in your browser to view live packet streaming, live alert feed, real-time metrics cards, and interactive comparison views.

---

## 👥 Contributors
- **Student Team:** [Member 1] • [Member 2] • [Member 3] • [Member 4] • [Member 5]
- **Faculty Guide:** [Faculty Name]
- **Course:** Cryptography & Network Security (CNS) — Project-Based Learning
