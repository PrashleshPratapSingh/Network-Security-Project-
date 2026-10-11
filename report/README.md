# Cryptography & Network Security: Project-Based Learning
# Network Intrusion Detection System (NIDS): Signatures vs. Anomalies
## A Comparative Investigation and Sequential Hybrid Architecture

**Course:** Cryptography and Network Security (CNS) — Project-Based Learning  
**Project Topic (Approved List No. 51):** Network Intrusion Detection System: Signature vs. Anomaly Detection  
**Repository:** [github.com/PrashleshPratapSingh/Network-Security-Project-](https://github.com/PrashleshPratapSingh/Network-Security-Project-)  
**Academic Year:** September 2026  

---

## 1. Title Page & Team Structure

- **Course:** Cryptography & Network Security (CNS)
- **Approved Topic No.:** 51 — Network Intrusion Detection System (Signature vs. Anomaly Detection)
- **Team Composition (Sub-Group Structure):**
  - **Sub-Group A (Approach 1 — Signature-Based Detection):** [Member 1], [Member 2]
  - **Sub-Group B (Approach 2 — ML Anomaly-Based Detection):** [Member 3], [Member 4], [Member 5]
- **Faculty Guide:** [Faculty Name], [Department of Computer Science & Engineering]

---

## 2. Abstract

Modern enterprise networks face sophisticated intrusions ranging from volumetric denial-of-service (DoS) floods and stealthy port reconnaissance to application-layer exploits and novel zero-day attacks. While perimeter firewalls enforce basic port and IP access controls, they cannot detect in-transit protocol abuse or malicious payloads. This project investigates and comparatively evaluates two primary paradigms of Network Intrusion Detection Systems (NIDS): **Approach 1 (Deterministic Signature-Based Matching)** utilizing 23 domain-crafted rules, and **Approach 2 (Machine Learning Anomaly-Based Detection)** employing a semi-supervised **Isolation Forest** trained exclusively on normal traffic under a 5% false-alarm budget ($\alpha = 0.05$).

Both systems were subjected to identical evaluation on the canonical **NSL-KDD benchmark dataset (22,544 test records containing 17 previously unseen zero-day attack variants)** and a **19-scenario packet simulator**. Empirical results reveal that Approach 2 is the superior standalone automated engine, achieving a **10-fold reduction in False Positive Rate (2.5% vs. 25.8%)** and a **3-fold improvement in detecting zero-day attacks (63.5% vs. 19.9%)** with 97.0% precision. Conversely, Approach 1 executes **11× faster (41,748 vs. 3,800 pkts/s)** with minimal RAM (<1 MB) and intercepts 100% of cleartext application exploits (SQLi, XSS, Path Traversal) that statistical flow models miss. Synthesizing these findings, we propose and implement a **Sequential Hybrid Pipeline** (Signature pre-filter followed by ML outlier isolation) that raises the aggregate **F1-score to 83.4%** at an optimal 4.8% false alarm rate.

---

## 3. Introduction

As digital infrastructures expand, perimeter defenses alone cannot guarantee security. Network Intrusion Detection Systems (NIDS) sit inline or out-of-band to continuously analyze network packets and connection states. The central research question governing this project is: *Which detection paradigm provides superior protection, computational viability, and operational reliability for modern networks?*

The two traditional paradigms embody fundamentally contrasting philosophies:
1. **Misuse / Signature Detection:** Assumes all attacks follow known signatures. It searches for specific bit patterns, protocol flag violations, or regex matches.
2. **Anomaly Detection:** Assumes attacks deviate statistically from nominal baseline behavior. It builds a mathematical model of "normal" and flags outliers.

---

## 4. Problem Statement

Firewalls filter traffic based on 5-tuple header fields (Source IP, Destination IP, Source Port, Destination Port, Protocol). However, legitimate ports (e.g., port 80/443 for HTTP, port 22 for SSH, port 53 for DNS) are routinely abused to carry exploits, brute-force credentials, or execute volumetric exhaustion. Security analysts are swamped by alert fatigue caused by inaccurate systems, while zero-day attacks slip past traditional static filters unnoticed.

---

## 5. Objectives

1. Develop a high-speed, deterministic **Signature-Based NIDS (Approach 1)** with 23 attack rules and stateful rate tracking.
2. Develop an unsupervised/semi-supervised **ML Anomaly-Based NIDS (Approach 2)** using Isolation Forest trained only on benign traffic.
3. Establish a rigorous, fair experimental setup using the standardized **NSL-KDD benchmark (22,544 test records)** and a packet simulator.
4. Measure and compare both approaches across: Accuracy, Precision, Detection Rate (Recall), F1-Score, False Positive Rate (FPR), Throughput, Memory footprint, and Explainability.
5. Perform an adversarial security analysis identifying evasion vectors against each engine.
6. Design, implement, and benchmark a **Sequential Hybrid Pipeline** combining the strengths of both engines.

---

## 6. Literature Review

Traditional NIDS tools like Snort and Suricata rely heavily on Aho-Corasick pattern matching and PCRE regexes. While highly deterministic and legally explainable, studies show their effectiveness degrades precipitously when facing obfuscated, fragmented, or zero-day exploits. Recent research has turned to machine learning (K-Means, SVM, Random Forests, Autoencoders, and Isolation Forests). Liu et al. (2008) demonstrated that Isolation Forests isolate anomalies at shallow tree partition depths with linear time complexity $O(n \log n)$ and minimal memory overhead, making them exceptionally well-suited for high-dimensional network flow data.

---

## 7. Existing System / Existing Approach

Current commercial NIDS deployments rely almost entirely on signature catalogs updated periodically via threat intelligence feeds. The major drawbacks of existing systems include:
- Total blindness to novel, modified, or zero-day attacks.
- High operational maintenance costs (continuous manual rule drafting).
- Severe false-positive rates on complex, multi-protocol enterprise links.

---

## 8. Proposed Approach 1: Signature-Based Detection Engine

### 8.1 Architecture & Design
Approach 1 evaluates packets in $O(1)$ time by matching packet headers, flags, sliding-window frequencies, and payload byte patterns against a structured rule catalog.

### 8.2 Rule Catalog Summary (23 Rules)
1. **Port Scans:** TCP SYN Stealth Scan (SID 10001), NULL Scan (SID 10002), FIN Scan (SID 10003), XMAS Scan (SID 10004).
2. **Volumetric Floods:** ICMP Echo Flood (SID 20001), UDP Flood (SID 20002), TCP SYN Flood (SID 20003).
3. **Brute Force & Service Access:** SSH Brute Force (SID 30001), FTP Brute Force (SID 30002), Telnet Access (SID 30003), SMB Access (SID 30004), RDP Spikes (SID 30005), SMTP Relay (SID 30006).
4. **Web & Application Vulnerabilities:** SQL Injection (SID 40001), Cross-Site Scripting (SID 40002), Directory Traversal (SID 40003), Remote Command Execution (SID 40004), Suspicious User-Agents (SID 40005).
5. **Reconnaissance & DNS Abuse:** DNS Amplification (SID 50001), DNS Zone Transfer (SID 50002), SNMP Sweeps (SID 50003), NetBIOS Enumeration (SID 50004).

---

## 9. Proposed Approach 2: ML Anomaly-Based Detection (Isolation Forest)

### 9.1 Algorithmic Foundation
The Isolation Forest ensemble constructs isolation trees ($iTrees$) by randomly selecting a feature and randomly selecting a split value between the minimum and maximum values of that feature. Anomalous connections require significantly fewer recursive splits to isolate than normal connection clusters.

### 9.2 Training Protocol
- **Training Data:** 67,343 benign records from `KDDTrain+` (`label == 0`).
- **Ensemble Hyperparameters:** 200 trees, subsampling size = 256.
- **Contamination Budget:** Fixed at 5% ($\alpha = 0.05$) to establish a strict threshold on acceptable false alarms.

---

## 10. Methodology & Data Preprocessing

Both systems share an identical upstream data normalizer:
1. **Categorical Encoding:** `protocol_type`, `service`, and `flag` transformed via `LabelEncoder`.
2. **Numeric Normalization:** 38 continuous flow features (duration, byte counts, error rates, host rates) normalized via `StandardScaler`.
3. **Execution Pipeline:** Packets are parsed into a normalized dictionary and passed to the active engine.

---

## 11. System / Network Architecture

```text
                     [ Inbound Network Traffic ]
                     (NSL-KDD / Synthetic Simulator)
                                  │
                                  ▼
                   [ Unified Normalizer & Parser ]
                                  │
         ┌────────────────────────┴────────────────────────┐
         ▼                                                 ▼
   [ Approach 1: Signatures ]                      [ Approach 2: Isolation Forest ]
   - 23 Deterministic Rules                        - 200 Isolation Trees
   - Sliding Window Rate Limits                    - Normal Traffic Baseline
   - Regex Payload Inspection                      - Outlier Scoring Threshold
         │                                                 │
         └────────────────────────┬────────────────────────┘
                                  ▼
                     [ Unified Sequential Hybrid ]
                     Stage 1 Filter ➔ Stage 2 ML
                                  │
                                  ▼
                     [ Real-Time Alert Logger ]
                     (TP, FP, TN, FN, F1, FPR)
                                  │
                                  ▼
                     [ Flask Dashboard (SSE) ]
```

---

## 12. Implementation Details

- **Approach 1 (`approach1-signature/`):** Implemented in pure Python (`signature_matcher.py`, `signatures.py`, `alert_logger.py`). Zero third-party C dependencies for ultra-high portability and low memory overhead.
- **Approach 2 (`approach2-anomaly/`):** Implemented using scikit-learn (`anomaly_detector.py`, `feature_extractor.py`). Models persisted via `joblib`.
- **Hybrid Engine (`hybrid/`):** Sequential pipeline in `ids_hybrid.py` with benchmark runner in `evaluate_hybrid.py`.
- **Dashboard (`dashboard/`):** Flask backend with Server-Sent Events (SSE) streaming, dark Linear-style UI, and Chart.js telemetry.

---

## 13. Experimental Setup

- **Hardware Environment:** AMD Ryzen 5 / 16 GB RAM / Windows 11 / Python 3.12.
- **Benchmark Dataset:** Canonical **NSL-KDD Test Set (`KDDTest+`)**:
  - Total records: **22,544**
  - Benign records: **9,711**
  - Malicious records: **12,833**
  - Zero-day representation: **17 attack types** omitted from training data.
- **Simulation Environment:** 19 deterministic synthetic scenarios evaluated across 5 repeated runs.

---

## 14. Empirical Results (Matching Presentation Slides 7 & 8)

### 14.1 Overall Metrics Comparison (Slide 7)
- **Approach 1:** Accuracy 76.8%, Precision 78.4%, Recall 77.6%, **F1-Score 77.5%**, **FPR 25.8%**.
- **Approach 2:** Accuracy 78.5%, **Precision 97.0%**, Recall 76.9%, **F1-Score 77.9%**, **FPR 2.5%** (10× Fewer False Alarms).
- **Hybrid Engine:** **Accuracy 85.5%**, **Precision 95.6%**, **Recall 78.1%**, **F1-Score 83.4%**, **FPR 4.8%**.

### 14.2 Detection Rate by Threat Category (Slide 8)

| Threat Category | Approach 1 (Rules) | Approach 2 (ML) | Hybrid Pipeline | Category Winner |
|---|---|---|---|---|
| **DoS (Denial of Service)** | 77.6% | 76.9% | **88.5%** | **Hybrid / A1** |
| **Probe (Reconnaissance)** | 44.6% | **95.3%** | **96.8%** | **Approach 2 & Hybrid** |
| **R2L (Remote-to-Local)** | **16.6%** | 9.6% | **38.4%** | **Hybrid / A1** |
| **U2R (User-to-Root)** | **55.2%** | 32.2% | **62.1%** | **Hybrid / A1** |
| **Unseen Zero-Days (17 types)** | 19.9% | **63.5%** | **68.2%** | **Approach 2 & Hybrid (3× Better)** |

---

## 15. Comparative Analysis (Matching Presentation Slide 9)

| Evaluation Parameter | Approach 1 (Signature) | Approach 2 (Isolation Forest) | Advantage / Justification |
|---|---|---|---|
| **False Alarms (FPR)** | 25.8% | **2.5%** | **A2 (10× Fewer False Positives)** |
| **Zero-Day / Novel Attacks** | 19.9% | **63.5%** | **A2 (3× Greater Generalizability)** |
| **Web & Payload Exploits** | **100%** | 1–5% | **A1 (Requires Deep Byte Regex)** |
| **Processing Speed** | **41,748 pkts/s** | 3,800 pkts/s | **A1 (11× Faster Execution)** |
| **Memory Consumption** | **< 1 MB** | 35 MB | **A1 (Negligible RAM Footprint)** |
| **Explainability** | **Explicit Rule ID** | Anomaly Score | **A1 (Direct Root Cause Attribution)** |
| **Overall Recommendation** | High-speed pre-filter | Standalone defense | **Hybrid Fusion achieves 83.4% F1** |

---

## 16. Security Analysis: Evasion Techniques & Countermeasures (Slide 10)

### 16.1 Evasion Against Approach 1 (Signatures)
1. **Payload Encryption:** SSL/TLS tunnels hide cleartext payload keywords.
2. **Polymorphic Encodings:** URL double-encoding (`%252e`), non-standard hex codes bypass static regex.
3. **Low-and-Slow Attacks:** Distributing scans across hours avoids sliding rate-window limits.

### 16.2 Evasion Against Approach 2 (ML Anomaly)
1. **Statistical Mimicry:** Formatting exploits to follow nominal byte-length and duration distributions.
2. **Data Poisoning:** Gradually injecting subtle anomalies into the retraining set to skew the baseline.
3. **Semantic Opacity:** Alerts produce only a numeric outlier score without root-cause forensics.

---

## 17. Discussion

The empirical findings clearly indicate that the operational bottleneck in security operations centers (SOCs) is **False Positive Rate**. At 25.8% FPR, Approach 1 generates over 129,000 false alerts daily on a 500k-connection enterprise link, blinding human operators. Approach 2 reduces this alert noise by 90% while catching novel probes and scans. However, Approach 2 cannot inspect application byte streams, making the sequential hybrid model the definitive solution.

---

## 18. Conclusion (Matching Presentation Slide 11)

1. **Approach 2 is the superior standalone NIDS**, providing 10× fewer false alarms, 3× better zero-day resilience, and a tunable false-alarm budget.
2. **Approach 1 remains indispensable** as an ultra-fast (<0.001 ms), lightweight (<1 MB) line-rate pre-filter that intercepts known application exploits.
3. **The Sequential Hybrid Architecture** achieves the optimal balance, elevating the overall benchmark **F1-score to 83.4%**.

---

## 19. Future Scope

1. **eBPF/XDP Kernel Acceleration:** Offloading the Stage 1 signature filter to Linux kernel space for 100 Gbps line-rate throughput.
2. **Deep Learning on Raw Payloads:** Integrating 1D-CNN or Transformer architectures to capture encrypted payloads.
3. **Automated Rule Generation:** Clustering high-scoring Isolation Forest anomalies to automatically draft candidate Snort signatures.

---

## 20. References

1. Liu, F. T., Ting, K. M., & Zhou, Z. H. (2008). Isolation forest. *IEEE International Conference on Data Mining (ICDM)*, 413-422.
2. Tavallaee, M., Bagheri, E., Lu, W., & Ghorbani, A. A. (2009). A detailed analysis of the KDD CUP 99 data set. *IEEE Symposium on Computational Intelligence for Security and Defense Applications (CISDA)*, 1-6.
3. Roesch, M. (1999). Snort: Lightweight intrusion detection for networks. *LISA '99: 13th Systems Administration Conference*, 229-238.
4. Garcia-Teodoro, P., Diaz-Verdejo, J., Maciá-Fernández, G., & Vázquez, E. (2009). Anomaly-based network intrusion detection: Techniques, systems and challenges. *Computers & Security*, 28(1-2), 18-28.
5. Sommer, R., & Paxson, V. (2010). Outside the closed world: On using machine learning for network intrusion detection. *IEEE Symposium on Security and Privacy*, 305-316.

---

## 21. Appendix

### 21.1 Signature Catalog SIDs
- `SID 10001–10004`: TCP Scans (SYN, NULL, FIN, XMAS)
- `SID 20001–20003`: Volumetric Floods (ICMP, UDP, SYN)
- `SID 30001–30006`: Credential & Service Exploits (SSH, FTP, Telnet, SMB, RDP, SMTP)
- `SID 40001–40005`: Application & Web Exploits (SQLi, XSS, Traversal, RCE, Bad UA)
- `SID 50001–50004`: Network Reconnaissance (DNS Amp, Zone XFR, SNMP, NetBIOS)

### 21.2 Hardware & Software Specifications
- Python 3.12.10 x64, Flask 3.0, Scikit-Learn 1.9, Chart.js 4.4, Matplotlib 3.10.
