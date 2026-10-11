"""
dashboard/app.py — Flask Backend for NIDS Unified Dashboard
------------------------------------------------------------
Runs Approach 1 simulation INSIDE a background thread (no subprocess).
Alerts are pushed directly into the SSE queue — guaranteed real-time delivery.
"""

import json
import os
import queue
import sys
import threading
import time

from flask import Flask, Response, jsonify, render_template, request

# ── Add approach1 to path ─────────────────────────────────────────────────────
BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR  = os.path.dirname(BASE_DIR)
A1_DIR       = os.path.join(PROJECT_DIR, "approach1-signature")
RESULTS_DIR  = os.path.join(PROJECT_DIR, "results")
DATASETS_DIR = os.path.join(PROJECT_DIR, "datasets")

A2_DIR       = os.path.join(PROJECT_DIR, "approach2-anomaly")

sys.path.insert(0, A1_DIR)
sys.path.insert(0, A2_DIR)

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["SECRET_KEY"] = "nids-dashboard-key"

# ── Global SSE broadcast queue ────────────────────────────────────────────────
# Every SSE subscriber gets its own queue clone via a subscriber list
_subscribers: list[queue.Queue] = []
_subscribers_lock = threading.Lock()

def _broadcast(obj: dict):
    """Push a JSON-serialisable dict to every connected SSE subscriber."""
    msg = json.dumps(obj)
    with _subscribers_lock:
        dead = []
        for q in _subscribers:
            try:
                q.put_nowait(msg)
            except queue.Full:
                dead.append(q)
        for q in dead:
            _subscribers.remove(q)

# ── Shared run-state ──────────────────────────────────────────────────────────
_state = {
    "approach1": {"status": "stopped", "alerts": [], "metrics": {}, "mode": "simulator"},
    "approach2": {"status": "stopped", "alerts": [], "metrics": {}, "mode": "simulator"},
}
_stop_events = {
    "approach1": threading.Event(),
    "approach2": threading.Event(),
}

# ── Approach 1 — in-process simulation thread ─────────────────────────────────

def _run_approach1_thread(mode: str, opts: dict):
    """Run Approach 1 inside a thread and push alerts directly to SSE."""
    from signature_matcher import match_packet
    from alert_logger import AlertLogger

    state = _state["approach1"]
    stop_ev = _stop_events["approach1"]
    stop_ev.clear()

    _broadcast({"type": "status", "approach": "approach1", "status": "running"})

    os.makedirs(RESULTS_DIR, exist_ok=True)
    log_path = os.path.join(RESULTS_DIR, "approach1_alerts.jsonl")

    with AlertLogger(log_file=log_path, verbose=False) as logger:

        if mode == "simulator":
            _run_simulator(state, logger, stop_ev, opts)
        elif mode == "csv":
            _run_csv(state, logger, stop_ev, opts)

        logger.print_summary()
        logger.save_metrics()

        # Push final metrics
        metrics = logger.get_metrics()
        state["metrics"] = metrics
        _broadcast({"type": "metrics_final", "approach": "approach1", "metrics": metrics})

    state["status"] = "done"
    _broadcast({"type": "status", "approach": "approach1", "status": "done",
                "metrics": state["metrics"]})


def _run_simulator(state, logger, stop_ev, opts):
    """Run synthetic traffic simulation."""
    import random

    n_packets    = int(opts.get("packets", 300))
    attack_ratio = float(opts.get("attack_ratio", 0.40))

    # Import scenario factories from traffic_simulator
    sys.path.insert(0, A1_DIR)
    from traffic_simulator import SCENARIOS, GROUND_TRUTH, flood_sources_map

    attack_scenarios = [k for k, v in GROUND_TRUTH.items() if v == 1]
    normal_scenarios = [k for k, v in GROUND_TRUTH.items() if v == 0]

    _broadcast({"type": "log", "approach": "approach1",
                "message": f"[Simulator] Generating {n_packets} packets ({int(attack_ratio*100)}% attacks)…"})

    from signature_matcher import match_packet

    for i in range(n_packets):
        if stop_ev.is_set():
            break

        if random.random() < attack_ratio:
            name = random.choice(attack_scenarios)
            pkt  = SCENARIOS[name]()
            fs   = flood_sources_map()
            if name in fs:
                pkt["src_ip"] = fs[name]
            gt = 1
        else:
            name = random.choice(normal_scenarios)
            pkt  = SCENARIOS[name]()
            gt   = 0

        alerts = match_packet(pkt)

        if alerts:
            logger.log(alerts, ground_truth=gt)
            for alert in alerts:
                ad = alert.to_dict()
                ad["src_dst"] = f"{pkt.get('src_ip','?')}:{pkt.get('src_port','?')} → {pkt.get('dst_ip','?')}:{pkt.get('dst_port','?')}"
                state["alerts"].append(ad)
                _broadcast({"type": "alert", "approach": "approach1", "alert": ad})
        else:
            logger.log_normal(ground_truth=gt)

        # Broadcast live metrics every 25 packets
        if (i + 1) % 25 == 0:
            m = logger.get_metrics()
            state["metrics"] = m
            _broadcast({"type": "metrics", "approach": "approach1", "metrics": m,
                        "progress": i + 1, "total": n_packets})

        # Tiny delay so the browser can render — floods still cluster
        time.sleep(0.015)

    _broadcast({"type": "log", "approach": "approach1",
                "message": f"[Simulator] Done — {n_packets} packets processed."})


def _run_csv(state, logger, stop_ev, opts):
    """Run CSV dataset mode (UNSW-NB15)."""
    import csv as csv_mod
    from packet_parser import parse_csv_row
    from signature_matcher import match_packet

    csv_path = opts.get("input") or os.path.join(DATASETS_DIR, "UNSW_NB15_training-set.csv")
    max_rows = int(opts.get("max_rows", 0))

    if not os.path.isfile(csv_path):
        _broadcast({"type": "log", "approach": "approach1",
                    "message": f"[ERROR] CSV not found: {csv_path}"})
        return

    _broadcast({"type": "log", "approach": "approach1",
                "message": f"[CSV] Loading: {os.path.basename(csv_path)}"})

    count = 0
    with open(csv_path, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv_mod.DictReader(f)
        for row in reader:
            if stop_ev.is_set():
                break
            if max_rows and count >= max_rows:
                break

            count += 1
            try:
                parsed = parse_csv_row(row)
            except Exception:
                continue
            if not parsed:
                continue

            gt = parsed.get("ground_truth_label")
            alerts = match_packet(parsed)

            if alerts:
                logger.log(alerts, ground_truth=gt)
                for alert in alerts:
                    ad = alert.to_dict()
                    ad["src_dst"] = f"{parsed.get('src_ip','?')} → {parsed.get('dst_ip','?')}"
                    state["alerts"].append(ad)
                    _broadcast({"type": "alert", "approach": "approach1", "alert": ad})
            else:
                logger.log_normal(ground_truth=gt)

            if count % 25 == 0:
                m = logger.get_metrics()
                state["metrics"] = m
                _broadcast({"type": "metrics", "approach": "approach1", "metrics": m,
                            "progress": count})

    _broadcast({"type": "log", "approach": "approach1",
                "message": f"[CSV] Done — {count} rows processed."})


# ── Approach 2 — ML Anomaly Detection thread ──────────────────────────────

def _run_approach2_thread(mode: str, opts: dict):
    """Run Approach 2 inside a thread and push alerts directly to SSE."""
    state = _state["approach2"]
    stop_ev = _stop_events["approach2"]
    stop_ev.clear()

    _broadcast({"type": "status", "approach": "approach2", "status": "running"})

    os.makedirs(RESULTS_DIR, exist_ok=True)
    from anomaly_detector import AnomalyDetector, MODEL_PATH
    from feature_extractor import prepare_training_data, load_encoders

    contamination = float(opts.get("contamination", 0.05))
    detector = AnomalyDetector(contamination=contamination, n_estimators=100)

    if not os.path.isfile(MODEL_PATH):
        _broadcast({"type": "log", "approach": "approach2",
                    "message": "[Approach 2] No trained model found — training Isolation Forest on normal traffic..."})
        X_train, encoders = prepare_training_data()
        detector.train(X_train)
        _broadcast({"type": "log", "approach": "approach2",
                    "message": "[Approach 2] Model training complete!"})
    else:
        detector.load()
        encoders = load_encoders()

    if mode == "simulator":
        _run_approach2_simulator(state, detector, encoders, stop_ev, opts)
    elif mode == "csv":
        _run_approach2_csv(state, detector, encoders, stop_ev, opts)

    # Save metrics
    metrics = state.get("metrics", {})
    if metrics:
        path = os.path.join(RESULTS_DIR, "approach2_metrics.json")
        with open(path, "w") as f:
            json.dump(metrics, f, indent=2)

    state["status"] = "done"
    _broadcast({"type": "metrics_final", "approach": "approach2", "metrics": metrics})
    _broadcast({"type": "status", "approach": "approach2", "status": "done",
                "metrics": metrics})


def _run_approach2_simulator(state, detector, encoders, stop_ev, opts):
    """Run Approach 2 evaluation on simulated / sampled NSL-KDD test traffic."""
    import random
    import pandas as pd
    from feature_extractor import TEST_CSV, transform_features

    n_packets    = int(opts.get("packets", 300))
    attack_ratio = float(opts.get("attack_ratio", 0.40))

    _broadcast({"type": "log", "approach": "approach2",
                "message": f"[ML Simulator] Evaluating {n_packets} test samples with Isolation Forest..."})

    if not os.path.isfile(TEST_CSV):
        _broadcast({"type": "log", "approach": "approach2",
                    "message": f"[ERROR] NSL-KDD test set not found: {TEST_CSV}"})
        return

    df_test = pd.read_csv(TEST_CSV, low_memory=False)
    df_normal = df_test[df_test["label"] == 0]
    df_attack = df_test[df_test["label"] == 1]

    n_attacks = int(n_packets * attack_ratio)
    n_normals = n_packets - n_attacks

    sampled_attack = df_attack.sample(n=min(n_attacks, len(df_attack)), replace=True)
    sampled_normal = df_normal.sample(n=min(n_normals, len(df_normal)), replace=True)
    df_sample = pd.concat([sampled_attack, sampled_normal]).sample(frac=1.0).reset_index(drop=True)

    X_sample = transform_features(df_sample, encoders)
    y_true = df_sample["label"].values.astype(int)
    attack_types = df_sample["attack_type"].values if "attack_type" in df_sample.columns else ["attack"] * len(df_sample)
    services = df_sample["service"].values if "service" in df_sample.columns else ["http"] * len(df_sample)
    protocols = df_sample["protocol_type"].values if "protocol_type" in df_sample.columns else ["tcp"] * len(df_sample)

    scores = detector.predict_scores(X_sample)
    preds = detector.predict(X_sample)

    tp = fp = tn = fn = 0

    for i in range(len(df_sample)):
        if stop_ev.is_set():
            break

        gt = int(y_true[i])
        pred = int(preds[i])
        score = float(scores[i])
        atk_type = str(attack_types[i])
        svc = str(services[i])
        proto = str(protocols[i]).upper()

        src_ip = f"192.168.1.{random.randint(10, 199)}"
        dst_ip = f"10.0.0.{random.randint(1, 50)}"

        if pred == 1 and gt == 1:
            tp += 1
        elif pred == 1 and gt == 0:
            fp += 1
        elif pred == 0 and gt == 0:
            tn += 1
        elif pred == 0 and gt == 1:
            fn += 1

        if pred == 1:
            severity = "HIGH" if score < -0.10 else "MEDIUM"
            rule_name = f"Anomaly: {atk_type.capitalize()}" if gt == 1 else "Anomaly: Outlier"
            alert = {
                "timestamp": time.strftime("%H:%M:%S"),
                "severity": severity,
                "rule": rule_name,
                "signature_id": 90000 + (hash(atk_type) % 9999),
                "src_dst": f"{src_ip} -> {dst_ip} ({svc})",
                "protocol": proto,
                "details": f"Anomaly score: {score:.4f}",
                "approach": "approach2",
            }
            state["alerts"].append(alert)
            _broadcast({"type": "alert", "approach": "approach2", "alert": alert})

        if (i + 1) % 25 == 0 or (i + 1) == len(df_sample):
            precision = round((tp / (tp + fp) * 100), 2) if (tp + fp) > 0 else 0.0
            recall = round((tp / (tp + fn) * 100), 2) if (tp + fn) > 0 else 0.0
            accuracy = round(((tp + tn) / (i + 1) * 100), 2)
            f1 = round((2 * (precision/100) * (recall/100) / ((precision/100) + (recall/100))), 4) if (precision + recall) > 0 else 0.0
            fpr = round((fp / (fp + tn) * 100), 2) if (fp + tn) > 0 else 0.0

            m = {
                "total_packets": i + 1,
                "total_alerts": tp + fp,
                "true_positives": tp,
                "false_positives": fp,
                "true_negatives": tn,
                "false_negatives": fn,
                "accuracy": accuracy,
                "precision": precision,
                "recall_detection_rate": recall,
                "f1_score": f1,
                "false_positive_rate": fpr,
            }
            state["metrics"] = m
            _broadcast({"type": "metrics", "approach": "approach2", "metrics": m,
                        "progress": i + 1, "total": len(df_sample)})

        time.sleep(0.015)

    _broadcast({"type": "log", "approach": "approach2",
                "message": f"[ML Simulator] Done — {len(df_sample)} samples evaluated."})


def _run_approach2_csv(state, detector, encoders, stop_ev, opts):
    """Run Approach 2 CSV evaluation."""
    import pandas as pd
    from feature_extractor import transform_features, TEST_CSV

    csv_path = opts.get("input") or TEST_CSV
    max_rows = int(opts.get("max_rows", 0))

    if not os.path.isfile(csv_path):
        _broadcast({"type": "log", "approach": "approach2",
                    "message": f"[ERROR] CSV not found: {csv_path}"})
        return

    _broadcast({"type": "log", "approach": "approach2",
                "message": f"[ML CSV] Loading: {os.path.basename(csv_path)}"})

    df = pd.read_csv(csv_path, low_memory=False)
    if max_rows and len(df) > max_rows:
        df = df.iloc[:max_rows]

    X = transform_features(df, encoders)
    y_true = df["label"].values.astype(int) if "label" in df.columns else [0] * len(df)
    attack_types = df["attack_type"].values if "attack_type" in df.columns else ["unknown"] * len(df)
    services = df["service"].values if "service" in df.columns else ["http"] * len(df)
    protocols = df["protocol_type"].values if "protocol_type" in df.columns else ["tcp"] * len(df)

    scores = detector.predict_scores(X)
    preds = detector.predict(X)

    tp = fp = tn = fn = 0
    total = len(df)

    for i in range(total):
        if stop_ev.is_set():
            break

        gt = int(y_true[i])
        pred = int(preds[i])
        score = float(scores[i])
        atk_type = str(attack_types[i])
        svc = str(services[i])
        proto = str(protocols[i]).upper()

        if pred == 1 and gt == 1:
            tp += 1
        elif pred == 1 and gt == 0:
            fp += 1
        elif pred == 0 and gt == 0:
            tn += 1
        elif pred == 0 and gt == 1:
            fn += 1

        if pred == 1:
            severity = "HIGH" if score < -0.10 else "MEDIUM"
            rule_name = f"Anomaly: {atk_type.capitalize()}" if gt == 1 else "Anomaly: Outlier"
            alert = {
                "timestamp": time.strftime("%H:%M:%S"),
                "severity": severity,
                "rule": rule_name,
                "signature_id": 90000 + (hash(atk_type) % 9999),
                "src_dst": f"NSL-KDD Row {i+1} ({svc})",
                "protocol": proto,
                "details": f"Anomaly score: {score:.4f}",
                "approach": "approach2",
            }
            state["alerts"].append(alert)
            _broadcast({"type": "alert", "approach": "approach2", "alert": alert})

        if (i + 1) % 25 == 0 or (i + 1) == total:
            precision = round((tp / (tp + fp) * 100), 2) if (tp + fp) > 0 else 0.0
            recall = round((tp / (tp + fn) * 100), 2) if (tp + fn) > 0 else 0.0
            accuracy = round(((tp + tn) / (i + 1) * 100), 2)
            f1 = round((2 * (precision/100) * (recall/100) / ((precision/100) + (recall/100))), 4) if (precision + recall) > 0 else 0.0
            fpr = round((fp / (fp + tn) * 100), 2) if (fp + tn) > 0 else 0.0

            m = {
                "total_packets": i + 1,
                "total_alerts": tp + fp,
                "true_positives": tp,
                "false_positives": fp,
                "true_negatives": tn,
                "false_negatives": fn,
                "accuracy": accuracy,
                "precision": precision,
                "recall_detection_rate": recall,
                "f1_score": f1,
                "false_positive_rate": fpr,
            }
            state["metrics"] = m
            _broadcast({"type": "metrics", "approach": "approach2", "metrics": m,
                        "progress": i + 1, "total": total})

        time.sleep(0.005)

    _broadcast({"type": "log", "approach": "approach2",
                "message": f"[ML CSV] Done — {total} rows evaluated."})


# ── REST API ──────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/status")
def api_status():
    return jsonify({k: {"status": v["status"], "alert_count": len(v["alerts"]),
                        "mode": v["mode"]} for k, v in _state.items()})


@app.route("/api/metrics")
def api_metrics():
    # Try to reload from saved file if empty
    for ap_key in ("approach1", "approach2"):
        if not _state[ap_key]["metrics"]:
            path = os.path.join(RESULTS_DIR, f"{ap_key}_metrics.json")
            if os.path.isfile(path):
                with open(path) as f:
                    _state[ap_key]["metrics"] = json.load(f)
    return jsonify({k: v["metrics"] for k, v in _state.items()})


@app.route("/api/alerts")
def api_alerts():
    ap    = request.args.get("approach", "approach1")
    limit = int(request.args.get("limit", 100))
    return jsonify(_state.get(ap, {}).get("alerts", [])[-limit:])


@app.route("/api/<approach>/start", methods=["POST"])
def api_start(approach):
    if approach not in _state:
        return jsonify({"error": "Unknown approach"}), 400
    if _state[approach]["status"] == "running":
        return jsonify({"error": "Already running"}), 409

    data = request.get_json(force=True, silent=True) or {}
    mode = data.get("mode", "simulator")

    _state[approach]["status"]  = "running"
    _state[approach]["alerts"]  = []
    _state[approach]["metrics"] = {}
    _state[approach]["mode"]    = mode

    if approach == "approach1":
        t = threading.Thread(target=_run_approach1_thread, args=(mode, data), daemon=True)
        t.start()
        return jsonify({"status": "started"})
    else:
        t = threading.Thread(target=_run_approach2_thread, args=(mode, data), daemon=True)
        t.start()
        return jsonify({"status": "started"})


@app.route("/api/<approach>/stop", methods=["POST"])
def api_stop(approach):
    if approach not in _state:
        return jsonify({"error": "Unknown approach"}), 400
    _stop_events[approach].set()
    _state[approach]["status"] = "stopped"
    _broadcast({"type": "status", "approach": approach, "status": "stopped"})
    return jsonify({"status": "stopped"})


@app.route("/api/stream/alerts")
def stream_alerts():
    """SSE endpoint — each subscriber gets its own queue."""
    q = queue.Queue(maxsize=300)
    with _subscribers_lock:
        _subscribers.append(q)

    def generate():
        # Send initial connected event
        yield f"data: {json.dumps({'type': 'connected'})}\n\n"
        try:
            while True:
                try:
                    msg = q.get(timeout=20)
                    yield f"data: {msg}\n\n"
                except queue.Empty:
                    yield f"data: {json.dumps({'type': 'ping'})}\n\n"
        except GeneratorExit:
            with _subscribers_lock:
                if q in _subscribers:
                    _subscribers.remove(q)

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache",
                             "X-Accel-Buffering": "no",
                             "Connection": "keep-alive"})


# ── Entrypoint ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()
    print(f"\n  ✦ NIDS Dashboard →  http://{args.host}:{args.port}\n")
    app.run(host=args.host, port=args.port, debug=False, threaded=True)
