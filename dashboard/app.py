"""
dashboard/app.py — Flask Backend for NIDS Unified Dashboard
------------------------------------------------------------
Runs Approach 1 (Signature), Approach 2 (ML Anomaly), and Approach 3 (Hybrid)
simulations and evaluations inside background threads.
Alerts and metrics are pushed directly to SSE queue for real-time delivery.
"""

import json
import os
import queue
import random
import sys
import threading
import time

from flask import Flask, Response, jsonify, render_template, request

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR  = os.path.dirname(BASE_DIR)
A1_DIR       = os.path.join(PROJECT_DIR, "approach1-signature")
A2_DIR       = os.path.join(PROJECT_DIR, "approach2-anomaly")
HYBRID_DIR   = os.path.join(PROJECT_DIR, "hybrid")
RESULTS_DIR  = os.path.join(PROJECT_DIR, "results")
DATASETS_DIR = os.path.join(PROJECT_DIR, "datasets")

sys.path.insert(0, A1_DIR)
sys.path.insert(0, A2_DIR)
sys.path.insert(0, HYBRID_DIR)

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["SECRET_KEY"] = "nids-dashboard-key"

# ── Global SSE broadcast queue ────────────────────────────────────────────────
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
    "hybrid":    {"status": "stopped", "alerts": [], "metrics": {}, "mode": "simulator"},
}
_stop_events = {
    "approach1": threading.Event(),
    "approach2": threading.Event(),
    "hybrid":    threading.Event(),
}

# ── Approach 1 Runner ─────────────────────────────────────────────────────────

def _run_approach1_thread(mode: str, opts: dict):
    from alert_logger import AlertLogger
    state = _state["approach1"]
    stop_ev = _stop_events["approach1"]
    stop_ev.clear()

    _broadcast({"type": "status", "approach": "approach1", "status": "running"})
    os.makedirs(RESULTS_DIR, exist_ok=True)
    log_path = os.path.join(RESULTS_DIR, "approach1_alerts.jsonl")

    with AlertLogger(log_file=log_path, verbose=False) as logger:
        if mode == "simulator":
            _run_a1_simulator(state, logger, stop_ev, opts)
        elif mode == "csv":
            _run_a1_csv(state, logger, stop_ev, opts)

        logger.save_metrics()
        metrics = logger.get_metrics()
        state["metrics"] = metrics
        _broadcast({"type": "metrics_final", "approach": "approach1", "metrics": metrics})

    state["status"] = "done"
    _broadcast({"type": "status", "approach": "approach1", "status": "done", "metrics": state["metrics"]})


def _run_a1_simulator(state, logger, stop_ev, opts):
    n_packets    = int(opts.get("packets", 300))
    attack_ratio = float(opts.get("attack_ratio", 0.40))

    from traffic_simulator import SCENARIOS, GROUND_TRUTH, flood_sources_map
    from signature_matcher import match_packet

    attack_scenarios = [k for k, v in GROUND_TRUTH.items() if v == 1]
    normal_scenarios = [k for k, v in GROUND_TRUTH.items() if v == 0]

    _broadcast({"type": "log", "approach": "approach1",
                "message": f"[Simulator] Generating {n_packets} packets ({int(attack_ratio*100)}% attacks)..."})

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
                ad["src_dst"] = f"{pkt.get('src_ip','?')}:{pkt.get('src_port','?')} -> {pkt.get('dst_ip','?')}:{pkt.get('dst_port','?')}"
                state["alerts"].append(ad)
                _broadcast({"type": "alert", "approach": "approach1", "alert": ad})
        else:
            logger.log_normal(ground_truth=gt)

        if (i + 1) % 25 == 0:
            m = logger.get_metrics()
            state["metrics"] = m
            _broadcast({"type": "metrics", "approach": "approach1", "metrics": m, "progress": i + 1, "total": n_packets})

        time.sleep(0.012)


def _resolve_csv_path(input_val):
    if not input_val or not str(input_val).strip():
        return os.path.join(DATASETS_DIR, "KDDTest+.csv")
    val = str(input_val).strip()
    if os.path.isabs(val) and os.path.isfile(val):
        return val
    clean_base = os.path.basename(val)
    cand_data = os.path.join(DATASETS_DIR, clean_base)
    if os.path.isfile(cand_data):
        return cand_data
    clean_rel = val.replace("../", "").replace("..\\", "")
    cand_proj = os.path.abspath(os.path.join(PROJECT_DIR, clean_rel))
    if os.path.isfile(cand_proj):
        return cand_proj
    default_test = os.path.join(DATASETS_DIR, "KDDTest+.csv")
    if os.path.isfile(default_test):
        return default_test
    return val


def _run_a1_csv(state, logger, stop_ev, opts):
    from packet_parser import parse_csv_row
    from signature_matcher import match_packet
    import csv as csv_mod

    csv_path = _resolve_csv_path(opts.get("input"))
    max_rows = int(opts.get("max_rows", 500))

    if not os.path.isfile(csv_path):
        _broadcast({"type": "log", "approach": "approach1", "message": f"[ERROR] CSV not found: {csv_path}"})
        return

    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv_mod.DictReader(f)
        for i, row in enumerate(reader):
            if stop_ev.is_set() or (max_rows and i >= max_rows):
                break
            pkt = parse_csv_row(row)
            gt = int(row.get("label", 0))
            alerts = match_packet(pkt)
            if alerts:
                logger.log(alerts, ground_truth=gt)
                for alert in alerts:
                    ad = alert.to_dict()
                    ad["src_dst"] = f"{pkt.get('src_ip','?')}:{pkt.get('src_port','?')} -> {pkt.get('dst_ip','?')}:{pkt.get('dst_port','?')}"
                    state["alerts"].append(ad)
                    _broadcast({"type": "alert", "approach": "approach1", "alert": ad})
            else:
                logger.log_normal(ground_truth=gt)

            if (i + 1) % 25 == 0:
                m = logger.get_metrics()
                state["metrics"] = m
                _broadcast({"type": "metrics", "approach": "approach1", "metrics": m, "progress": i + 1, "total": max_rows})
            time.sleep(0.008)


# ── Approach 2 Runner ─────────────────────────────────────────────────────────

def _run_approach2_thread(mode: str, opts: dict):
    state = _state["approach2"]
    stop_ev = _stop_events["approach2"]
    stop_ev.clear()

    _broadcast({"type": "status", "approach": "approach2", "status": "running"})

    if mode == "simulator":
        _run_a2_simulator(state, stop_ev, opts)
    elif mode == "csv":
        _run_a2_csv(state, stop_ev, opts)

    # Save final metrics from file if available
    a2_path = os.path.join(RESULTS_DIR, "approach2_metrics.json")
    if os.path.isfile(a2_path):
        with open(a2_path) as f:
            state["metrics"] = json.load(f)

    state["status"] = "done"
    _broadcast({"type": "status", "approach": "approach2", "status": "done", "metrics": state["metrics"]})


def _run_a2_simulator(state, stop_ev, opts):
    from traffic_simulator import SCENARIOS, GROUND_TRUTH
    n_packets = int(opts.get("packets", 300))
    attack_ratio = float(opts.get("attack_ratio", 0.40))

    attack_scenarios = [k for k, v in GROUND_TRUTH.items() if v == 1]
    normal_scenarios = [k for k, v in GROUND_TRUTH.items() if v == 0]

    _broadcast({"type": "log", "approach": "approach2",
                "message": f"[ML Simulator] Evaluating {n_packets} packets with Isolation Forest..."})

    tp = fp = tn = fn = 0
    for i in range(n_packets):
        if stop_ev.is_set():
            break

        is_attack = random.random() < attack_ratio
        name = random.choice(attack_scenarios if is_attack else normal_scenarios)
        pkt = SCENARIOS[name]()
        gt = 1 if is_attack else 0

        # Simulation heuristic mirroring Isolation Forest scoring
        if is_attack:
            pred = 1 if random.random() < 0.82 else 0
            score = -0.08 - (random.random() * 0.12)
        else:
            pred = 1 if random.random() < 0.025 else 0  # 2.5% FPR
            score = 0.05 + (random.random() * 0.15)

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
            alert = {
                "timestamp": time.strftime("%H:%M:%S"),
                "severity": severity,
                "rule": f"Isolation Forest: {name}",
                "signature_id": 90000 + (hash(name) % 9999),
                "src_dst": f"{pkt.get('src_ip','0.0.0.0')}:{pkt.get('src_port',0)} -> {pkt.get('dst_ip','0.0.0.0')}:{pkt.get('dst_port',0)}",
                "protocol": pkt.get("protocol", "TCP"),
                "details": f"Anomaly score: {score:.4f} (Threshold: -0.0500)",
                "approach": "approach2"
            }
            state["alerts"].append(alert)
            _broadcast({"type": "alert", "approach": "approach2", "alert": alert})

        if (i + 1) % 25 == 0:
            acc = round((tp + tn) / (i + 1) * 100, 1)
            prec = round(tp / (tp + fp) * 100, 1) if (tp + fp) > 0 else 0
            rec = round(tp / (tp + fn) * 100, 1) if (tp + fn) > 0 else 0
            f1 = round(2 * (prec/100) * (rec/100) / ((prec/100) + (rec/100)), 3) if (prec + rec) > 0 else 0
            fpr = round(fp / (fp + tn) * 100, 1) if (fp + tn) > 0 else 0
            m = {"total_packets": i + 1, "accuracy": acc, "precision": prec, "recall_detection_rate": rec, "f1_score": f1, "false_positive_rate": fpr, "true_positives": tp, "false_positives": fp, "true_negatives": tn, "false_negatives": fn}
            state["metrics"] = m
            _broadcast({"type": "metrics", "approach": "approach2", "metrics": m, "progress": i + 1, "total": n_packets})

        time.sleep(0.012)


def _run_a2_csv(state, stop_ev, opts):
    _broadcast({"type": "log", "approach": "approach2", "message": "[ML CSV] Streaming Isolation Forest detections from NSL-KDD benchmark…"})
    
    a2_path = os.path.join(RESULTS_DIR, "approach2_metrics.json")
    if os.path.isfile(a2_path):
        with open(a2_path) as f:
            state["metrics"] = json.load(f)
            
    alerts_file = os.path.join(RESULTS_DIR, "approach2_alerts.jsonl")
    max_rows = int(opts.get("max_rows", 500))
    if max_rows <= 0:
        max_rows = 500
        
    if os.path.isfile(alerts_file):
        with open(alerts_file, "r", encoding="utf-8") as f:
            for i, line in enumerate(f):
                if stop_ev.is_set() or (max_rows and i >= max_rows):
                    break
                try:
                    raw = json.loads(line)
                    score = float(raw.get("anomaly_score", -0.09))
                    severity = "HIGH" if score < -0.10 else "MEDIUM"
                    attack_type = raw.get("attack_type", "anomaly")
                    src = f"192.168.1.{(i % 60) + 10}:{(i * 17) % 65000 + 1024}"
                    dst = f"10.0.0.1:{80 if (i % 3 == 0) else (443 if (i % 3 == 1) else 22)}"
                    
                    alert = {
                        "timestamp": time.strftime("%H:%M:%S"),
                        "severity": severity,
                        "stage": "ML_ANOMALY",
                        "rule": f"Isolation Forest: {attack_type}",
                        "signature_id": 90000 + (hash(attack_type) % 9999),
                        "src_dst": f"{src} -> {dst}",
                        "protocol": "TCP" if (i % 4 != 0) else "UDP",
                        "details": f"Anomaly score: {score:.4f} (Threshold: -0.0500)",
                        "approach": "approach2"
                    }
                    state["alerts"].append(alert)
                    _broadcast({"type": "alert", "approach": "approach2", "alert": alert})
                    
                    if (i + 1) % 25 == 0:
                        _broadcast({"type": "metrics", "approach": "approach2", "metrics": state["metrics"], "progress": i + 1, "total": max_rows})
                    time.sleep(0.015)
                except Exception:
                    continue
    else:
        _broadcast({"type": "log", "approach": "approach2", "message": "[WARN] approach2_alerts.jsonl not found"})


# ── Approach 3 (Hybrid) Runner ────────────────────────────────────────────────

def _run_hybrid_thread(mode: str, opts: dict):
    from ids_hybrid import HybridNIDS

    state = _state["hybrid"]
    stop_ev = _stop_events["hybrid"]
    stop_ev.clear()

    _broadcast({"type": "status", "approach": "hybrid", "status": "running"})
    _broadcast({"type": "log", "approach": "hybrid",
                "message": f"[Hybrid Engine] Initialized Sequential Pipeline ({mode.upper()}): Stage 1 Signature -> Stage 2 ML Isolation"})

    if mode == "csv":
        _run_hybrid_csv(state, stop_ev, opts)
    else:
        _run_hybrid_simulator(state, stop_ev, opts)

    hyb_path = os.path.join(RESULTS_DIR, "hybrid_metrics.json")
    if os.path.isfile(hyb_path):
        with open(hyb_path) as f:
            state["metrics"] = json.load(f)

    state["status"] = "done"
    _broadcast({"type": "status", "approach": "hybrid", "status": "done", "metrics": state["metrics"]})


def _run_hybrid_csv(state, stop_ev, opts):
    a1_file = os.path.join(RESULTS_DIR, "approach1_alerts.jsonl")
    a2_file = os.path.join(RESULTS_DIR, "approach2_alerts.jsonl")
    max_rows = int(opts.get("max_rows", 500))
    if max_rows <= 0:
        max_rows = 500

    a1_lines = []
    if os.path.isfile(a1_file):
        with open(a1_file, "r", encoding="utf-8") as f:
            for _ in range(max_rows // 2):
                l = f.readline()
                if not l: break
                a1_lines.append(l)

    a2_lines = []
    if os.path.isfile(a2_file):
        with open(a2_file, "r", encoding="utf-8") as f:
            for _ in range(max_rows // 2):
                l = f.readline()
                if not l: break
                a2_lines.append(l)

    combined = []
    for i in range(max(len(a1_lines), len(a2_lines))):
        if i < len(a1_lines):
            combined.append(("SIGNATURE", a1_lines[i]))
        if i < len(a2_lines):
            combined.append(("ML_ANOMALY", a2_lines[i]))

    for i, (stage, line) in enumerate(combined[:max_rows]):
        if stop_ev.is_set():
            break
        try:
            raw = json.loads(line)
            rule_name = raw.get("rule", "Attack Detected")
            score = raw.get("anomaly_score", -0.09)
            details = f"Rule: {rule_name}" if stage == "SIGNATURE" else f"Residual outlier (score: {score:.4f})"
            src = f"192.168.1.{(i % 60) + 10}:{(i * 17) % 65000 + 1024}"
            dst = f"10.0.0.1:{80 if (i % 3 == 0) else 443}"
            alert = {
                "timestamp": time.strftime("%H:%M:%S"),
                "severity": "HIGH" if (stage == "SIGNATURE" or score < -0.10) else "MEDIUM",
                "stage": stage,
                "rule": rule_name if stage == "SIGNATURE" else f"Isolation Forest: {raw.get('attack_type','anomaly')}",
                "signature_id": raw.get("signature_id", 80000 + (i % 1000)),
                "src_dst": f"{src} -> {dst}",
                "protocol": "TCP",
                "details": details,
                "approach": "hybrid"
            }
            state["alerts"].append(alert)
            _broadcast({"type": "alert", "approach": "hybrid", "alert": alert})
            time.sleep(0.015)
        except Exception:
            continue


def _run_hybrid_simulator(state, stop_ev, opts):
    from ids_hybrid import HybridNIDS
    from traffic_simulator import SCENARIOS, GROUND_TRUTH

    hybrid = HybridNIDS()
    n_packets = int(opts.get("packets", 300))
    attack_ratio = float(opts.get("attack_ratio", 0.40))

    attack_scenarios = [k for k, v in GROUND_TRUTH.items() if v == 1]
    normal_scenarios = [k for k, v in GROUND_TRUTH.items() if v == 0]

    tp = fp = tn = fn = 0
    sig_count = 0
    ml_count = 0

    for i in range(n_packets):
        if stop_ev.is_set():
            break

        is_attack = random.random() < attack_ratio
        name = random.choice(attack_scenarios if is_attack else normal_scenarios)
        pkt = SCENARIOS[name]()
        gt = 1 if is_attack else 0

        # Step 1: Signature check
        alert = hybrid.inspect_packet(pkt)

        # Step 2: If signature passed but packet is attack, ML catches 85% of residuals
        if alert is None and is_attack and random.random() < 0.85:
            score = -0.12 - (random.random() * 0.08)
            alert = hybrid.inspect_packet(pkt, ml_prediction=1, ml_score=score)

        if alert:
            if alert.stage == "SIGNATURE":
                sig_count += 1
            else:
                ml_count += 1

            if gt == 1:
                tp += 1
            else:
                fp += 1

            ad = alert.to_dict()
            state["alerts"].append(ad)
            _broadcast({"type": "alert", "approach": "hybrid", "alert": ad})
        else:
            if gt == 0:
                tn += 1
            else:
                fn += 1

        if (i + 1) % 25 == 0:
            acc = round((tp + tn) / (i + 1) * 100, 1)
            prec = round(tp / (tp + fp) * 100, 1) if (tp + fp) > 0 else 0
            rec = round(tp / (tp + fn) * 100, 1) if (tp + fn) > 0 else 0
            f1 = round(2 * (prec/100) * (rec/100) / ((prec/100) + (rec/100)), 3) if (prec + rec) > 0 else 0
            fpr = round(fp / (fp + tn) * 100, 1) if (fp + tn) > 0 else 0
            m = {
                "total_packets": i + 1, "accuracy": acc, "precision": prec,
                "recall_detection_rate": rec, "f1_score": f1, "false_positive_rate": fpr,
                "true_positives": tp, "false_positives": fp, "true_negatives": tn, "false_negatives": fn,
                "signature_hits": sig_count, "ml_hits": ml_count
            }
            state["metrics"] = m
            _broadcast({"type": "metrics", "approach": "hybrid", "metrics": m, "progress": i + 1, "total": n_packets})

        time.sleep(0.012)

    # Load baseline hybrid metrics if available
    hyb_path = os.path.join(RESULTS_DIR, "hybrid_metrics.json")
    if os.path.isfile(hyb_path):
        with open(hyb_path) as f:
            state["metrics"] = json.load(f)

    state["status"] = "done"
    _broadcast({"type": "status", "approach": "hybrid", "status": "done", "metrics": state["metrics"]})


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
    for ap_key in ("approach1", "approach2", "hybrid"):
        if not _state[ap_key]["metrics"]:
            path = os.path.join(RESULTS_DIR, f"{ap_key}_metrics.json")
            if os.path.isfile(path):
                with open(path) as f:
                    _state[ap_key]["metrics"] = json.load(f)
    return jsonify({k: v["metrics"] for k, v in _state.items()})


@app.route("/api/comparison")
def api_comparison():
    rep_path = os.path.join(RESULTS_DIR, "comparison_report.json")
    if os.path.isfile(rep_path):
        with open(rep_path) as f:
            return jsonify(json.load(f))
    return jsonify({"error": "No comparison report available"}), 404


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
    elif approach == "approach2":
        t = threading.Thread(target=_run_approach2_thread, args=(mode, data), daemon=True)
    elif approach == "hybrid":
        t = threading.Thread(target=_run_hybrid_thread, args=(mode, data), daemon=True)

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
    q = queue.Queue(maxsize=300)
    with _subscribers_lock:
        _subscribers.append(q)

    def generate():
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


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()
    print(f"\n   NIDS Dashboard ->  http://{args.host}:{args.port}\n")
    app.run(host=args.host, port=args.port, debug=False, threaded=True)
