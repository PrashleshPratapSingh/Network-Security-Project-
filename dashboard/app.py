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

sys.path.insert(0, A1_DIR)

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
        # Approach 2 not built yet
        _state[approach]["status"] = "error"
        return jsonify({"error": "Approach 2 not built yet — coming soon!"}), 501


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
