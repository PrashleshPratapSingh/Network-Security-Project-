"""
traffic_simulator.py — Synthetic Traffic Generator for Testing Approach 1
--------------------------------------------------------------------------
Generates fake parsed-packet dictionaries simulating both normal traffic
and known attack patterns. Allows you to test and demo the IDS without
needing a real network interface, pcap file, or dataset.

Run: python traffic_simulator.py
"""

import sys
import os
import time
import random

sys.path.insert(0, os.path.dirname(__file__))

from signature_matcher import match_packet
from alert_logger      import AlertLogger


# ─────────────────────────────────────────────────────────────────────────────
# Packet Factories
# ─────────────────────────────────────────────────────────────────────────────

def _rand_ip():
    return f"192.168.{random.randint(0,10)}.{random.randint(1,254)}"

def _make_packet(proto="TCP", src_ip=None, dst_ip=None,
                 src_port=None, dst_port=None, flags="", payload=""):
    return {
        "src_ip":      src_ip  or _rand_ip(),
        "dst_ip":      dst_ip  or "10.0.0.1",
        "protocol":    proto,
        "src_port":    src_port or random.randint(1024, 65535),
        "dst_port":    dst_port or 80,
        "flags":       flags,
        "payload":     payload,
        "size":        random.randint(40, 1500),
        "raw_summary": f"{proto} {src_ip}:{src_port} → 10.0.0.1:{dst_port}",
    }


# ── Attack Scenarios ──────────────────────────────────────────────────────────

SCENARIOS = {

    # ─── Normal Traffic ───────────────────────────────────────────────────────
    "normal_http": lambda: _make_packet(
        proto="TCP", dst_port=80, flags="PA",
        payload="GET /index.html HTTP/1.1\r\nHost: example.com\r\n"
    ),
    "normal_https": lambda: _make_packet(
        proto="TCP", dst_port=443, flags="PA"
    ),
    "normal_dns": lambda: _make_packet(
        proto="UDP", dst_port=53
    ),

    # ─── Port Scan ────────────────────────────────────────────────────────────
    "syn_scan": lambda: _make_packet(
        proto="TCP", flags="S",
        src_ip="10.1.1.100",
        dst_port=random.choice([22, 23, 80, 443, 3389, 8080])
    ),
    "xmas_scan": lambda: _make_packet(
        proto="TCP", flags="FPU",
        src_ip="10.1.1.101",
        dst_port=random.randint(1, 1024)
    ),
    "null_scan": lambda: _make_packet(
        proto="TCP", flags="",
        src_ip="10.1.1.102"
    ),
    "fin_scan": lambda: _make_packet(
        proto="TCP", flags="F",
        src_ip="10.1.1.103"
    ),

    # ─── Flood Attacks ────────────────────────────────────────────────────────
    "icmp_flood": lambda: _make_packet(
        proto="ICMP", src_ip="172.16.0.5"
    ),
    "syn_flood": lambda: _make_packet(
        proto="TCP", flags="S", src_ip="172.16.0.6",
        dst_port=80
    ),
    "udp_flood": lambda: _make_packet(
        proto="UDP", src_ip="172.16.0.7",
        dst_port=random.randint(1, 65535)
    ),

    # ─── Dangerous Ports ─────────────────────────────────────────────────────
    "telnet": lambda: _make_packet(proto="TCP", dst_port=23, flags="S"),
    "rdp":    lambda: _make_packet(proto="TCP", dst_port=3389, flags="S"),
    "smb":    lambda: _make_packet(proto="TCP", dst_port=445, flags="S"),

    # ─── Brute Force ─────────────────────────────────────────────────────────
    "ssh_brute": lambda: _make_packet(
        proto="TCP", dst_port=22, flags="S", src_ip="10.5.5.5"
    ),

    # ─── Application Layer ────────────────────────────────────────────────────
    "sql_injection": lambda: _make_packet(
        proto="TCP", dst_port=80, flags="PA",
        payload="GET /login?user=admin' OR '1'='1'; --&pass=x HTTP/1.1\r\n"
    ),
    "xss": lambda: _make_packet(
        proto="TCP", dst_port=80, flags="PA",
        payload="POST /comment HTTP/1.1\r\n\r\n<script>alert(document.cookie)</script>"
    ),
    "dir_traversal": lambda: _make_packet(
        proto="TCP", dst_port=80, flags="PA",
        payload="GET /../../../../etc/passwd HTTP/1.1\r\n"
    ),
    "cmd_injection": lambda: _make_packet(
        proto="TCP", dst_port=80, flags="PA",
        payload="GET /ping?host=localhost;cat /etc/passwd HTTP/1.1\r\n"
    ),
    "scanner_ua": lambda: _make_packet(
        proto="TCP", dst_port=80, flags="PA",
        payload="GET / HTTP/1.1\r\nUser-Agent: sqlmap/1.7\r\n"
    ),
}

# Assign ground-truth label (0=normal, 1=attack)
GROUND_TRUTH = {
    "normal_http": 0, "normal_https": 0, "normal_dns": 0,
    "syn_scan": 1, "xmas_scan": 1, "null_scan": 1, "fin_scan": 1,
    "icmp_flood": 1, "syn_flood": 1, "udp_flood": 1,
    "telnet": 1, "rdp": 1, "smb": 1, "ssh_brute": 1,
    "sql_injection": 1, "xss": 1, "dir_traversal": 1,
    "cmd_injection": 1, "scanner_ua": 1,
}

# Fixed source IPs for flood scenarios (so rate-tracker groups them)
_FLOOD_SOURCES = {
    "icmp_flood": "172.16.0.5",
    "syn_flood":  "172.16.0.6",
    "udp_flood":  "172.16.0.7",
    "ssh_brute":  "10.5.5.5",
    "syn_scan":   "10.1.1.100",
}

def flood_sources_map() -> dict:
    """Return the fixed source IP map for flood scenarios."""
    return _FLOOD_SOURCES


# ─────────────────────────────────────────────────────────────────────────────
# Simulation Runner
# ─────────────────────────────────────────────────────────────────────────────

def run_simulation(n_packets: int = 500, attack_ratio: float = 0.35):
    """
    Generate and process n_packets synthetic packets.

    Args:
        n_packets    : Total number of packets to simulate
        attack_ratio : Fraction of packets that should be attacks (0–1)
    """
    print(f"\n[Simulator] Generating {n_packets} synthetic packets "
          f"({int(attack_ratio*100)}% attacks)...\n")

    attack_scenarios = [k for k, v in GROUND_TRUTH.items() if v == 1]
    normal_scenarios = [k for k, v in GROUND_TRUTH.items() if v == 0]
    flood_sources = _FLOOD_SOURCES

    with AlertLogger(verbose=True) as logger:
        for i in range(n_packets):
            # Pick a scenario
            if random.random() < attack_ratio:
                scenario_name = random.choice(attack_scenarios)
                # For floods: override src_ip so rate-tracker groups them
                pkt = SCENARIOS[scenario_name]()
                if scenario_name in flood_sources:
                    pkt["src_ip"] = flood_sources[scenario_name]
                ground_truth = 1
            else:
                scenario_name = random.choice(normal_scenarios)
                pkt = SCENARIOS[scenario_name]()
                ground_truth = 0

            alerts = match_packet(pkt)
            logger.log(alerts, ground_truth=ground_truth)

            # Small delay to allow rate window to accumulate flood packets
            if scenario_name in ("icmp_flood", "syn_flood", "udp_flood", "ssh_brute"):
                time.sleep(0.01)

        logger.print_summary()
        logger.save_metrics()


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="NIDS Approach 1 — Traffic Simulator")
    parser.add_argument("--packets",       type=int,   default=300,
                        help="Number of packets to simulate (default: 300)")
    parser.add_argument("--attack-ratio",  type=float, default=0.4,
                        help="Fraction of packets that are attacks (default: 0.4)")
    args = parser.parse_args()

    run_simulation(n_packets=args.packets, attack_ratio=args.attack_ratio)
