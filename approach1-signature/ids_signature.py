"""
ids_signature.py — Main Entry Point: Signature-Based Network IDS
-----------------------------------------------------------------
Supports three modes:
  1. LIVE mode    — Sniff real network traffic using Scapy (requires root)
  2. PCAP mode    — Read from a .pcap file offline (requires Scapy)
  3. CSV mode     — Replay UNSW-NB15 / CIC-IDS-2017 dataset (no root needed)

Usage:
  python ids_signature.py --mode csv   --file ../datasets/UNSW_NB15_training-set.csv
  python ids_signature.py --mode pcap  --file capture.pcap
  python ids_signature.py --mode live  --iface eth0

Requirements (install once):
  sudo pacman -S python-scapy        (Arch Linux)
  -- OR --
  pip install scapy psutil           (other distros)
"""

import argparse
import csv
import os
import sys
import time
import psutil

# ── Path setup so sibling imports work ───────────────────────────────────────
sys.path.insert(0, os.path.dirname(__file__))

from packet_parser    import parse_packet, parse_csv_row, SCAPY_AVAILABLE
from signature_matcher import match_packet
from alert_logger      import AlertLogger


# ─────────────────────────────────────────────────────────────────────────────
# MODE 1: LIVE SNIFFING
# ─────────────────────────────────────────────────────────────────────────────

def run_live(interface: str, logger: AlertLogger, packet_limit: int = 0):
    """
    Sniff live packets on the given network interface.
    Requires root privileges and Scapy to be installed.
    """
    if not SCAPY_AVAILABLE:
        print("[ERROR] Scapy is not installed. Cannot run live mode.")
        print("        Install it with: sudo pacman -S python-scapy")
        sys.exit(1)

    from scapy.all import sniff

    print(f"[*] Starting LIVE capture on interface: {interface}")
    print(f"[*] Packet limit: {'unlimited' if packet_limit == 0 else packet_limit}")
    print(f"[*] Press Ctrl+C to stop.\n")

    _start_time = time.time()
    _pkt_counter = [0]

    def handle_packet(pkt):
        _pkt_counter[0] += 1
        parsed = parse_packet(pkt)
        if parsed is None:
            return
        alerts = match_packet(parsed)
        if alerts:
            logger.log(alerts)
        else:
            logger.log_normal()

    try:
        sniff(
            iface=interface,
            prn=handle_packet,
            count=packet_limit,
            store=False,
        )
    except KeyboardInterrupt:
        pass
    except PermissionError:
        print("[ERROR] Permission denied. Run with sudo for live packet capture.")
        sys.exit(1)

    elapsed = time.time() - _start_time
    pps = _pkt_counter[0] / elapsed if elapsed > 0 else 0
    print(f"\n[*] Capture stopped. {_pkt_counter[0]} packets in {elapsed:.1f}s ({pps:.1f} pkt/s)")


# ─────────────────────────────────────────────────────────────────────────────
# MODE 2: PCAP FILE
# ─────────────────────────────────────────────────────────────────────────────

def run_pcap(pcap_file: str, logger: AlertLogger):
    """Read and analyse packets from a .pcap file."""
    if not SCAPY_AVAILABLE:
        print("[ERROR] Scapy is not installed. Cannot read PCAP files.")
        print("        Install it with: sudo pacman -S python-scapy")
        sys.exit(1)

    from scapy.all import rdpcap

    print(f"[*] Loading PCAP: {pcap_file}")
    try:
        packets = rdpcap(pcap_file)
    except FileNotFoundError:
        print(f"[ERROR] File not found: {pcap_file}")
        sys.exit(1)

    print(f"[*] {len(packets)} packets loaded. Analysing...\n")

    start_time = time.time()
    for pkt in packets:
        parsed = parse_packet(pkt)
        if parsed is None:
            continue
        alerts = match_packet(parsed)
        if alerts:
            logger.log(alerts)
        else:
            logger.log_normal()

    elapsed = time.time() - start_time
    print(f"\n[*] Done. Processed {len(packets)} packets in {elapsed:.2f}s")


# ─────────────────────────────────────────────────────────────────────────────
# MODE 3: CSV DATASET (Offline — no Scapy needed)
# ─────────────────────────────────────────────────────────────────────────────

def run_csv(csv_file: str, logger: AlertLogger, max_rows: int = 0):
    """
    Replay a UNSW-NB15 / CIC-IDS-2017 CSV dataset row by row.
    Uses ground-truth labels for metrics computation (TP/FP/TN/FN).
    """
    if not os.path.isfile(csv_file):
        print(f"[ERROR] CSV file not found: {csv_file}")
        print("        Download UNSW-NB15 from:")
        print("        https://research.unsw.edu.au/projects/unsw-nb15-dataset")
        sys.exit(1)

    print(f"[*] Loading dataset: {csv_file}")

    start_time = time.time()
    row_count  = 0
    skipped    = 0

    with open(csv_file, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)

        # Auto-detect column name variations between UNSW-NB15 and CIC-IDS-2017
        first_row = None

        for row in reader:
            if max_rows > 0 and row_count >= max_rows:
                break

            row_count += 1

            # Parse the CSV row into our standard packet dict
            try:
                parsed = parse_csv_row(row)
            except Exception as e:
                skipped += 1
                continue

            if parsed is None:
                skipped += 1
                continue

            ground_truth = parsed.get("ground_truth_label", None)
            alerts = match_packet(parsed)

            if alerts:
                logger.log(alerts, ground_truth=ground_truth)
            else:
                logger.log_normal(ground_truth=ground_truth)

            # Progress indicator every 10,000 rows
            if row_count % 10_000 == 0:
                elapsed = time.time() - start_time
                rps = row_count / elapsed
                print(f"  [Progress] {row_count:,} rows | {rps:.0f} rows/s | "
                      f"Alerts so far: {len(logger._alerts)}")

    elapsed = time.time() - start_time
    rps = row_count / elapsed if elapsed > 0 else 0
    print(f"\n[*] Done. Processed {row_count:,} rows in {elapsed:.2f}s ({rps:.0f} rows/s)")
    if skipped:
        print(f"[!] Skipped {skipped} malformed rows.")


# ─────────────────────────────────────────────────────────────────────────────
# RESOURCE MONITOR
# ─────────────────────────────────────────────────────────────────────────────

def print_resource_usage():
    """Print CPU and memory usage of this process (for Approach comparison)."""
    proc = psutil.Process(os.getpid())
    cpu  = psutil.cpu_percent(interval=0.5)
    mem  = proc.memory_info().rss / (1024 * 1024)  # MB
    print(f"[Resource] CPU: {cpu:.1f}% | RAM: {mem:.1f} MB")


# ─────────────────────────────────────────────────────────────────────────────
# CLI ENTRYPOINT
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Signature-Based Network Intrusion Detection System (Approach 1)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyse UNSW-NB15 CSV dataset (recommended for testing):
  python ids_signature.py --mode csv --file ../datasets/UNSW_NB15_training-set.csv

  # Analyse only the first 50,000 rows:
  python ids_signature.py --mode csv --file ../datasets/UNSW_NB15_training-set.csv --max-rows 50000

  # Read from a PCAP capture file:
  python ids_signature.py --mode pcap --file capture.pcap

  # Live sniffing (needs root):
  sudo python ids_signature.py --mode live --iface eth0
        """,
    )

    parser.add_argument("--mode",     choices=["live", "pcap", "csv"], default="csv",
                        help="Operation mode (default: csv)")
    parser.add_argument("--file",     default="../datasets/UNSW_NB15_training-set.csv",
                        help="Input file path (.csv or .pcap)")
    parser.add_argument("--iface",    default="eth0",
                        help="Network interface for live mode")
    parser.add_argument("--max-rows", type=int, default=0,
                        help="Limit rows to process in CSV mode (0 = all)")
    parser.add_argument("--quiet",    action="store_true",
                        help="Suppress per-alert console output")

    args = parser.parse_args()

    with AlertLogger(verbose=not args.quiet) as logger:
        start_wall = time.time()

        if args.mode == "live":
            run_live(args.iface, logger)
        elif args.mode == "pcap":
            run_pcap(args.file, logger)
        elif args.mode == "csv":
            run_csv(args.file, logger, max_rows=args.max_rows)

        wall_time = time.time() - start_wall
        print(f"\n[*] Total wall-clock time: {wall_time:.2f}s")

        print_resource_usage()

        logger.print_summary()
        logger.save_metrics()


if __name__ == "__main__":
    main()
