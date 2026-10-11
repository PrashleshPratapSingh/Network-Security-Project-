"""
download_nslkdd.py — Download and Prepare the NSL-KDD Dataset
--------------------------------------------------------------
Downloads KDDTrain+ and KDDTest+ from the canonical source,
adds proper column headers, and saves as ready-to-use CSVs.

Usage:
  python datasets/download_nslkdd.py
"""

import os
import sys
import urllib.request
import csv

# ── Column names for NSL-KDD (41 features + label + difficulty) ──────────────
COLUMN_NAMES = [
    "duration", "protocol_type", "service", "flag", "src_bytes",
    "dst_bytes", "land", "wrong_fragment", "urgent", "hot",
    "num_failed_logins", "logged_in", "num_compromised", "root_shell",
    "su_attempted", "num_root", "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
    "attack_type", "difficulty_level",
]

# ── Attack type → category mapping (for per-category analysis) ───────────────
ATTACK_CATEGORY = {
    # Normal
    "normal": "Normal",
    # DoS
    "back": "DoS", "land": "DoS", "neptune": "DoS", "pod": "DoS",
    "smurf": "DoS", "teardrop": "DoS", "apache2": "DoS", "udpstorm": "DoS",
    "processtable": "DoS", "mailbomb": "DoS",
    # Probe
    "satan": "Probe", "ipsweep": "Probe", "nmap": "Probe", "portsweep": "Probe",
    "mscan": "Probe", "saint": "Probe",
    # R2L (Remote to Local)
    "guess_passwd": "R2L", "ftp_write": "R2L", "imap": "R2L", "phf": "R2L",
    "multihop": "R2L", "warezmaster": "R2L", "warezclient": "R2L",
    "spy": "R2L", "xlock": "R2L", "xsnoop": "R2L", "snmpguess": "R2L",
    "snmpgetattack": "R2L", "httptunnel": "R2L", "sendmail": "R2L",
    "named": "R2L", "worm": "R2L",
    # U2R (User to Root)
    "buffer_overflow": "U2R", "loadmodule": "U2R", "rootkit": "U2R",
    "perl": "U2R", "sqlattack": "U2R", "xterm": "U2R", "ps": "U2R",
    "httptunnel": "R2L",
}

# ── Download URLs ─────────────────────────────────────────────────────────────
URLS = {
    "KDDTrain+.txt": "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain%2B.txt",
    "KDDTest+.txt":  "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest%2B.txt",
}

DATASET_DIR = os.path.dirname(os.path.abspath(__file__))


def download_file(url: str, dest: str):
    """Download a file with progress indicator."""
    if os.path.isfile(dest):
        print(f"  [SKIP] Already exists: {os.path.basename(dest)}")
        return

    print(f"  [GET]  {url}")
    try:
        urllib.request.urlretrieve(url, dest)
        size_mb = os.path.getsize(dest) / (1024 * 1024)
        print(f"  [OK]   Saved: {os.path.basename(dest)} ({size_mb:.1f} MB)")
    except Exception as e:
        print(f"  [FAIL] Download failed: {e}")
        sys.exit(1)


def convert_to_csv(txt_path: str, csv_path: str):
    """Convert raw NSL-KDD .txt to CSV with proper headers."""
    if os.path.isfile(csv_path):
        print(f"  [SKIP] Already exists: {os.path.basename(csv_path)}")
        return

    print(f"  [CVT]  Converting {os.path.basename(txt_path)} -> {os.path.basename(csv_path)}")

    row_count = 0
    with open(txt_path, "r", encoding="utf-8") as fin, \
         open(csv_path, "w", newline="", encoding="utf-8") as fout:

        writer = csv.writer(fout)
        writer.writerow(COLUMN_NAMES)

        for line in fin:
            line = line.strip()
            if not line:
                continue
            parts = line.split(",")
            if len(parts) >= 42:
                # Normalise attack label (remove trailing dot if present)
                parts[41] = parts[41].rstrip(".")
                attack = parts[41].lower()
                label = 0 if attack == "normal" else 1
                category = ATTACK_CATEGORY.get(attack, "Unknown")
                diff = parts[42] if len(parts) >= 43 else "0"
                writer.writerow(parts[:41] + [attack, diff, label, category])
                row_count += 1

    # Rewrite header to include label and category
    # Read back to fix header
    with open(csv_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    new_header = ",".join(COLUMN_NAMES + ["label", "attack_category"]) + "\n"
    lines[0] = new_header

    with open(csv_path, "w", encoding="utf-8") as f:
        f.writelines(lines)

    print(f"  [OK]   {row_count:,} records written to {os.path.basename(csv_path)}")


def main():
    print("\n" + "=" * 52)
    print("   NSL-KDD Dataset Downloader & Preparer")
    print("=" * 52 + "\n")

    # Download raw files
    print("[1/2] Downloading raw files...\n")
    for filename, url in URLS.items():
        dest = os.path.join(DATASET_DIR, filename)
        download_file(url, dest)

    # Convert to CSV
    print("\n[2/2] Converting to CSV with headers...\n")
    for txt_name in URLS.keys():
        txt_path = os.path.join(DATASET_DIR, txt_name)
        csv_name = txt_name.replace(".txt", ".csv")
        csv_path = os.path.join(DATASET_DIR, csv_name)
        convert_to_csv(txt_path, csv_path)

    # Print summary
    print("\n[OK] Dataset ready! Files in:", DATASET_DIR)
    for f in sorted(os.listdir(DATASET_DIR)):
        if f.endswith((".csv", ".txt")) and f != "README.md":
            fpath = os.path.join(DATASET_DIR, f)
            size_mb = os.path.getsize(fpath) / (1024 * 1024)
            print(f"    - {f}  ({size_mb:.1f} MB)")
    print()


if __name__ == "__main__":
    main()
