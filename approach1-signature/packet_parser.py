"""
packet_parser.py — Packet Parsing Module for Signature-Based NIDS
------------------------------------------------------------------
Parses raw Scapy packets into a clean, normalized dictionary that
the signature matcher can work with.
"""

try:
    # pyrefly: ignore [missing-import]
    from scapy.all import IP, TCP, UDP, ICMP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def parse_packet(pkt) -> dict | None:
    """
    Parse a Scapy packet into a normalized dict.

    Returns:
        dict with keys: src_ip, dst_ip, protocol, src_port, dst_port,
                        flags, payload, raw_summary
        None if packet is not IP-based (e.g., ARP, Ethernet only)
    """
    if not SCAPY_AVAILABLE:
        return None

    # Must have IP layer
    if not pkt.haslayer(IP):
        return None

    ip_layer = pkt[IP]

    parsed = {
        "src_ip":      ip_layer.src,
        "dst_ip":      ip_layer.dst,
        "protocol":    "UNKNOWN",
        "src_port":    None,
        "dst_port":    None,
        "flags":       "",
        "payload":     "",
        "size":        len(pkt),
        "raw_summary": pkt.summary(),
    }

    # ── TCP ──────────────────────────────────────────────────────────────────
    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        parsed["protocol"] = "TCP"
        parsed["src_port"] = tcp.sport
        parsed["dst_port"] = tcp.dport
        parsed["flags"]    = _decode_tcp_flags(tcp.flags)

        if pkt.haslayer(Raw):
            try:
                parsed["payload"] = pkt[Raw].load.decode("utf-8", errors="ignore")
            except Exception:
                parsed["payload"] = ""

    # ── UDP ──────────────────────────────────────────────────────────────────
    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        parsed["protocol"] = "UDP"
        parsed["src_port"] = udp.sport
        parsed["dst_port"] = udp.dport

        if pkt.haslayer(Raw):
            try:
                parsed["payload"] = pkt[Raw].load.decode("utf-8", errors="ignore")
            except Exception:
                parsed["payload"] = ""

    # ── ICMP ─────────────────────────────────────────────────────────────────
    elif pkt.haslayer(ICMP):
        parsed["protocol"] = "ICMP"

    else:
        return None  # Skip non-TCP/UDP/ICMP

    return parsed


def _decode_tcp_flags(flags_int) -> str:
    """
    Convert Scapy TCP flags integer/object to a string of flag letters.
    e.g.  0x002 → "S"   (SYN)
          0x018 → "PA"  (PSH+ACK)
          0x001 → "F"   (FIN)
          0x029 → "FPU" (FIN+PSH+URG) — XMAS
    """
    flag_map = {
        "F": 0x001,   # FIN
        "S": 0x002,   # SYN
        "R": 0x004,   # RST
        "P": 0x008,   # PSH
        "A": 0x010,   # ACK
        "U": 0x020,   # URG
        "E": 0x040,   # ECE
        "C": 0x080,   # CWR
    }

    try:
        flags_val = int(flags_int)
    except (TypeError, ValueError):
        # Scapy may return a FlagValue object — convert via str then parse
        flags_str = str(flags_int)
        return flags_str

    result = ""
    for letter, bit in flag_map.items():
        if flags_val & bit:
            result += letter
    return result


# ── Offline CSV Row Parser (for UNSW-NB15 / CIC-IDS-2017 datasets) ──────────

def parse_csv_row(row: dict) -> dict | None:
    """
    Parse a row from UNSW-NB15 or CIC-IDS-2017 dataset CSV into the same
    normalized dict format as parse_packet(). Allows offline testing
    without live network traffic.

    Expects columns (UNSW-NB15): srcip, dstip, proto, sport, dsport,
                                  state, sbytes, dbytes, attack_cat, label
    """
    proto_map = {"tcp": "TCP", "udp": "UDP", "icmp": "ICMP"}

    proto_raw = str(row.get("proto", "")).lower()
    protocol  = proto_map.get(proto_raw, "TCP")

    try:
        src_port = int(float(row.get("sport", 0) or 0))
    except (ValueError, TypeError):
        src_port = 0

    try:
        dst_port = int(float(row.get("dsport", 0) or 0))
    except (ValueError, TypeError):
        dst_port = 0

    return {
        "src_ip":      row.get("srcip", "0.0.0.0"),
        "dst_ip":      row.get("dstip", "0.0.0.0"),
        "protocol":    protocol,
        "src_port":    src_port,
        "dst_port":    dst_port,
        "flags":       row.get("state", ""),
        "payload":     "",           # Not available in CSV
        "size":        int(float(row.get("sbytes", 0) or 0)),
        "raw_summary": f"{protocol} {row.get('srcip')}:{src_port} → {row.get('dstip')}:{dst_port}",
        "ground_truth_label": int(row.get("label", 0)),   # 0=normal, 1=attack
        "attack_category":    row.get("attack_cat", ""),
    }
