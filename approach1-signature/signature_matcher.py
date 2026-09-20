"""
signature_matcher.py — Core Matching Engine for Signature-Based NIDS
----------------------------------------------------------------------
Takes a parsed packet dict and checks it against all SIGNATURES rules.
Also handles rate-based (flood) detection using a sliding time window.

Returns a list of Alert dicts for every rule that matched.
"""

import time
from collections import defaultdict
from signatures import SIGNATURES


# ── Rate-limit state tracker (sliding window per source IP per rule) ──────────
# Structure: { (src_ip, rule_name): [timestamp1, timestamp2, ...] }
_rate_tracker: dict[tuple, list] = defaultdict(list)


class Alert:
    """Represents a single triggered intrusion alert."""

    SEVERITY_COLORS = {
        "HIGH":   "\033[91m",   # Red
        "MEDIUM": "\033[93m",   # Yellow
        "LOW":    "\033[94m",   # Blue
        "__RESET__": "\033[0m",
    }

    def __init__(self, rule: dict, packet: dict, match_type: str = "signature"):
        self.timestamp   = time.strftime("%Y-%m-%d %H:%M:%S")
        self.rule_name   = rule["name"]
        self.severity    = rule.get("severity", "LOW")
        self.description = rule.get("description", "")
        self.src_ip      = packet.get("src_ip", "?")
        self.dst_ip      = packet.get("dst_ip", "?")
        self.protocol    = packet.get("protocol", "?")
        self.src_port    = packet.get("src_port")
        self.dst_port    = packet.get("dst_port")
        self.flags       = packet.get("flags", "")
        self.match_type  = match_type   # "signature" | "rate"
        self.packet_summary = packet.get("raw_summary", "")

    def to_dict(self) -> dict:
        return {
            "timestamp":    self.timestamp,
            "rule":         self.rule_name,
            "severity":     self.severity,
            "src_ip":       self.src_ip,
            "dst_ip":       self.dst_ip,
            "protocol":     self.protocol,
            "src_port":     self.src_port,
            "dst_port":     self.dst_port,
            "match_type":   self.match_type,
            "description":  self.description,
        }

    def __str__(self) -> str:
        color  = self.SEVERITY_COLORS.get(self.severity, "")
        reset  = self.SEVERITY_COLORS["__RESET__"]
        port_s = f":{self.src_port}" if self.src_port else ""
        port_d = f":{self.dst_port}" if self.dst_port else ""

        return (
            f"{color}[{self.severity}] {self.timestamp} | "
            f"{self.rule_name} | "
            f"{self.src_ip}{port_s} → {self.dst_ip}{port_d} | "
            f"{self.protocol} {self.flags} | "
            f"{self.description}{reset}"
        )


# ── Main Matching Function ────────────────────────────────────────────────────

def match_packet(packet: dict) -> list[Alert]:
    """
    Match a single parsed packet against all signature rules.

    Args:
        packet: Normalized dict from packet_parser.parse_packet() or parse_csv_row()

    Returns:
        List of Alert objects (empty list = no match = normal traffic)
    """
    alerts = []

    for rule in SIGNATURES:
        if _matches_rule(packet, rule):
            match_type = "rate" if "rate_limit" in rule and _is_rate_exceeded(packet, rule) else "signature"

            # For rate-limited rules: only alert on rate breach, not every packet
            if "rate_limit" in rule:
                if _is_rate_exceeded(packet, rule):
                    alerts.append(Alert(rule, packet, match_type="rate"))
            else:
                alerts.append(Alert(rule, packet, match_type="signature"))

            # Track packet in rate window regardless
            _track_rate(packet, rule)

    return alerts


# ── Private Helpers ───────────────────────────────────────────────────────────

def _matches_rule(packet: dict, rule: dict) -> bool:
    """Check if a packet satisfies the static (non-rate) conditions of a rule."""

    # ── Protocol check ─────────────────────────────────────────────────
    rule_proto = rule.get("protocol", "ANY")
    if rule_proto != "ANY" and packet.get("protocol") != rule_proto:
        return False

    # ── Single destination port ─────────────────────────────────────────
    if "dst_port" in rule:
        if packet.get("dst_port") != rule["dst_port"]:
            return False

    # ── Multiple destination ports ──────────────────────────────────────
    if "dst_ports" in rule:
        if packet.get("dst_port") not in rule["dst_ports"]:
            return False

    # ── Source port ─────────────────────────────────────────────────────
    if "src_port" in rule:
        if packet.get("src_port") != rule["src_port"]:
            return False

    # ── TCP Flags ───────────────────────────────────────────────────────
    if "flags" in rule:
        pkt_flags = set(packet.get("flags", ""))
        rule_flags = set(rule["flags"])
        if pkt_flags != rule_flags:
            return False

    # ── Payload keyword inspection ──────────────────────────────────────
    if "payload_keywords" in rule:
        payload = packet.get("payload", "").upper()
        matched_keyword = any(kw.upper() in payload for kw in rule["payload_keywords"])
        if not matched_keyword:
            return False

    return True


def _track_rate(packet: dict, rule: dict):
    """Record a packet timestamp in the sliding window for a given (src_ip, rule)."""
    if "rate_limit" not in rule:
        return

    key  = (packet.get("src_ip", "?"), rule["name"])
    now  = time.time()
    window = rule["rate_limit"]["window_sec"]

    _rate_tracker[key].append(now)
    # Prune old timestamps outside the window
    _rate_tracker[key] = [t for t in _rate_tracker[key] if now - t <= window]


def _is_rate_exceeded(packet: dict, rule: dict) -> bool:
    """Return True if the packet count for (src_ip, rule) exceeds threshold in window."""
    if "rate_limit" not in rule:
        return False

    key       = (packet.get("src_ip", "?"), rule["name"])
    now       = time.time()
    window    = rule["rate_limit"]["window_sec"]
    threshold = rule["rate_limit"]["threshold"]

    recent = [t for t in _rate_tracker.get(key, []) if now - t <= window]
    return len(recent) >= threshold


def get_rate_stats() -> dict:
    """Return current rate tracking stats — useful for dashboard/reporting."""
    now = time.time()
    stats = {}
    for (src_ip, rule_name), timestamps in _rate_tracker.items():
        recent = [t for t in timestamps if now - t <= 60]  # last 60s
        if recent:
            stats[f"{src_ip} → {rule_name}"] = len(recent)
    return stats
