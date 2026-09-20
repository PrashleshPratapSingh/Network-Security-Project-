"""
signatures.py — Signature Rule Definitions for Signature-Based NIDS
----------------------------------------------------------------------
Each rule is a dictionary that defines the conditions to match a
specific known attack pattern against a parsed packet.

Rule fields:
  - name          : Human-readable attack name
  - protocol      : "TCP" | "UDP" | "ICMP" | "ANY"
  - dst_port      : Exact destination port to match (optional)
  - dst_ports     : List of destination ports (optional)
  - src_port      : Exact source port (optional)
  - flags         : TCP flags string e.g. "S" for SYN (optional)
  - payload_keywords : List of strings to search in payload (optional)
  - severity      : "HIGH" | "MEDIUM" | "LOW"
  - description   : Brief explanation
  - rate_limit    : Dict with 'threshold' & 'window_sec' for flood detection
"""

SIGNATURES = [

    # ─── PORT SCAN DETECTION ──────────────────────────────────────────────────
    {
        "name": "TCP SYN Port Scan",
        "protocol": "TCP",
        "flags": "S",           # Only SYN, no ACK
        "severity": "HIGH",
        "description": "Rapid SYN packets to multiple ports — classic Nmap/port scan.",
        "rate_limit": {"threshold": 20, "window_sec": 5},  # >20 SYN in 5s = alert
    },
    {
        "name": "NULL Scan",
        "protocol": "TCP",
        "flags": "",            # No flags set
        "severity": "HIGH",
        "description": "TCP packet with no flags — used to evade firewalls.",
    },
    {
        "name": "FIN Scan",
        "protocol": "TCP",
        "flags": "F",
        "severity": "MEDIUM",
        "description": "TCP FIN scan used to probe open ports stealthily.",
    },
    {
        "name": "XMAS Scan",
        "protocol": "TCP",
        "flags": "FPU",         # FIN + PSH + URG
        "severity": "HIGH",
        "description": "XMAS scan — all flags lit up to fingerprint systems.",
    },

    # ─── FLOOD ATTACKS ────────────────────────────────────────────────────────
    {
        "name": "ICMP Flood (Ping Flood)",
        "protocol": "ICMP",
        "severity": "HIGH",
        "description": "Excessive ICMP echo requests — potential DoS attack.",
        "rate_limit": {"threshold": 50, "window_sec": 5},
    },
    {
        "name": "UDP Flood",
        "protocol": "UDP",
        "severity": "MEDIUM",
        "description": "High-rate UDP packets to random ports — UDP flood DoS.",
        "rate_limit": {"threshold": 100, "window_sec": 5},
    },
    {
        "name": "TCP SYN Flood",
        "protocol": "TCP",
        "flags": "S",
        "severity": "HIGH",
        "description": "SYN flood — exhausts server connection table (DoS).",
        "rate_limit": {"threshold": 50, "window_sec": 3},
    },

    # ─── DANGEROUS PORTS / SERVICES ───────────────────────────────────────────
    {
        "name": "Telnet Access Attempt",
        "protocol": "TCP",
        "dst_port": 23,
        "severity": "HIGH",
        "description": "Telnet is unencrypted — any connection attempt is suspicious.",
    },
    {
        "name": "FTP Connection Attempt",
        "protocol": "TCP",
        "dst_port": 21,
        "severity": "MEDIUM",
        "description": "Plain FTP is unencrypted — potential credential exposure.",
    },
    {
        "name": "SMB Port Access",
        "protocol": "TCP",
        "dst_ports": [445, 139],
        "severity": "HIGH",
        "description": "SMB access — associated with ransomware and lateral movement.",
    },
    {
        "name": "RDP Access Attempt",
        "protocol": "TCP",
        "dst_port": 3389,
        "severity": "HIGH",
        "description": "RDP connection — frequent target for brute force and exploits.",
    },
    {
        "name": "SMTP Open Relay Attempt",
        "protocol": "TCP",
        "dst_port": 25,
        "severity": "MEDIUM",
        "description": "SMTP connection — may indicate spam relay or phishing.",
    },

    # ─── BRUTE FORCE ──────────────────────────────────────────────────────────
    {
        "name": "SSH Brute Force",
        "protocol": "TCP",
        "dst_port": 22,
        "severity": "HIGH",
        "description": "Rapid SSH connection attempts — credential brute force.",
        "rate_limit": {"threshold": 10, "window_sec": 10},
    },
    {
        "name": "FTP Brute Force",
        "protocol": "TCP",
        "dst_port": 21,
        "severity": "HIGH",
        "description": "Rapid FTP connections — brute force login attempt.",
        "rate_limit": {"threshold": 10, "window_sec": 10},
    },

    # ─── APPLICATION LAYER (PAYLOAD INSPECTION) ───────────────────────────────
    {
        "name": "SQL Injection Attempt",
        "protocol": "TCP",
        "payload_keywords": [
            "SELECT ", "UNION SELECT", "DROP TABLE", "INSERT INTO",
            "1=1", "' OR '", "'; --", "xp_cmdshell",
        ],
        "severity": "HIGH",
        "description": "SQL keywords in TCP payload — possible SQL injection attack.",
    },
    {
        "name": "Cross-Site Scripting (XSS)",
        "protocol": "TCP",
        "payload_keywords": [
            "<script>", "</script>", "javascript:", "onerror=",
            "onload=", "alert(", "document.cookie",
        ],
        "severity": "HIGH",
        "description": "XSS payloads detected in HTTP traffic.",
    },
    {
        "name": "Directory Traversal",
        "protocol": "TCP",
        "payload_keywords": [
            "../", "..\\", "/etc/passwd", "/etc/shadow",
            "..%2F", "%2e%2e%2f",
        ],
        "severity": "HIGH",
        "description": "Path traversal characters in payload — LFI/RFI attempt.",
    },
    {
        "name": "Command Injection",
        "protocol": "TCP",
        "payload_keywords": [
            "; rm -rf", "| cat /etc/passwd", "&& wget", "`whoami`",
            "$(id)", "; /bin/sh", "| nc ",
        ],
        "severity": "HIGH",
        "description": "Shell commands in payload — OS command injection attempt.",
    },
    {
        "name": "HTTP Suspicious User-Agent",
        "protocol": "TCP",
        "payload_keywords": [
            "sqlmap", "nikto", "nmap", "masscan",
            "zgrab", "python-requests/2", "curl/",
        ],
        "severity": "MEDIUM",
        "description": "Known scanner/exploit tool user-agent strings.",
    },

    # ─── DNS ATTACKS ──────────────────────────────────────────────────────────
    {
        "name": "DNS Amplification",
        "protocol": "UDP",
        "dst_port": 53,
        "severity": "MEDIUM",
        "description": "Large DNS queries — potential DNS amplification DDoS.",
    },
    {
        "name": "DNS Zone Transfer Attempt",
        "protocol": "TCP",
        "dst_port": 53,
        "payload_keywords": ["AXFR"],
        "severity": "HIGH",
        "description": "DNS zone transfer (AXFR) — exposes entire DNS zone data.",
    },

    # ─── NETWORK RECONNAISSANCE ───────────────────────────────────────────────
    {
        "name": "SNMP Sweep",
        "protocol": "UDP",
        "dst_port": 161,
        "severity": "MEDIUM",
        "description": "SNMP probing — used to gather network device information.",
    },
    {
        "name": "NetBIOS Enumeration",
        "protocol": "UDP",
        "dst_ports": [137, 138],
        "severity": "MEDIUM",
        "description": "NetBIOS name queries — network reconnaissance activity.",
    },
]
