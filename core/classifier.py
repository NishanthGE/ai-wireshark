"""
core/classifier.py
Rule-based threat classifier — works WITHOUT any API key.
Detects known attack patterns from packet metadata.
"""

import time
from collections import defaultdict
from typing import Optional
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from config import (
    SYN_FLOOD_THRESHOLD, PORT_SCAN_THRESHOLD,
    DNS_QUERY_SIZE_THRESHOLD, BRUTE_FORCE_THRESHOLD,
    RISK_LOW, RISK_MEDIUM, RISK_HIGH, RISK_CRITICAL
)

# Suspicious ports — cleartext protocols
CLEARTEXT_PORTS = {21: "FTP", 23: "Telnet", 80: "HTTP", 110: "POP3", 143: "IMAP"}
SENSITIVE_PORTS = {22: "SSH", 3389: "RDP", 5900: "VNC", 3306: "MySQL", 5432: "PostgreSQL"}
COMMON_MALWARE_PORTS = {4444, 1337, 31337, 12345, 54321, 6666, 6667}

# Private IP ranges (RFC 1918)
PRIVATE_RANGES = [
    ("10.0.0.0",     "10.255.255.255"),
    ("172.16.0.0",   "172.31.255.255"),
    ("192.168.0.0",  "192.168.255.255"),
]


class ThreatClassifier:
    """
    Stateful classifier — tracks packet history per IP
    to detect patterns across multiple packets.
    """

    def __init__(self):
        # State tracking per source IP
        self._syn_tracker      = defaultdict(list)   # IP -> [timestamps]
        self._port_tracker     = defaultdict(set)    # IP -> {ports_hit}
        self._port_time        = defaultdict(float)  # IP -> window_start
        self._dns_tracker      = defaultdict(list)   # IP -> [query_sizes]
        self._arp_tracker      = defaultdict(set)    # IP -> {mac_addresses}
        self._brute_tracker    = defaultdict(list)   # IP -> [timestamps]
        self._beacon_tracker   = defaultdict(list)   # IP:port -> [timestamps]
        # Deduplication: track last alert time per (ip, threat_type)
        self._last_alert: dict[tuple, float] = {}
        self._COOLDOWN = 10.0                        # seconds before re-alerting same threat

    def classify(self, packet: dict) -> Optional[dict]:
        """
        Classify a single packet.
        Returns a threat dict if a threat is detected, else None.

        Threat dict shape:
        {
            "type":        str,   # e.g. "SYN Flood"
            "severity":    str,   # LOW / MEDIUM / HIGH / CRITICAL
            "risk_score":  int,   # 0-100
            "src_ip":      str,
            "dst_ip":      str,
            "dst_port":    int,
            "description": str,   # human-readable
            "packet":      dict,  # original packet
        }
        """
        threats = []

        src = packet.get("src_ip")
        dst = packet.get("dst_ip")
        dst_port = packet.get("dst_port")
        src_port = packet.get("src_port")
        now = time.time()

        if not src or not dst:
            return None  # non-IP packet

        # ── 1. SYN Flood Detection ─────────────────────────────────────────────
        if packet.get("syn") and not packet.get("ack"):
            self._syn_tracker[src].append(now)
            # Keep only last 1 second
            self._syn_tracker[src] = [t for t in self._syn_tracker[src] if now - t < 1]
            rate = len(self._syn_tracker[src])
            if rate >= SYN_FLOOD_THRESHOLD:
                threats.append({
                    "type": "SYN Flood",
                    "severity": "CRITICAL",
                    "risk_score": min(95, 70 + rate),
                    "description": f"{src} sent {rate} SYN packets/sec to {dst} — possible DDoS attack."
                })

        # ── 2. Port Scan Detection ─────────────────────────────────────────────
        if dst_port and packet.get("syn") and not packet.get("ack"):
            window_start = self._port_time.get(src, now)
            if now - window_start > 5:
                self._port_tracker[src].clear()
                self._port_time[src] = now

            self._port_tracker[src].add(dst_port)
            unique_ports = len(self._port_tracker[src])

            if unique_ports >= PORT_SCAN_THRESHOLD:
                threats.append({
                    "type": "Port Scan",
                    "severity": "HIGH",
                    "risk_score": min(85, 50 + unique_ports * 2),
                    "description": f"{src} has probed {unique_ports} unique ports on {dst} in 5 seconds — likely Nmap or similar scanner."
                })

        # ── 3. Cleartext Protocol Alert ────────────────────────────────────────
        if dst_port in CLEARTEXT_PORTS:
            proto_name = CLEARTEXT_PORTS[dst_port]
            threats.append({
                "type": f"Cleartext {proto_name}",
                "severity": "MEDIUM",
                "risk_score": 55,
                "description": f"Unencrypted {proto_name} traffic from {src} to {dst}:{dst_port}. Credentials may be exposed."
            })

        # ── 4. Malware Port Communication ──────────────────────────────────────
        if dst_port in COMMON_MALWARE_PORTS:
            threats.append({
                "type": "Suspicious Port",
                "severity": "HIGH",
                "risk_score": 80,
                "description": f"{src} → {dst}:{dst_port} — port {dst_port} is commonly used by malware/backdoors (Metasploit, netcat shells, botnets)."
            })

        # ── 5. DNS Query Size (DNS Tunneling) ──────────────────────────────────
        dns_query = packet.get("dns_query")
        if dns_query and len(dns_query) > DNS_QUERY_SIZE_THRESHOLD:
            self._dns_tracker[src].append(len(dns_query))
            if len(self._dns_tracker[src]) >= 3:
                threats.append({
                    "type": "DNS Tunneling",
                    "severity": "HIGH",
                    "risk_score": 78,
                    "description": f"{src} is sending unusually large DNS queries ({len(dns_query)} chars). Possible DNS tunneling for C2 or data exfiltration."
                })

        # ── 6. ARP Spoofing ────────────────────────────────────────────────────
        if packet.get("arp_opcode") == "2":  # ARP reply
            arp_ip = src
            arp_mac = packet.get("eth_src") or "unknown"
            if arp_ip in self._arp_tracker and arp_mac not in self._arp_tracker[arp_ip]:
                threats.append({
                    "type": "ARP Spoofing",
                    "severity": "CRITICAL",
                    "risk_score": 92,
                    "description": f"Multiple MAC addresses responding for IP {arp_ip} — ARP spoofing detected. Possible MITM attack in progress."
                })
            self._arp_tracker[arp_ip].add(arp_mac)

        # ── 7. Brute Force (SSH/RDP/VNC) ───────────────────────────────────────
        if dst_port in SENSITIVE_PORTS:
            service = SENSITIVE_PORTS[dst_port]
            key = f"{src}->{dst}:{dst_port}"
            self._brute_tracker[key].append(now)
            self._brute_tracker[key] = [t for t in self._brute_tracker[key] if now - t < 30]
            count = len(self._brute_tracker[key])
            if count >= BRUTE_FORCE_THRESHOLD:
                threats.append({
                    "type": f"{service} Brute Force",
                    "severity": "HIGH",
                    "risk_score": min(90, 60 + count),
                    "description": f"{src} has made {count} connections to {dst}:{dst_port} ({service}) in 30 seconds — possible credential brute force attack."
                })

        # ── 8. Beacon Detection (C2 check-ins) ────────────────────────────────
        if dst_port and dst and not _is_private(dst):
            key = f"{src}->{dst}:{dst_port}"
            self._beacon_tracker[key].append(now)
            intervals = self._beacon_tracker[key]
            if len(intervals) >= 5:
                # Check if intervals are suspiciously regular
                gaps = [intervals[i+1] - intervals[i] for i in range(len(intervals)-1)]
                avg_gap = sum(gaps) / len(gaps)
                variance = sum((g - avg_gap)**2 for g in gaps) / len(gaps)
                if 10 < avg_gap < 300 and variance < 5:
                    threats.append({
                        "type": "C2 Beaconing",
                        "severity": "CRITICAL",
                        "risk_score": 88,
                        "description": f"{src} is making regular connections to external IP {dst}:{dst_port} every ~{avg_gap:.0f}s — possible C2 beacon from malware."
                    })
                # Keep only last 10 timestamps
                self._beacon_tracker[key] = intervals[-10:]

        if not threats:
            return None

        # Return the highest severity threat found
        severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        top = max(threats, key=lambda t: severity_order.get(t["severity"], 0))

        # Deduplicate — suppress re-alerts for the same (src, type, dst) within cooldown
        dedup_key = (src, top["type"], dst)
        if now - self._last_alert.get(dedup_key, 0.0) < self._COOLDOWN:
            return None
        self._last_alert[dedup_key] = now

        return {
            **top,
            "src_ip":   src,
            "dst_ip":   dst,
            "dst_port": dst_port,
            "packet":   packet,
        }


def _ip_to_int(ip: str) -> int:
    """Convert dotted IP string to integer."""
    try:
        parts = [int(x) for x in ip.split(".")]
        return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]
    except Exception:
        return 0


def _is_private(ip: str) -> bool:
    """Check if an IP is in a private RFC 1918 range."""
    try:
        ip_int = _ip_to_int(ip)
        for start, end in PRIVATE_RANGES:
            if _ip_to_int(start) <= ip_int <= _ip_to_int(end):
                return True
        return False
    except Exception:
        return False
