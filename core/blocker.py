"""
core/blocker.py
Auto-block attacking IPs via iptables on CRITICAL threats.
Only runs on Linux with root privileges.
Enable via AUTO_BLOCK_CRITICAL = True in config.py.
"""

import ipaddress
import subprocess
import sys
import os
from datetime import datetime
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from config import AUTO_BLOCK_CRITICAL


def _valid_ip(ip: str) -> bool:
    """Validate that ip is a proper IPv4/IPv6 address (no CIDR, no flags)."""
    try:
        ipaddress.ip_address(ip)
        return True
    except (ValueError, TypeError):
        return False

_blocked_ips: set[str] = set()


def block_ip(ip: str, reason: str = "") -> bool:
    """
    Add an iptables DROP rule for the given IP.
    Returns True if blocked, False if already blocked or failed.
    """
    if not AUTO_BLOCK_CRITICAL:
        return False

    if not ip or not _valid_ip(ip) or ip in _blocked_ips:
        return False

    # Skip private/loopback IPs
    private = ("10.", "192.168.", "127.", "172.")
    if any(ip.startswith(p) for p in private):
        return False

    try:
        subprocess.run(
            ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
            check=True, capture_output=True
        )
        _blocked_ips.add(ip)
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"\n  [BLOCKED] {ip} at {ts} — {reason}")
        _log_block(ip, reason)
        return True
    except subprocess.CalledProcessError as e:
        print(f"[!] iptables block failed for {ip}: {e.stderr.decode().strip()}")
        return False
    except FileNotFoundError:
        print("[!] iptables not found — auto-block disabled")
        return False


def unblock_ip(ip: str) -> bool:
    """Remove the iptables DROP rule for the given IP."""
    if not _valid_ip(ip) or ip not in _blocked_ips:
        return False
    try:
        subprocess.run(
            ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
            check=True, capture_output=True
        )
        _blocked_ips.discard(ip)
        return True
    except Exception:
        return False


def get_blocked() -> list[str]:
    """Return list of currently blocked IPs."""
    return list(_blocked_ips)


def _log_block(ip: str, reason: str):
    """Append block event to a local log file."""
    try:
        os.makedirs("data", exist_ok=True)
        with open("data/blocked_ips.log", "a") as f:
            f.write(f"{datetime.now().isoformat()} | BLOCKED | {ip} | {reason}\n")
    except Exception:
        pass
