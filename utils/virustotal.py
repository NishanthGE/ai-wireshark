"""
utils/virustotal.py
VirusTotal IP reputation check.
Free API key at virustotal.com — 4 req/min on free tier.
Set VIRUSTOTAL_API_KEY in config.py to enable.
"""

import requests
from functools import lru_cache
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from config import VIRUSTOTAL_API_KEY

SKIPPED = {"checked": False, "reason": "no_api_key"}


@lru_cache(maxsize=256)
def check_ip(ip: str) -> dict:
    """Check an IP against VirusTotal. Cached per IP."""
    if not VIRUSTOTAL_API_KEY:
        return SKIPPED

    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        r = requests.get(url, headers=headers, timeout=5)

        if r.status_code == 200:
            attrs  = r.json()["data"]["attributes"]
            stats  = attrs.get("last_analysis_stats", {})
            malicious  = stats.get("malicious",  0)
            suspicious = stats.get("suspicious", 0)
            total      = sum(stats.values()) or 1

            verdict = "clean"
            if malicious > 0:
                verdict = "malicious"
            elif suspicious > 0:
                verdict = "suspicious"

            return {
                "checked":    True,
                "malicious":  malicious,
                "suspicious": suspicious,
                "total":      total,
                "verdict":    verdict,
                "score":      f"{malicious}/{total}",
            }

        if r.status_code == 404:
            return {"checked": True, "verdict": "not_found", "malicious": 0, "suspicious": 0, "total": 0, "score": "0/0"}

    except Exception:
        pass

    return {"checked": False, "reason": "error"}
