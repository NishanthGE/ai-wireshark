"""
utils/geoip.py
GeoIP lookup via ip-api.com (free, no key needed, 45 req/min).
Results are cached per IP to avoid hitting rate limits.
"""

import requests
from functools import lru_cache

PRIVATE_PREFIXES = ("10.", "192.168.", "127.", "172.16.", "172.17.",
                    "172.18.", "172.19.", "172.20.", "172.21.", "172.22.",
                    "172.23.", "172.24.", "172.25.", "172.26.", "172.27.",
                    "172.28.", "172.29.", "172.30.", "172.31.", "::1", "0.")

UNKNOWN = {"country": "Private", "country_code": "--", "city": "", "isp": "", "flag": "🏠"}


def _is_private(ip: str) -> bool:
    return any(ip.startswith(p) for p in PRIVATE_PREFIXES)


@lru_cache(maxsize=512)
def lookup(ip: str) -> dict:
    """Return geo info for an IP. Cached per IP."""
    if not ip or _is_private(ip):
        return UNKNOWN

    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,country,countryCode,city,isp,org"},
            timeout=3,
        )
        if r.status_code == 200:
            data = r.json()
            if data.get("status") == "success":
                code = data.get("countryCode", "??")
                return {
                    "country":      data.get("country", "Unknown"),
                    "country_code": code,
                    "city":         data.get("city", ""),
                    "isp":          data.get("isp", ""),
                    "flag":         _flag(code),
                }
    except Exception:
        pass

    return {"country": "Unknown", "country_code": "??", "city": "", "isp": "", "flag": "🌐"}


def _flag(country_code: str) -> str:
    """Convert country code to flag emoji."""
    try:
        return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in country_code.upper())
    except Exception:
        return "🌐"
