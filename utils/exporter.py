"""
utils/exporter.py
Export threats to CSV or JSON for reporting.
"""

import csv
import json
import os
from datetime import datetime
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from config import EXPORT_PATH
from utils.db import get_recent_threats


def export(format: str = "csv"):
    """Export all threats to CSV or JSON."""
    os.makedirs(EXPORT_PATH, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    rows = get_recent_threats(limit=10000)

    if format == "csv":
        path = os.path.join(EXPORT_PATH, f"threats_{ts}.csv")
        _export_csv(rows, path)
    else:
        path = os.path.join(EXPORT_PATH, f"threats_{ts}.json")
        _export_json(rows, path)

    print(f"[✓] Exported {len(rows)} threats to {path}")
    return path


def _export_csv(rows, path):
    headers = [
        "id", "timestamp", "threat_type", "severity", "risk_score",
        "src_ip", "dst_ip", "dst_port", "description",
        "ai_analyzed", "ai_confirmed", "ai_explanation", "ai_remediation"
    ]
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        for row in rows:
            writer.writerow(row[:len(headers)])


def _export_json(rows, path):
    headers = [
        "id", "timestamp", "threat_type", "severity", "risk_score",
        "src_ip", "dst_ip", "dst_port", "description",
        "ai_analyzed", "ai_confirmed", "ai_explanation", "ai_remediation", "raw_packet"
    ]
    data = []
    for row in rows:
        d = dict(zip(headers, row))
        try:
            d["ai_remediation"] = json.loads(d.get("ai_remediation") or "[]")
            d["raw_packet"]     = json.loads(d.get("raw_packet") or "{}")
        except Exception:
            pass
        data.append(d)

    with open(path, "w") as f:
        json.dump(data, f, indent=2)
