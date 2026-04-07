"""
utils/db.py
SQLite storage for packets and threats.
"""

import sqlite3
import json
import os
from datetime import datetime
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from config import DB_PATH, LOG_ALL_PACKETS, LOG_THREATS_ONLY


def init_db():
    """Create database tables if they don't exist."""
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS threats (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp    TEXT NOT NULL,
            threat_type  TEXT,
            severity     TEXT,
            risk_score   INTEGER,
            src_ip       TEXT,
            dst_ip       TEXT,
            dst_port     INTEGER,
            description  TEXT,
            ai_analyzed  INTEGER DEFAULT 0,
            ai_confirmed INTEGER DEFAULT 1,
            ai_explanation TEXT,
            ai_remediation TEXT,
            raw_packet   TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS packets (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            src_ip    TEXT,
            dst_ip    TEXT,
            protocol  TEXT,
            src_port  INTEGER,
            dst_port  INTEGER,
            length    INTEGER,
            flagged   INTEGER DEFAULT 0
        )
    """)

    conn.commit()
    conn.close()


def save_threat(threat: dict):
    """Store a detected threat in the database."""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO threats
            (timestamp, threat_type, severity, risk_score,
             src_ip, dst_ip, dst_port, description,
             ai_analyzed, ai_confirmed, ai_explanation,
             ai_remediation, raw_packet)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        datetime.now().isoformat(),
        threat.get("ai_threat_name") or threat.get("type"),
        threat.get("ai_severity")    or threat.get("severity"),
        threat.get("ai_risk_score")  or threat.get("risk_score"),
        threat.get("src_ip"),
        threat.get("dst_ip"),
        threat.get("dst_port"),
        threat.get("ai_explanation") or threat.get("description"),
        1 if threat.get("ai_analyzed") else 0,
        1 if threat.get("ai_confirmed", True) else 0,
        threat.get("ai_explanation", ""),
        json.dumps(threat.get("ai_remediation", [])),
        json.dumps(threat.get("packet", {})),
    ))
    conn.commit()
    conn.close()


def save_packet(packet: dict, flagged: bool = False):
    """Optionally store raw packet metadata."""
    if LOG_THREATS_ONLY and not flagged:
        return
    if not LOG_ALL_PACKETS and not flagged:
        return

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO packets
            (timestamp, src_ip, dst_ip, protocol, src_port, dst_port, length, flagged)
        VALUES (?,?,?,?,?,?,?,?)
    """, (
        datetime.now().isoformat(),
        packet.get("src_ip"),
        packet.get("dst_ip"),
        packet.get("protocol"),
        packet.get("src_port"),
        packet.get("dst_port"),
        packet.get("length"),
        1 if flagged else 0,
    ))
    conn.commit()
    conn.close()


def get_recent_threats(limit: int = 50) -> list:
    """Retrieve most recent threats from DB."""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        SELECT * FROM threats
        ORDER BY id DESC LIMIT ?
    """, (limit,))
    rows = cur.fetchall()
    conn.close()
    return rows
