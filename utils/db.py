"""
utils/db.py
Storage backend — supports SQLite (default) and MongoDB.
Switch via DB_TYPE in config.py.
"""

import sqlite3
import json
import os
from datetime import datetime
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from config import DB_PATH, LOG_ALL_PACKETS, LOG_THREATS_ONLY, DB_TYPE, MONGODB_URI, MONGODB_DB

# ── MongoDB lazy connection ───────────────────────────────────────────────────

_mongo_db = None

def _get_mongo():
    global _mongo_db
    if _mongo_db is None:
        from pymongo import MongoClient
        client = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=3000)
        _mongo_db = client[MONGODB_DB]
    return _mongo_db


# ── Public API ────────────────────────────────────────────────────────────────

def init_db():
    """Initialize the storage backend."""
    if DB_TYPE == "mongodb":
        try:
            db = _get_mongo()
            db.threats.create_index("timestamp")
            db.threats.create_index("severity")
            db.packets.create_index("timestamp")
            print("[+] MongoDB connected")
        except Exception as e:
            print(f"[!] MongoDB connection failed: {e} — falling back to SQLite")
            _init_sqlite()
    else:
        _init_sqlite()


def save_threat(threat: dict):
    if DB_TYPE == "mongodb":
        try:
            _save_threat_mongo(threat)
            return
        except Exception as e:
            print(f"[!] MongoDB save failed: {e}")
    _save_threat_sqlite(threat)


def save_packet(packet: dict, flagged: bool = False):
    if LOG_THREATS_ONLY and not flagged:
        return
    if not LOG_ALL_PACKETS and not flagged:
        return

    if DB_TYPE == "mongodb":
        try:
            _save_packet_mongo(packet, flagged)
            return
        except Exception as e:
            print(f"[!] MongoDB save failed: {e}")
    _save_packet_sqlite(packet, flagged)


def get_recent_threats(limit: int = 50) -> list:
    if DB_TYPE == "mongodb":
        try:
            return _get_threats_mongo(limit)
        except Exception as e:
            print(f"[!] MongoDB read failed: {e}")
    return _get_threats_sqlite(limit)


# ── SQLite backend ────────────────────────────────────────────────────────────

def _init_sqlite():
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS threats (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp     TEXT NOT NULL,
                threat_type   TEXT,
                severity      TEXT,
                risk_score    INTEGER,
                src_ip        TEXT,
                dst_ip        TEXT,
                dst_port      INTEGER,
                description   TEXT,
                ai_analyzed   INTEGER DEFAULT 0,
                ai_confirmed  INTEGER DEFAULT 1,
                ai_explanation  TEXT,
                ai_remediation  TEXT,
                raw_packet    TEXT
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


def _save_threat_sqlite(threat: dict):
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("""
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
    except sqlite3.Error as e:
        print(f"[!] DB save threat failed: {e}")


def _save_packet_sqlite(packet: dict, flagged: bool):
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("""
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
    except sqlite3.Error as e:
        print(f"[!] DB save packet failed: {e}")


def _get_threats_sqlite(limit: int) -> list:
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cur = conn.execute("SELECT * FROM threats ORDER BY id DESC LIMIT ?", (limit,))
            return cur.fetchall()
    except sqlite3.Error as e:
        print(f"[!] DB read failed: {e}")
        return []


# ── MongoDB backend ───────────────────────────────────────────────────────────

def _save_threat_mongo(threat: dict):
    doc = {
        "timestamp":      datetime.now().isoformat(),
        "threat_type":    threat.get("ai_threat_name") or threat.get("type"),
        "severity":       threat.get("ai_severity")    or threat.get("severity"),
        "risk_score":     threat.get("ai_risk_score")  or threat.get("risk_score"),
        "src_ip":         threat.get("src_ip"),
        "dst_ip":         threat.get("dst_ip"),
        "dst_port":       threat.get("dst_port"),
        "description":    threat.get("ai_explanation") or threat.get("description"),
        "ai_analyzed":    bool(threat.get("ai_analyzed")),
        "ai_confirmed":   bool(threat.get("ai_confirmed", True)),
        "ai_explanation": threat.get("ai_explanation", ""),
        "ai_remediation": threat.get("ai_remediation", []),
        "raw_packet":     threat.get("packet", {}),
    }
    _get_mongo().threats.insert_one(doc)


def _save_packet_mongo(packet: dict, flagged: bool):
    doc = {
        "timestamp": datetime.now().isoformat(),
        "src_ip":    packet.get("src_ip"),
        "dst_ip":    packet.get("dst_ip"),
        "protocol":  packet.get("protocol"),
        "src_port":  packet.get("src_port"),
        "dst_port":  packet.get("dst_port"),
        "length":    packet.get("length"),
        "flagged":   flagged,
    }
    _get_mongo().packets.insert_one(doc)


def _get_threats_mongo(limit: int) -> list:
    """Return threats as list-of-tuples matching the SQLite column order."""
    docs  = list(_get_mongo().threats.find().sort("_id", -1).limit(limit))
    rows  = []
    for i, doc in enumerate(docs):
        rows.append((
            i + 1,
            doc.get("timestamp"),
            doc.get("threat_type"),
            doc.get("severity"),
            doc.get("risk_score"),
            doc.get("src_ip"),
            doc.get("dst_ip"),
            doc.get("dst_port"),
            doc.get("description"),
            1 if doc.get("ai_analyzed") else 0,
            1 if doc.get("ai_confirmed", True) else 0,
            doc.get("ai_explanation", ""),
            json.dumps(doc.get("ai_remediation", [])),
            json.dumps(doc.get("raw_packet", {})),
        ))
    return rows
