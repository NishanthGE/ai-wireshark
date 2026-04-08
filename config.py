# config.py — All settings for AI Wireshark
# Edit this file OR create a .env file with your keys (recommended)

import os
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# ─── API Keys ────────────────────────────────────────────────────────────────
ANTHROPIC_API_KEY    = os.getenv("ANTHROPIC_API_KEY", "")
OPENAI_API_KEY       = os.getenv("OPENAI_API_KEY",    "")
GEMINI_API_KEY       = os.getenv("GEMINI_API_KEY",    "")
GROQ_API_KEY         = os.getenv("GROQ_API_KEY",      "")
VIRUSTOTAL_API_KEY   = os.getenv("VIRUSTOTAL_API_KEY", "")

# Which AI provider to use: "anthropic" or "openai"
AI_PROVIDER = "groq"
AI_MODEL = "llama-3.3-70b-versatile"  # or "gpt-4o"

# ─── Capture Settings ─────────────────────────────────────────────────────────
DEFAULT_INTERFACE = "eth0"       # change to wlan0 for WiFi, or run --interface
PACKET_BATCH_SIZE = 10           # analyze this many packets per AI call
CAPTURE_FILTER = ""              # optional BPF filter e.g. "port 80 or port 443"
MAX_PACKETS = 0                  # 0 = unlimited, set number to stop after N packets

# ─── Threat Detection Thresholds ──────────────────────────────────────────────
SYN_FLOOD_THRESHOLD = 20         # SYN packets/second from one IP = flood
PORT_SCAN_THRESHOLD = 5         # unique ports hit in 5s = port scan
DNS_QUERY_SIZE_THRESHOLD = 100   # bytes — large DNS = possible tunneling
ARP_SPOOF_WINDOW = 5             # seconds to watch for duplicate ARP replies
BRUTE_FORCE_THRESHOLD = 10       # failed auth attempts in 30s = brute force
EXFIL_THRESHOLD_MB = 50          # MB outbound to single IP = possible exfil

# ─── Alert Settings ───────────────────────────────────────────────────────────
ALERT_TERMINAL = True            # always show in terminal
ALERT_SLACK = False              # set True + add webhook to enable
SLACK_WEBHOOK_URL = ""

ALERT_EMAIL = False              # set True + configure below to enable
EMAIL_SMTP_SERVER = "smtp.gmail.com"
EMAIL_SMTP_PORT = 587
EMAIL_FROM = ""
EMAIL_PASSWORD = ""              # use app password for Gmail
EMAIL_TO = ""

# Only alert on these severities: "LOW", "MEDIUM", "HIGH", "CRITICAL"
MIN_ALERT_SEVERITY = "MEDIUM"

# ─── Storage ──────────────────────────────────────────────────────────────────
DB_TYPE = "sqlite"               # "sqlite" or "mongodb"
DB_PATH = "data/packets.db"      # SQLite database path
MONGODB_URI = "mongodb://localhost:27017"
MONGODB_DB  = "ai_wireshark"
EXPORT_PATH = "data/export"      # CSV/JSON export directory
LOG_ALL_PACKETS = False          # True = store every packet (disk-heavy)
LOG_THREATS_ONLY = True          # True = store only flagged packets

# ─── AI Analysis ──────────────────────────────────────────────────────────────
ENABLE_AI = True                 # False = rule-based only, no API calls

# ─── Dashboard ────────────────────────────────────────────────────────────────
DASHBOARD_REFRESH = 1.0          # seconds between dashboard refresh
MAX_TABLE_ROWS = 20              # max rows shown in live table
SHOW_PACKET_BYTES = False        # show raw hex in dashboard

# ─── Risk Score Thresholds ────────────────────────────────────────────────────
RISK_LOW      = 25
RISK_MEDIUM   = 50
RISK_HIGH     = 75
RISK_CRITICAL = 90

# ─── Phase 3 — Web API ────────────────────────────────────────────────────────
API_HOST = "0.0.0.0"             # listen on all interfaces
API_PORT = 8080                  # open http://localhost:8080 in browser

# ─── Phase 3 — Auto-block ─────────────────────────────────────────────────────
AUTO_BLOCK_CRITICAL = False      # True = auto iptables block on CRITICAL threats
