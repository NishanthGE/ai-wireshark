# AI Wireshark — Real-time Network Threat Detection

![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python&logoColor=white)
![License](https://img.shields.io/github/license/NishanthGE/ai-wireshark)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-557C94?logo=kalilinux&logoColor=white)
![FastAPI](https://img.shields.io/badge/API-FastAPI-009688?logo=fastapi&logoColor=white)

An AI-powered network traffic analyzer that captures live packets, detects threats in real-time, and uses LLM analysis (Groq / Anthropic / Gemini) to explain attacks — with a browser-based SOC dashboard.

---

## Features

**Core Detection**
- Live packet capture via tshark
- Rule-based threat detection (works without API key)
- AI-powered threat analysis via Groq / Anthropic / Gemini (HIGH/CRITICAL only)
- Deduplication with 30s cooldown to prevent alert spam

**Dashboards**
- Real-time **Rich terminal dashboard** (split-pane: packets + threat feed)
- **Web SOC dashboard** at `http://localhost:8080` (FastAPI + SSE)
- Live threat flash animation with badge counter
- Threat detail slide-in panel with AI analysis, GeoIP, and remediation steps
- CSV / JSON download from browser

**Enrichment**
- GeoIP lookup — country, city, ISP, flag emoji per threat
- VirusTotal IP reputation check
- Auto-fallback to destination IP when source is private

**Response**
- Auto-block CRITICAL threats via iptables
- Slack & email alerting
- CSV / JSON export (CLI flag or browser button)

**Storage**
- SQLite (default) + MongoDB support
- Connection-safe with context managers

**Security Hardened**
- XSS protection on all dashboard fields
- IP validation before iptables commands
- CORS restricted to localhost
- AI response field type validation
- No secrets in code — `.env` file support

---

## Threats Detected

| Threat | Severity | Risk Score |
|---|---|---|
| SYN Flood | CRITICAL | 90–95 |
| C2 Beaconing | CRITICAL | 88 |
| ARP Spoofing | CRITICAL | 92 |
| Port Scan | HIGH | 60–85 |
| DNS Tunneling | HIGH | 78 |
| Brute Force (SSH/RDP/VNC) | HIGH | 60–90 |
| Suspicious Port (4444, 1337...) | HIGH | 80 |
| Cleartext Protocols (HTTP/FTP/Telnet) | MEDIUM | 55 |

---

## Installation

```bash
# Install tshark
sudo apt install tshark -y

# Clone repo
git clone https://github.com/NishanthGE/ai-wireshark.git
cd ai-wireshark

# Create venv and install dependencies
python3 -m venv venv
venv/bin/pip install -r requirements.txt

# Set up API keys
cp .env.example .env
nano .env   # add your GROQ_API_KEY (free at console.groq.com)
```

---

## Usage

```bash
# Full mode — terminal dashboard + web dashboard
sudo venv/bin/python3 main.py

# Terminal dashboard only (no web)
sudo venv/bin/python3 main.py --no-web

# Plain text mode (no dashboard)
sudo venv/bin/python3 main.py --no-dashboard

# Disable AI analysis (rule-based only, no API calls)
sudo venv/bin/python3 main.py --no-ai

# Read from a pcap file
venv/bin/python3 main.py --pcap capture.pcap

# Export threats to CSV/JSON on exit
sudo venv/bin/python3 main.py --export csv

# List available network interfaces
venv/bin/python3 main.py --list-interfaces
```

Open `http://localhost:8080` in your browser for the live web dashboard.

---

## Configuration

Copy `.env.example` to `.env` and fill in your keys:

```
GROQ_API_KEY=your-key-here
VIRUSTOTAL_API_KEY=your-key-here   # optional
```

Additional settings in `config.py`:

| Setting | Default | Description |
|---|---|---|
| `DEFAULT_INTERFACE` | `eth0` | Network interface to capture on |
| `DB_TYPE` | `sqlite` | `"sqlite"` or `"mongodb"` |
| `AUTO_BLOCK_CRITICAL` | `False` | Auto-block CRITICAL IPs via iptables |
| `ALERT_SLACK` | `False` | Enable Slack webhook alerts |
| `ALERT_EMAIL` | `False` | Enable email alerts |
| `MIN_ALERT_SEVERITY` | `MEDIUM` | Minimum severity to alert on |
| `AI_PROVIDER` | `groq` | `"groq"`, `"anthropic"`, or `"gemini"` |
| `API_PORT` | `8080` | Web dashboard port |

---

## Project Structure

```
ai-wireshark/
├── main.py                  # Entry point — runs capture + web server
├── config.py                # All settings (loads from .env)
├── .env.example             # API key template
├── requirements.txt         # Python dependencies
├── core/
│   ├── capture.py           # tshark packet capture (live + pcap)
│   ├── classifier.py        # Rule-based threat detection + dedup
│   └── blocker.py           # iptables auto-block for CRITICAL threats
├── alerts/
│   ├── ai_analyzer.py       # Groq / Anthropic / Gemini AI analysis
│   └── notifier.py          # Terminal, Slack, email alerts
├── utils/
│   ├── db.py                # SQLite + MongoDB storage
│   ├── geoip.py             # ip-api.com GeoIP lookup
│   ├── virustotal.py        # VirusTotal IP reputation
│   └── exporter.py          # CSV / JSON file export
├── api/
│   └── server.py            # FastAPI REST API + SSE stream
├── web/
│   └── index.html           # SOC dashboard (dark theme)
└── data/                    # SQLite DB + blocked IP logs
```

---

## Tech Stack

| Component | Technology |
|---|---|
| Packet Capture | tshark (EK JSON format) |
| Terminal Dashboard | Rich (Live, Layout, Table, Panel) |
| Web Dashboard | FastAPI + uvicorn + Server-Sent Events |
| AI Analysis | Groq / Anthropic / Gemini LLMs |
| GeoIP | ip-api.com (free, no key, cached) |
| IP Reputation | VirusTotal API v3 |
| Storage | SQLite / MongoDB |
| Async Runtime | Python asyncio |

---

## Roadmap

- Phase 1 — Live capture + rule-based threat detection ✅
- Phase 2 — Rich dashboard + AI analysis + MongoDB + Slack alerts ✅
- Phase 3 — Web SOC dashboard + GeoIP + VirusTotal + auto-block ✅
- Phase 4 — Docker, pcap replay mode, Suricata rule export (planned)

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## License

MIT License — see [LICENSE](LICENSE) for details.

## Author

**NishanthGE** — [github.com/NishanthGE](https://github.com/NishanthGE)
