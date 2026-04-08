# AI Wireshark — Real-time Network Threat Detection

An AI-powered network traffic analyzer that captures live packets, detects threats in real-time, and uses LLM analysis (Groq / Anthropic / Gemini) to explain attacks — with a browser-based SOC dashboard.

## Features

- Live packet capture via tshark
- Real-time **Rich terminal dashboard** (split-pane: packets + threat feed)
- **Web SOC dashboard** at `http://localhost:8080` (FastAPI + SSE)
- Rule-based threat detection (no API key needed)
- AI-powered threat analysis via Groq / Anthropic / Gemini (HIGH/CRITICAL only)
- GeoIP lookup — country, city, ISP, flag per threat
- VirusTotal IP reputation check
- Auto-block CRITICAL threats via iptables
- SQLite + MongoDB storage support
- Slack & email alerting
- CSV / JSON export (terminal flag or browser download button)

## Threats Detected

| Threat | Severity | Risk Score |
|---|---|---|
| SYN Flood | CRITICAL | 90–95 |
| Port Scan | HIGH | 60–85 |
| C2 Beaconing | CRITICAL | 88 |
| ARP Spoofing | CRITICAL | 92 |
| DNS Tunneling | HIGH | 78 |
| Brute Force (SSH/RDP/VNC) | HIGH | 60–90 |
| Suspicious Port (4444, 1337…) | HIGH | 80 |
| Cleartext Protocols (HTTP/FTP/Telnet) | MEDIUM | 55 |

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

## Tech Stack

- Python 3, tshark, asyncio
- Rich (terminal dashboard)
- FastAPI + uvicorn (web API + dashboard)
- Groq / Anthropic / Gemini (AI analysis)
- ip-api.com (GeoIP, free, no key)
- VirusTotal API v3 (IP reputation)
- SQLite / MongoDB (storage)

## Roadmap

- Phase 1 — Live capture + rule-based threat detection ✅
- Phase 2 — Rich dashboard + AI analysis + MongoDB + Slack alerts ✅
- Phase 3 — Web SOC dashboard + GeoIP + VirusTotal + auto-block ✅

## Author

NishanthGE — https://github.com/NishanthGE
