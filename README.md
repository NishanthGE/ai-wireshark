# AI Wireshark - Real-time Network Threat Detection

An AI-powered network traffic analyzer that captures live packets, detects threats in real-time, and uses LLM analysis (Groq / Anthropic / Gemini) to explain and remediate attacks.

## Features
- Live packet capture via tshark
- Real-time Rich terminal dashboard (split-pane: packets + threat feed)
- Rule-based threat detection (no API key needed)
- AI-powered threat analysis via Groq / Anthropic / Gemini
- SQLite + MongoDB storage support
- Slack & email alerting
- CSV / JSON export for compliance reporting

## Threats Detected
| Threat | Severity | Risk Score |
|---|---|---|
| SYN Flood | CRITICAL | 90-95 |
| Port Scan | HIGH | 60-85 |
| C2 Beaconing | CRITICAL | 88 |
| ARP Spoofing | CRITICAL | 92 |
| DNS Tunneling | HIGH | 78 |
| Brute Force (SSH/RDP/VNC) | HIGH | 60-90 |
| Suspicious Port (4444, 1337...) | HIGH | 80 |
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

# Add your API key to config.py
nano config.py  # set GROQ_API_KEY
```

## Usage

```bash
# Live dashboard (default)
sudo venv/bin/python3 main.py

# Plain text mode
sudo venv/bin/python3 main.py --no-dashboard

# Read from pcap file
venv/bin/python3 main.py --pcap capture.pcap

# Disable AI (rule-based only)
sudo venv/bin/python3 main.py --no-ai

# Export threats on exit
sudo venv/bin/python3 main.py --export csv

# List interfaces
venv/bin/python3 main.py --list-interfaces
```

## Configuration
Edit `config.py` to set:
- `GROQ_API_KEY` — get free key at console.groq.com
- `DEFAULT_INTERFACE` — network interface (eth0, wlan0)
- `DB_TYPE` — `"sqlite"` or `"mongodb"`
- `ALERT_SLACK` / `ALERT_EMAIL` — enable alerting
- `ENABLE_AI` — toggle AI analysis

## Tech Stack
- Python 3, tshark, asyncio
- Rich (terminal dashboard)
- Groq / Anthropic / Gemini (AI analysis)
- SQLite / MongoDB (storage)
- Requests (Slack/email alerts)

## Roadmap
- Phase 1 — Live capture + rule-based threat detection ✅
- Phase 2 — Rich dashboard + AI analysis + MongoDB + Slack alerts ✅
- Phase 3 — FastAPI + React web dashboard + Docker + VirusTotal + GeoIP

## Author
NishanthGE — https://github.com/NishanthGE
