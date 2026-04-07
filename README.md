# AI Wireshark - Real-time Network Threat Detection

An AI-powered network traffic analyzer that captures live packets and detects threats in real-time.

## Threats Detected
- CRITICAL: SYN Flood DoS Attack (Risk 90-95/100)
- HIGH: Port Scanning (Risk 60-85/100)
- MEDIUM: Cleartext HTTP (Risk 55/100)

## Installation
```bash
pip install -r requirements.txt
sudo python3 main.py
```

## Tech Stack
- Python 3, tshark, SQLite, Rich

## Roadmap
- Phase 1 MVP: Live capture + threat detection ✅
- Phase 2: Rich dashboard + MongoDB + Slack alerts
- Phase 3: FastAPI + React frontend + Docker

## Author
NishanthGE - https://github.com/NishanthGE
