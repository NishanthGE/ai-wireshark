# AI-Powered Wireshark — Real-Time Packet Analysis with LLM

Capture live network packets, classify threats automatically, and get
AI-generated explanations for every suspicious event — all in your terminal.

## Project Structure

```
ai_wireshark/
├── main.py                  # Entry point — run this
├── config.py                # API keys, thresholds, settings
├── requirements.txt         # All dependencies
├── core/
│   ├── capture.py           # tshark packet capture via subprocess
│   ├── parser.py            # Parse raw tshark JSON → structured packets
│   └── classifier.py        # Rule-based threat classifier (no API needed)
├── alerts/
│   ├── ai_analyzer.py       # Claude/OpenAI API integration
│   └── notifier.py          # Terminal, Slack, email alerts
├── dashboard/
│   └── cli_dashboard.py     # Rich terminal dashboard (live table)
├── utils/
│   ├── db.py                # SQLite storage
│   └── exporter.py          # CSV / JSON export
└── data/
    └── threat_rules.json    # Custom threat detection rules
```

## Setup (5 minutes)

### 1. Install tshark
```bash
# Ubuntu/Debian
sudo apt-get install tshark

# macOS
brew install wireshark

# Allow non-root capture (Linux)
sudo dpkg-reconfigure wireshark-common   # select YES
sudo usermod -aG wireshark $USER
newgrp wireshark
```

### 2. Install Python dependencies
```bash
pip install -r requirements.txt
```

### 3. Add your API key
```bash
# In config.py — add your Anthropic or OpenAI API key
ANTHROPIC_API_KEY = "sk-ant-..."   # get from console.anthropic.com
```

### 4. Run
```bash
# Capture on default interface with AI analysis
sudo python3 main.py

# Specify interface
sudo python3 main.py --interface wlan0

# Run without AI (rule-based only, no API key needed)
sudo python3 main.py --no-ai

# Analyze a saved .pcap file instead of live capture
python3 main.py --pcap /path/to/file.pcap

# Export results to CSV
sudo python3 main.py --export csv
```

## What It Detects

| Threat | Detection Method |
|--------|-----------------|
| Port scanning (Nmap) | High SYN rate to multiple ports |
| SYN flood (DDoS) | SYN packets without ACK from same IP |
| DNS tunneling | Unusually large/frequent DNS queries |
| ARP spoofing | Duplicate ARP replies for same IP |
| Cleartext passwords | HTTP/FTP/Telnet on sensitive ports |
| Suspicious beaconing | Regular outbound intervals to unknown IPs |
| Data exfiltration | Large outbound transfers |
| Brute force | Repeated auth failures (SSH/RDP) |

## AI Analysis Output Example

```
[HIGH] 192.168.1.105 → 10.0.0.1:22
───────────────────────────────────
Threat     : SSH Brute Force
Packets    : 47 in 12 seconds
AI Verdict : This IP is systematically attempting SSH login with
             multiple credential combinations. Pattern matches
             automated brute force tool (Hydra/Medusa).
             Recommendation: Block 192.168.1.105 immediately.
             Run: sudo ufw deny from 192.168.1.105
Risk Score : 92/100
```

## Resume Value

This project demonstrates:
- Real-time packet capture and analysis (tshark + Python)
- LLM API integration for security intelligence (Anthropic/OpenAI)
- Threat detection rule engineering
- CLI dashboard development (Rich)
- SQLite data persistence and CSV/JSON export
- Async Python (asyncio) for concurrent capture + analysis
