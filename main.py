import asyncio
import signal
import sys
import os
from collections import deque

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import DEFAULT_INTERFACE, ANTHROPIC_API_KEY
from core.capture import capture_live, capture_from_pcap, get_interfaces, check_tshark
from core.classifier import ThreatClassifier
from utils.db import init_db, save_threat, save_packet

classifier     = ThreatClassifier()
packet_history = deque(maxlen=100)
shutdown_event = asyncio.Event()

def _handle_shutdown(signum, frame):
    print("\n[*] Shutting down...")
    shutdown_event.set()

async def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--interface", default=DEFAULT_INTERFACE)
    parser.add_argument("--no-ai",    action="store_true")
    parser.add_argument("--pcap",     default=None)
    parser.add_argument("--list-interfaces", action="store_true")
    args = parser.parse_args()

    if args.list_interfaces:
        for i in get_interfaces():
            print(f"  {i['index']}. {i['name']}")
        return

    if not check_tshark():
        print("[!] tshark not installed")
        sys.exit(1)

    init_db()
    signal.signal(signal.SIGINT,  _handle_shutdown)
    signal.signal(signal.SIGTERM, _handle_shutdown)

    print(f"""
╭─────────────────────────────────────────╮
│  ⚡ AI Wireshark                        │
│  Interface : {args.interface:<28}│
│  Press Ctrl+C to stop                   │
╰─────────────────────────────────────────╯""")

    print(f"[*] Capturing on {args.interface}\n")

    total   = 0
    threats = 0

    source = capture_from_pcap(args.pcap) if args.pcap else capture_live(args.interface)

    async for packet in source:
        if shutdown_event.is_set():
            break

        total += 1
        packet_history.append(packet)
        save_packet(packet)

        src   = packet.get("src_ip",  "?")
        dst   = packet.get("dst_ip",  "?")
        proto = packet.get("protocol","?")
        dport = packet.get("dst_port","?")
        length= packet.get("length",  0)

        print(f"  [{total:04d}] {src:15} -> {dst:15}:{str(dport):<6} [{proto}] {length}b")

        threat = classifier.classify(packet)
        if threat:
            threats += 1
            sev   = threat.get("severity", "?")
            name  = threat.get("type",     "?")
            score = threat.get("risk_score", 0)
            desc  = threat.get("description", "")
            print(f"\n  {'='*55}")
            print(f"  🚨 [{sev}] {name}  (risk: {score}/100)")
            print(f"     {threat.get('src_ip')} -> {threat.get('dst_ip')}:{threat.get('dst_port')}")
            print(f"     {desc}")
            print(f"  {'='*55}\n")
            save_threat(threat)

    print(f"\n[✓] Done — {total} packets, {threats} threats")

if __name__ == "__main__":
    asyncio.run(main())
