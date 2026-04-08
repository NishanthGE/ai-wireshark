import asyncio
import signal
import sys
import os
from collections import deque

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import DEFAULT_INTERFACE, ANTHROPIC_API_KEY, ENABLE_AI, DASHBOARD_REFRESH
from core.capture import capture_live, capture_from_pcap, get_interfaces, check_tshark
from core.classifier import ThreatClassifier
from utils.db import init_db, save_threat, save_packet
from alerts.notifier import notify
from alerts.ai_analyzer import AIAnalyzer
from dashboard.cli_dashboard import Dashboard

try:
    from rich.live import Live
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

classifier     = ThreatClassifier()
ai_analyzer    = AIAnalyzer()
packet_history = deque(maxlen=100)
shutdown_event = asyncio.Event()


def _handle_shutdown(signum, frame):
    shutdown_event.set()
    # Cancel all running async tasks so the loop exits immediately
    for task in asyncio.all_tasks():
        task.cancel()


async def main():
    import argparse
    parser = argparse.ArgumentParser(description="AI Wireshark — Real-time Threat Detection")
    parser.add_argument("--interface",       default=DEFAULT_INTERFACE,  help="Network interface to capture on")
    parser.add_argument("--pcap",            default=None,               help="Read from .pcap file instead of live capture")
    parser.add_argument("--no-ai",           action="store_true",        help="Disable AI analysis (rule-based only)")
    parser.add_argument("--no-dashboard",    action="store_true",        help="Plain text output instead of live dashboard")
    parser.add_argument("--export",          choices=["csv", "json"],    help="Export stored threats on exit")
    parser.add_argument("--list-interfaces", action="store_true",        help="List available network interfaces")
    args = parser.parse_args()

    if args.list_interfaces:
        ifaces = get_interfaces()
        if ifaces:
            for i in ifaces:
                print(f"  {i['index']}. {i['name']}")
        else:
            print("[!] No interfaces found (is tshark installed?)")
        return

    if not check_tshark():
        print("[!] tshark not found — install Wireshark/tshark and ensure it is on PATH")
        sys.exit(1)

    init_db()
    signal.signal(signal.SIGINT,  _handle_shutdown)
    signal.signal(signal.SIGTERM, _handle_shutdown)

    use_ai        = ENABLE_AI and not args.no_ai
    use_dashboard = RICH_AVAILABLE and not args.no_dashboard

    dashboard = Dashboard()
    dashboard.print_startup(args.interface, use_ai)

    source = capture_from_pcap(args.pcap) if args.pcap else capture_live(args.interface)

    if use_dashboard:
        await _run_with_dashboard(source, dashboard, use_ai)
    else:
        await _run_plain(source, dashboard, use_ai)

    # ── Export on exit ────────────────────────────────────────────────────────
    if args.export:
        from utils.exporter import export
        export(args.export)

    total   = dashboard.stats["total_packets"]
    threats = dashboard.stats["threats_found"]
    print(f"\n[✓] Done — {total:,} packets, {threats} threats detected")


async def _run_with_dashboard(source, dashboard: Dashboard, use_ai: bool):
    """Capture loop with rich Live dashboard."""
    try:
        with Live(dashboard.build(), refresh_per_second=int(1 / DASHBOARD_REFRESH), screen=False) as live:
            async for packet in source:
                if shutdown_event.is_set():
                    break

                packet_history.append(packet)
                dashboard.add_packet(packet)
                save_packet(packet)

                threat = classifier.classify(packet)
                if threat:
                    if use_ai:
                        threat = await ai_analyzer.analyze(threat, list(packet_history))

                    packet["_flagged"] = True
                    dashboard.add_threat(threat)
                    save_threat(threat)
                    notify(threat, skip_terminal=True)

                live.update(dashboard.build())
    except asyncio.CancelledError:
        pass


async def _run_plain(source, dashboard: Dashboard, use_ai: bool):
    """Capture loop with plain terminal output (no rich dashboard)."""
    total = 0

    try:
        async for packet in source:
            if shutdown_event.is_set():
                break

            total += 1
            packet_history.append(packet)
            dashboard.add_packet(packet)
            save_packet(packet)

            src   = packet.get("src_ip",   "?")
            dst   = packet.get("dst_ip",   "?")
            proto = packet.get("protocol", "?")
            dport = packet.get("dst_port", "?")
            length= packet.get("length",   0)

            print(f"  [{total:04d}] {src:15} -> {dst:15}:{str(dport):<6} [{proto}] {length}b")

            threat = classifier.classify(packet)
            if threat:
                if use_ai:
                    threat = await ai_analyzer.analyze(threat, list(packet_history))

                dashboard.add_threat(threat)
                save_threat(threat)
                notify(threat, skip_terminal=False)
    except asyncio.CancelledError:
        pass


if __name__ == "__main__":
    asyncio.run(main())
