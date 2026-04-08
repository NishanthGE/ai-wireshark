import asyncio
import signal
import sys
import os
from collections import deque

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import DEFAULT_INTERFACE, ENABLE_AI, DASHBOARD_REFRESH, AUTO_BLOCK_CRITICAL
from core.capture import capture_live, capture_from_pcap, get_interfaces, check_tshark
from core.classifier import ThreatClassifier
from core.blocker import block_ip, get_blocked
from utils.db import init_db, save_threat, save_packet
from utils.geoip import lookup as geo_lookup
from utils.virustotal import check_ip as vt_check
from alerts.notifier import notify
from alerts.ai_analyzer import AIAnalyzer
from dashboard.cli_dashboard import Dashboard
from api.server import start_server, push_threat, push_packet, update_stats, update_blocked

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
    for task in asyncio.all_tasks():
        task.cancel()


async def main():
    import argparse
    parser = argparse.ArgumentParser(description="AI Wireshark — Real-time Threat Detection")
    parser.add_argument("--interface",       default=DEFAULT_INTERFACE)
    parser.add_argument("--pcap",            default=None)
    parser.add_argument("--no-ai",           action="store_true")
    parser.add_argument("--no-dashboard",    action="store_true")
    parser.add_argument("--no-web",          action="store_true",  help="Disable web dashboard")
    parser.add_argument("--export",          choices=["csv", "json"])
    parser.add_argument("--list-interfaces", action="store_true")
    args = parser.parse_args()

    if args.list_interfaces:
        ifaces = get_interfaces()
        for i in ifaces:
            print(f"  {i['index']}. {i['name']}")
        return

    if not check_tshark():
        print("[!] tshark not found — install Wireshark/tshark")
        sys.exit(1)

    init_db()
    signal.signal(signal.SIGINT,  _handle_shutdown)
    signal.signal(signal.SIGTERM, _handle_shutdown)

    use_ai        = ENABLE_AI and not args.no_ai
    use_dashboard = RICH_AVAILABLE and not args.no_dashboard
    use_web       = not args.no_web

    dashboard = Dashboard()
    dashboard.print_startup(args.interface, use_ai)

    source = capture_from_pcap(args.pcap) if args.pcap else capture_live(args.interface)

    # Start FastAPI web server in background
    tasks = []
    if use_web:
        tasks.append(asyncio.create_task(start_server()))

    # Start capture loop
    if use_dashboard:
        tasks.append(asyncio.create_task(
            _run_with_dashboard(source, dashboard, use_ai)
        ))
    else:
        tasks.append(asyncio.create_task(
            _run_plain(source, dashboard, use_ai)
        ))

    try:
        await asyncio.gather(*tasks)
    except asyncio.CancelledError:
        pass

    if args.export:
        from utils.exporter import export
        export(args.export)

    total   = dashboard.stats["total_packets"]
    threats = dashboard.stats["threats_found"]
    print(f"\n[✓] Done — {total:,} packets, {threats} threats detected")


async def _enrich_threat(threat: dict, use_ai: bool) -> dict:
    """Add GeoIP, VirusTotal, AI analysis, and auto-block to a threat."""
    src_ip = threat.get("src_ip", "")

    # GeoIP (fast, cached, no API key needed)
    geo = geo_lookup(src_ip)
    threat["geo"] = geo

    # VirusTotal (only if API key configured)
    vt = vt_check(src_ip)
    threat["vt"] = vt

    # AI analysis (HIGH/CRITICAL only — filtered inside analyze())
    if use_ai:
        threat = await ai_analyzer.analyze(threat, list(packet_history))

    # Auto-block CRITICAL threats
    if AUTO_BLOCK_CRITICAL and threat.get("severity") == "CRITICAL":
        blocked = block_ip(src_ip, reason=threat.get("type", "CRITICAL threat"))
        threat["blocked"] = blocked
        update_blocked(get_blocked())

    return threat


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
                push_packet(packet)

                threat = classifier.classify(packet)
                if threat:
                    threat = await _enrich_threat(threat, use_ai)
                    packet["_flagged"] = True
                    dashboard.add_threat(threat)
                    save_threat(threat)
                    notify(threat, skip_terminal=True)
                    push_threat(threat)

                # Push live stats to web
                update_stats(dashboard.stats)
                live.update(dashboard.build())
    except asyncio.CancelledError:
        pass


async def _run_plain(source, dashboard: Dashboard, use_ai: bool):
    """Capture loop with plain terminal output."""
    total = 0
    try:
        async for packet in source:
            if shutdown_event.is_set():
                break

            total += 1
            packet_history.append(packet)
            dashboard.add_packet(packet)
            save_packet(packet)
            push_packet(packet)

            src   = packet.get("src_ip",   "?")
            dst   = packet.get("dst_ip",   "?")
            proto = packet.get("protocol", "?")
            dport = packet.get("dst_port", "?")
            length= packet.get("length",   0)
            print(f"  [{total:04d}] {src:15} -> {dst:15}:{str(dport):<6} [{proto}] {length}b")

            threat = classifier.classify(packet)
            if threat:
                threat = await _enrich_threat(threat, use_ai)
                dashboard.add_threat(threat)
                save_threat(threat)
                notify(threat, skip_terminal=False)
                push_threat(threat)

            update_stats(dashboard.stats)
    except asyncio.CancelledError:
        pass


if __name__ == "__main__":
    asyncio.run(main())
