"""
dashboard/cli_dashboard.py
Live terminal dashboard using the Rich library.
Uses rich.live.Live for real-time refresh.
"""

from datetime import datetime
from collections import deque
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from config import MAX_TABLE_ROWS, DASHBOARD_REFRESH

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.layout import Layout
    from rich.live import Live
    from rich.text import Text
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

console = Console() if RICH_AVAILABLE else None

SEVERITY_STYLE = {
    "LOW":      "blue",
    "MEDIUM":   "yellow",
    "HIGH":     "red",
    "CRITICAL": "bold magenta",
}

PROTO_STYLE = {
    "TCP":  "cyan",
    "UDP":  "green",
    "ICMP": "yellow",
}


class Dashboard:
    """Live terminal dashboard — call build() to get a Rich renderable for Live."""

    def __init__(self):
        self.threats    = deque(maxlen=MAX_TABLE_ROWS)
        self.packets    = deque(maxlen=50)
        self.start_time = datetime.now()
        self.stats: dict[str, int] = {
            "total_packets":  0,
            "threats_found":  0,
            "critical_count": 0,
            "high_count":     0,
            "medium_count":   0,
            "low_count":      0,
            "ai_analyses":    0,
        }

    def add_packet(self, packet: dict):
        self.stats["total_packets"] += 1
        self.packets.append(packet)

    def add_threat(self, threat: dict):
        self.stats["threats_found"] += 1
        severity = threat.get("ai_severity") or threat.get("severity", "LOW")
        key = f"{severity.lower()}_count"
        self.stats[key] = self.stats.get(key, 0) + 1
        if threat.get("ai_analyzed"):
            self.stats["ai_analyses"] += 1
        self.threats.append({**threat, "_time": datetime.now()})

    # ── Renderables ───────────────────────────────────────────────────────────

    def _make_header(self) -> Panel:
        t = Text()
        t.append("⚡ AI Wireshark", style="bold cyan")
        t.append("  —  Real-time AI Packet Analysis  ", style="dim")
        t.append(f"  {datetime.now().strftime('%H:%M:%S')}", style="bold white")
        return Panel(t, border_style="cyan", padding=(0, 1))

    def _make_stats(self) -> Panel:
        elapsed = datetime.now() - self.start_time
        mins    = int(elapsed.total_seconds() // 60)
        secs    = int(elapsed.total_seconds() % 60)
        pps     = self.stats["total_packets"] / max(elapsed.total_seconds(), 1)

        t = Text()
        t.append("Packets : ", style="dim")
        t.append(f"{self.stats['total_packets']:,}", style="bold white")
        t.append(f"  ({pps:.1f}/s)\n")

        t.append("Threats : ", style="dim")
        t.append(f"{self.stats['threats_found']}", style="bold red")
        t.append("  (")
        t.append(f"CRIT:{self.stats['critical_count']} ", style="bold magenta")
        t.append(f"HIGH:{self.stats['high_count']} ",     style="red")
        t.append(f"MED:{self.stats['medium_count']} ",    style="yellow")
        t.append(f"LOW:{self.stats['low_count']}",        style="blue")
        t.append(")\n")

        t.append("AI Analyses : ", style="dim")
        t.append(f"{self.stats['ai_analyses']}", style="bold cyan")
        t.append("   Runtime : ", style="dim")
        t.append(f"{mins:02d}:{secs:02d}", style="bold white")

        return Panel(t, title="[bold]Stats[/bold]", border_style="dim white", padding=(0, 1))

    def _make_packet_table(self) -> Table:
        table = Table(
            box=box.SIMPLE,
            show_header=True,
            header_style="bold dim",
            expand=True,
            padding=(0, 1),
        )
        table.add_column("#",        width=5,  justify="right", style="dim")
        table.add_column("Time",     width=8,  style="dim")
        table.add_column("Source",   width=18)
        table.add_column("Dest",     width=21)
        table.add_column("Proto",    width=6,  justify="center")
        table.add_column("Size",     width=7,  justify="right", style="dim")
        table.add_column("Flag",     width=4,  justify="center")

        packets = list(self.packets)
        offset  = self.stats["total_packets"] - len(packets)

        for i, p in enumerate(reversed(packets)):
            proto       = p.get("protocol", "?")
            proto_style = PROTO_STYLE.get(proto, "white")
            src         = f"{p.get('src_ip','?')}:{p.get('src_port','?')}"
            dst         = f"{p.get('dst_ip','?')}:{p.get('dst_port','?')}"
            length      = p.get("length") or 0
            flagged     = p.get("_flagged", False)
            flag_cell   = "[bold red]![/bold red]" if flagged else " "
            num         = offset + len(packets) - i

            table.add_row(
                str(num),
                datetime.now().strftime("%H:%M:%S"),
                src[:18],
                dst[:21],
                f"[{proto_style}]{proto}[/{proto_style}]",
                f"{length}b",
                flag_cell,
            )

        return table

    def _make_threat_table(self) -> Table:
        table = Table(
            box=box.SIMPLE,
            show_header=True,
            header_style="bold dim",
            expand=True,
            padding=(0, 1),
        )
        table.add_column("Time",     width=8,  style="dim")
        table.add_column("Sev",      width=8)
        table.add_column("Threat",   width=24)
        table.add_column("Source",   width=16)
        table.add_column("Score",    width=5,  justify="right")
        table.add_column("AI",       width=3,  justify="center")

        for t in reversed(list(self.threats)):
            severity  = t.get("ai_severity")   or t.get("severity", "LOW")
            name      = t.get("ai_threat_name") or t.get("type", "?")
            score     = t.get("ai_risk_score")  or t.get("risk_score", 0)
            style     = SEVERITY_STYLE.get(str(severity), "white")
            _time: datetime = t["_time"]
            ts        = _time.strftime("%H:%M:%S")
            ai_badge  = "[cyan]✓[/cyan]" if t.get("ai_analyzed") else " "

            table.add_row(
                ts,
                f"[{style}]{severity}[/{style}]",
                f"[{style}]{name[:24]}[/{style}]",
                t.get("src_ip", "?"),
                str(score),
                ai_badge,
            )

        return table

    # ── Live layout ───────────────────────────────────────────────────────────

    def build(self) -> Layout:
        """Return a full Layout renderable for use with rich.live.Live."""
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body"),
            Layout(name="footer", size=4),
        )

        layout["header"].update(self._make_header())

        layout["body"].split_row(
            Layout(name="packets", ratio=3),
            Layout(name="threats", ratio=2),
        )
        layout["body"]["packets"].update(Panel(
            self._make_packet_table(),
            title="[bold green]Live Packets[/bold green]",
            border_style="green",
        ))
        threat_content = (
            self._make_threat_table() if self.threats
            else Text("\n  No threats detected yet — monitoring...", style="dim")
        )
        layout["body"]["threats"].update(Panel(
            threat_content,
            title="[bold red]Threat Feed[/bold red]",
            border_style="red",
        ))

        layout["footer"].update(self._make_stats())
        return layout

    # ── Non-Live helpers ──────────────────────────────────────────────────────

    def print_startup(self, interface: str, ai_enabled: bool):
        if not RICH_AVAILABLE:
            print(f"\n[AI Wireshark] Starting on {interface} | AI: {'ON' if ai_enabled else 'OFF'}")
            return

        banner = Text()
        banner.append("\n  ⚡ AI Wireshark\n", style="bold cyan")
        banner.append("  Real-time Network Threat Detection + LLM Analysis\n\n", style="dim")
        banner.append(f"  Interface  : {interface}\n", style="white")
        banner.append(f"  AI Engine  : ", style="white")
        if ai_enabled:
            from config import AI_PROVIDER, AI_MODEL
            banner.append(f"{AI_PROVIDER} / {AI_MODEL} ✓\n", style="bold cyan")
        else:
            banner.append("Disabled (rule-based only)\n", style="yellow")
        banner.append("\n  Press Ctrl+C to stop\n", style="dim")
        if console:
            console.print(Panel(banner, border_style="cyan"))


def simple_print_threat(threat: dict):
    severity = threat.get("severity", "UNKNOWN")
    name     = threat.get("type", "Threat")
    print(f"\n[{severity}] {name}")
    print(f"  {threat.get('src_ip')} → {threat.get('dst_ip')}:{threat.get('dst_port')}")
    print(f"  {threat.get('description')}")
