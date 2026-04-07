"""
dashboard/cli_dashboard.py
Beautiful terminal dashboard using the Rich library.
Shows live packet feed, threat alerts, and stats.
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
    from rich.columns import Columns
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


class Dashboard:
    """Live terminal dashboard for packet analysis."""

    def __init__(self):
        self.threats    = deque(maxlen=MAX_TABLE_ROWS)
        self.packets    = deque(maxlen=100)
        self.stats      = {
            "total_packets":   0,
            "threats_found":   0,
            "critical_count":  0,
            "high_count":      0,
            "medium_count":    0,
            "low_count":       0,
            "start_time":      datetime.now(),
            "ai_analyses":     0,
        }
        self._live = None

    def add_packet(self, packet: dict):
        """Register a captured packet."""
        self.stats["total_packets"] += 1
        self.packets.append(packet)

    def add_threat(self, threat: dict):
        """Register a detected threat."""
        self.stats["threats_found"] += 1
        severity = threat.get("ai_severity") or threat.get("severity", "LOW")
        self.stats[f"{severity.lower()}_count"] = self.stats.get(f"{severity.lower()}_count", 0) + 1
        if threat.get("ai_analyzed"):
            self.stats["ai_analyses"] += 1
        self.threats.append({**threat, "_time": datetime.now()})

    def _make_stats_panel(self) -> Panel:
        elapsed = datetime.now() - self.stats["start_time"]
        minutes = int(elapsed.total_seconds() // 60)
        seconds = int(elapsed.total_seconds() % 60)
        pps = self.stats["total_packets"] / max(elapsed.total_seconds(), 1)

        text = Text()
        text.append(f"  Packets    : ", style="dim")
        text.append(f"{self.stats['total_packets']:,}", style="bold white")
        text.append(f"  ({pps:.1f}/s)\n")

        text.append(f"  Threats    : ", style="dim")
        text.append(f"{self.stats['threats_found']}", style="bold red")
        text.append(f"  (")
        text.append(f"CRIT:{self.stats['critical_count']} ", style="bold magenta")
        text.append(f"HIGH:{self.stats['high_count']} ", style="red")
        text.append(f"MED:{self.stats['medium_count']} ", style="yellow")
        text.append(f"LOW:{self.stats['low_count']}", style="blue")
        text.append(f")\n")

        text.append(f"  AI Analyses: ", style="dim")
        text.append(f"{self.stats['ai_analyses']}", style="bold cyan")
        text.append(f"\n  Runtime    : ", style="dim")
        text.append(f"{minutes:02d}:{seconds:02d}", style="bold white")

        return Panel(text, title="[bold]Stats[/bold]", border_style="dim white")

    def _make_threat_table(self) -> Table:
        table = Table(
            box=box.SIMPLE_HEAVY,
            show_header=True,
            header_style="bold white",
            expand=True
        )
        table.add_column("Time",        width=8,  style="dim")
        table.add_column("Severity",    width=10)
        table.add_column("Threat",      width=22)
        table.add_column("Source",      width=16)
        table.add_column("Destination", width=20)
        table.add_column("Score",       width=6,  justify="right")
        table.add_column("AI",          width=4,  justify="center")

        for t in reversed(list(self.threats)):
            severity  = t.get("ai_severity")   or t.get("severity", "LOW")
            name      = t.get("ai_threat_name") or t.get("type", "?")
            score     = t.get("ai_risk_score")  or t.get("risk_score", 0)
            style     = SEVERITY_STYLE.get(severity, "white")
            ts        = t["_time"].strftime("%H:%M:%S")
            ai_badge  = "[cyan]✓[/cyan]" if t.get("ai_analyzed") else " "
            dst       = f"{t.get('dst_ip','?')}:{t.get('dst_port','?')}"

            table.add_row(
                ts,
                f"[{style}]{severity}[/{style}]",
                f"[{style}]{name[:22]}[/{style}]",
                t.get("src_ip", "?"),
                dst,
                str(score),
                ai_badge,
            )

        return table

    def render(self):
        """Render the full dashboard."""
        if not RICH_AVAILABLE:
            return

        title_text = Text()
        title_text.append("⚡ AI Wireshark", style="bold cyan")
        title_text.append("  —  Real-time AI Packet Analysis", style="dim")

        console.print(Panel(title_text, border_style="cyan"))
        console.print(self._make_stats_panel())

        if self.threats:
            console.print(Panel(
                self._make_threat_table(),
                title="[bold red]Threat Feed[/bold red]",
                border_style="red"
            ))
        else:
            console.print(Panel(
                "[dim]No threats detected yet — monitoring...[/dim]",
                title="[bold]Threat Feed[/bold]",
                border_style="dim"
            ))

    def print_startup(self, interface: str, ai_enabled: bool):
        """Print startup banner."""
        if not RICH_AVAILABLE:
            print(f"\n[AI Wireshark] Starting on {interface} | AI: {'ON' if ai_enabled else 'OFF'}")
            return

        banner = Text()
        banner.append("\n  ⚡ AI Wireshark\n", style="bold cyan")
        banner.append("  Real-time Network Packet Analysis + LLM Threat Intelligence\n\n", style="dim")
        banner.append(f"  Interface : {interface}\n", style="white")
        banner.append(f"  AI Engine : ", style="white")
        if ai_enabled:
            banner.append("Claude (Anthropic) ✓\n", style="bold cyan")
        else:
            banner.append("Disabled (rule-based only)\n", style="yellow")
        banner.append("\n  Press Ctrl+C to stop\n", style="dim")

        console.print(Panel(banner, border_style="cyan"))


# Fallback simple printer (no Rich)
def simple_print_threat(threat: dict):
    severity = threat.get("severity", "UNKNOWN")
    name     = threat.get("type", "Threat")
    print(f"\n[{severity}] {name}")
    print(f"  {threat.get('src_ip')} → {threat.get('dst_ip')}:{threat.get('dst_port')}")
    print(f"  {threat.get('description')}")
