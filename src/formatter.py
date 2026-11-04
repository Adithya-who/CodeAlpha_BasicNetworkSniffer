"""Console formatting and terminal presentation for captured packets and statistics."""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from typing import List, Dict, Any, Optional

from src.models import PacketRecord
from src.stats import CaptureStats

import sys

# Ensure UTF-8 output encoding across legacy Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

console = Console()

# Protocol color scheme for quick visual triaging
PROTOCOL_COLORS = {
    "TCP": "bright_cyan",
    "UDP": "bright_blue",
    "ICMP": "bright_yellow",
    "DNS": "bright_magenta",
    "HTTP": "bright_green",
    "ARP": "dark_goldenrod",
    "IPv6": "light_slate_blue",
    "MALFORMED": "bright_red",
}


def print_banner(interface_name: str, bpf_filter: Optional[str], pcap_file: Optional[str]) -> None:
    """Display startup banner with operational context and ethical disclaimer."""
    filter_str = bpf_filter if bpf_filter else "None (Promiscuous All)"
    pcap_str = pcap_file if pcap_file else "Disabled"

    banner_text = Text()
    banner_text.append("[*] CODEALPHA NETWORK SNIFFER v1.0.0\n", style="bold cyan")
    banner_text.append("Real-Time Traffic Inspection & Security Telemetry Engine\n\n", style="dim")
    banner_text.append(f"• Interface   : {interface_name}\n", style="white")
    banner_text.append(f"• BPF Filter  : {filter_str}\n", style="yellow")
    banner_text.append(f"• PCAP Output : {pcap_str}\n", style="green")
    banner_text.append("\n[ETHICAL BOUNDARY] Authorized local capture only. Press Ctrl+C to stop.", style="dim italic red")

    console.print(Panel(banner_text, border_style="cyan", expand=False))
    console.print()


def print_interfaces_table(interfaces: List[Dict[str, Any]]) -> None:
    """Print available network interfaces in a clean tabular view."""
    table = Table(title="Available Network Interfaces", border_style="blue", header_style="bold blue")
    table.add_column("#", style="dim", width=4)
    table.add_column("Interface Name", style="bold white", min_width=25)
    table.add_column("IP Address", style="bright_cyan", width=18)
    table.add_column("MAC Address", style="magenta", width=20)
    table.add_column("Description", style="dim", min_width=30)

    for idx, iface in enumerate(interfaces, start=1):
        table.add_row(
            str(idx),
            str(iface["name"]),
            str(iface["ip"]),
            str(iface["mac"]),
            str(iface["description"])
        )

    console.print(table)


def print_packet_line(packet_num: int, record: Optional[PacketRecord], raw_len: int) -> None:
    """Print a single captured packet row to the terminal."""
    if record is None:
        console.print(
            f"[dim]{packet_num:>5}[/dim] | "
            f"[bright_red]MALFORMED PACKET[/bright_red] | "
            f"Length: {raw_len}B | "
            f"[dim]Failed to parse protocol headers[/dim]"
        )
        return

    proto_color = PROTOCOL_COLORS.get(record.protocol, "white")
    proto_styled = f"[{proto_color}]{record.protocol:<5}[/{proto_color}]"

    # Endpoints
    src = f"{record.src_ip}:{record.src_port}" if record.src_port else record.src_ip
    dst = f"{record.dst_ip}:{record.dst_port}" if record.dst_port else record.dst_ip
    flow = f"{src:>21}  ->  {dst:<21}"

    # Flag preview
    flag_str = f" [{record.flags}]" if record.flags else ""

    console.print(
        f"[dim]{packet_num:>5}[/dim] | "
        f"[dim]{record.time_formatted}[/dim] | "
        f"{proto_styled} | "
        f"{flow} | "
        f"[dim]{record.length:>5}B[/dim] | "
        f"{record.info}{flag_str}"
    )


def print_summary_report(stats: CaptureStats) -> None:
    """Print the final session report and security telemetry."""
    console.print()
    stats_panel = Text()
    stats_panel.append("[*] CAPTURE SESSION SUMMARY\n", style="bold cyan")
    stats_panel.append(f"• Total Duration   : {stats.duration_seconds:.2f} seconds\n")
    stats_panel.append(f"• Packets Captured : {stats.total_packets}\n")
    stats_panel.append(f"• Total Data Volume: {stats.bandwidth_summary}\n")
    stats_panel.append(f"• Average Rate     : {stats.packets_per_second:.1f} packets/sec\n")
    if stats.malformed_packets > 0:
        stats_panel.append(f"• Malformed Packets: {stats.malformed_packets}\n", style="bold red")

    console.print(Panel(stats_panel, border_style="cyan", expand=False))

    # Protocol breakdown table
    proto_table = Table(title="Protocol Distribution", border_style="cyan", header_style="bold cyan")
    proto_table.add_column("Protocol", style="white")
    proto_table.add_column("Count", justify="right", style="bright_green")
    proto_table.add_column("Percentage", justify="right", style="bright_yellow")

    for proto, count in stats.protocol_counts.most_common():
        pct = (count / stats.total_packets * 100) if stats.total_packets > 0 else 0
        proto_table.add_row(proto, str(count), f"{pct:5.1f}%")

    console.print(proto_table)

    # Top talkers table
    if stats.top_sources:
        talkers_table = Table(title="Top Communicating Endpoints", border_style="green", header_style="bold green")
        talkers_table.add_column("IP Address", style="bright_cyan")
        talkers_table.add_column("Packets Sent", justify="right", style="white")

        for ip, count in stats.top_sources.most_common(5):
            talkers_table.add_row(ip, str(count))

        console.print(talkers_table)

    # Security alerts table if any alerts occurred
    if stats.alerts:
        alerts_table = Table(title="[!] Security Alerts Detected", border_style="red", header_style="bold red")
        alerts_table.add_column("Severity", style="bold")
        alerts_table.add_column("Type", style="yellow")
        alerts_table.add_column("Source IP", style="bright_cyan")
        alerts_table.add_column("Description", style="white")

        for alert in stats.alerts:
            sev_color = "red" if alert["severity"] == "HIGH" else "yellow" if alert["severity"] == "MEDIUM" else "cyan"
            alerts_table.add_row(
                f"[{sev_color}]{alert['severity']}[/{sev_color}]",
                alert["alert_type"],
                alert["source_ip"],
                alert["description"]
            )

        console.print(alerts_table)
