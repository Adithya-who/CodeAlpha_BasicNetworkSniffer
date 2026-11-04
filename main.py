"""CLI Entrypoint for CodeAlpha Network Sniffer."""

import argparse
import sys
from typing import Optional

from src.utils import is_admin, get_available_interfaces
from src.formatter import (
    console,
    print_banner,
    print_interfaces_table,
    print_summary_report,
)
from src.sniffer import SnifferEngine


def parse_arguments() -> argparse.Namespace:
    """Parse and validate command line arguments."""
    parser = argparse.ArgumentParser(
        description="CodeAlpha Basic Network Sniffer - Packet Analysis & Telemetry Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --list-interfaces
  python main.py -i 1 -f "tcp port 80"
  python main.py -i "Wi-Fi" -w captures/session.pcap -c 50
  python main.py -i 1 --protocol DNS
        """
    )

    parser.add_argument(
        "-i", "--interface",
        type=str,
        help="Interface name or index number (use --list-interfaces to inspect)"
    )
    parser.add_argument(
        "-l", "--list-interfaces",
        action="store_true",
        help="List available network interfaces and exit"
    )
    parser.add_argument(
        "-f", "--filter",
        type=str,
        default=None,
        help="BPF capture filter (e.g., 'tcp', 'udp port 53', 'icmp', 'host 192.168.1.1')"
    )
    parser.add_argument(
        "-w", "--write-pcap",
        type=str,
        default=None,
        help="Path to save captured packets in .pcap format"
    )
    parser.add_argument(
        "-r", "--read-pcap",
        type=str,
        default=None,
        help="Path to an existing .pcap file for offline analysis (no admin rights needed)"
    )
    parser.add_argument(
        "-c", "--count",
        type=int,
        default=0,
        help="Maximum number of packets to capture (default: 0 = continuous)"
    )
    parser.add_argument(
        "-t", "--timeout",
        type=int,
        default=None,
        help="Capture timeout in seconds (default: infinite)"
    )
    parser.add_argument(
        "-p", "--protocol",
        type=str,
        default=None,
        help="Application-level display filter (e.g., TCP, UDP, ICMP, DNS)"
    )
    parser.add_argument(
        "--detect-anomalies",
        action="store_true",
        help="Enable heuristic anomaly detection (port scans, cleartext credentials, DNS tunneling)"
    )
    parser.add_argument(
        "--export-json",
        type=str,
        default=None,
        help="Path to export session metrics, protocol counts, and alerts in JSON format"
    )
    parser.add_argument(
        "--no-admin-check",
        action="store_true",
        help="Skip administrative privilege verification check"
    )

    return parser.parse_args()


def resolve_interface(target: Optional[str]) -> Optional[str]:
    """Resolve an interface argument (integer index or name) to Scapy's interface descriptor."""
    if not target:
        return None

    interfaces = get_available_interfaces()

    # Case 1: Target is an integer index (1-based from table)
    if target.isdigit():
        idx = int(target) - 1
        if 0 <= idx < len(interfaces):
            return interfaces[idx]["key"]
        console.print(f"[bold red]Error:[/bold red] Interface index {target} out of range (1 - {len(interfaces)}).")
        sys.exit(1)

    # Case 2: Target is an interface name or description substring
    target_lower = target.lower()
    for iface in interfaces:
        if (target_lower in iface["name"].lower() or 
            target_lower in str(iface["description"]).lower() or
            target_lower == str(iface["key"]).lower()):
            return iface["key"]

    return target


def main() -> None:
    """Main execution workflow."""
    args = parse_arguments()

    # Mode 1: Interface listing
    if args.list_interfaces:
        interfaces = get_available_interfaces()
        print_interfaces_table(interfaces)
        sys.exit(0)

    # Mode 2: Offline PCAP Analysis (Zero elevation required)
    if args.read_pcap:
        import os
        if not os.path.isfile(args.read_pcap):
            console.print(f"[bold red]Error:[/bold red] PCAP file not found: {args.read_pcap}")
            sys.exit(1)

        console.print(f"[bold cyan][*] OFFLINE PCAP INSPECTION:[/bold cyan] {args.read_pcap}\n")
        engine = SnifferEngine(
            display_protocol=args.protocol,
            packet_count=args.count,
            detect_anomalies=args.detect_anomalies,
        )
        try:
            stats = engine.read_pcap(args.read_pcap)
            print_summary_report(stats)
            if args.export_json:
                stats.export_json(args.export_json)
                console.print(f"[bold green][+] Session telemetry exported to:[/bold green] {args.export_json}")
        except Exception as e:
            console.print(f"[bold red]Offline Analysis Error:[/bold red] {e}")
        sys.exit(0)

    # Mode 3: Live Capture - Pre-flight check for Administrative Privileges
    if not args.no_admin_check and not is_admin():
        console.print(
            "[bold red][!] PRIVILEGE ERROR:[/bold red] Live packet sniffing requires administrative privileges.\n"
            "Please reopen your terminal using [bold yellow]'Run as Administrator'[/bold yellow] to capture packets,\n"
            "or use [bold green]--read-pcap <file.pcap>[/bold green] for offline analysis."
        )
        sys.exit(1)

    # Resolve target interface
    selected_iface = resolve_interface(args.interface)
    iface_display = str(selected_iface) if selected_iface else "Default Adapter"

    # Print startup banner
    print_banner(iface_display, args.filter, args.write_pcap)

    # Instantiate and execute sniffer engine
    engine = SnifferEngine(
        interface=selected_iface,
        bpf_filter=args.filter,
        pcap_path=args.write_pcap,
        packet_count=args.count,
        timeout=args.timeout,
        display_protocol=args.protocol,
        detect_anomalies=args.detect_anomalies,
    )

    try:
        stats = engine.start()
        print_summary_report(stats)
        if args.export_json:
            stats.export_json(args.export_json)
            console.print(f"[bold green][+] Session telemetry exported to:[/bold green] {args.export_json}")
    except PermissionError as e:
        console.print(f"[bold red]Permission Error:[/bold red] {e}")
        console.print("Ensure Npcap is installed and running with admin privileges.")
    except Exception as e:
        console.print(f"[bold red]Runtime Capture Error:[/bold red] {e}")
    finally:
        console.print("[dim]Capture session finalized cleanly.[/dim]")


if __name__ == "__main__":
    main()
