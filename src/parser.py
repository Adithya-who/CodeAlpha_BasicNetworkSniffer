"""Packet parsing and protocol dissection logic."""

from datetime import datetime
from typing import Optional
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.layers.dns import DNS, DNSQR, DNSRR

from src.models import PacketRecord


def _decode_tcp_flags(flags: int) -> str:
    """Convert TCP flag bits to a human-readable string."""
    flag_names = []
    # Scapy flags representation
    flag_map = [
        (0x01, "FIN"),
        (0x02, "SYN"),
        (0x04, "RST"),
        (0x08, "PSH"),
        (0x10, "ACK"),
        (0x20, "URG"),
        (0x40, "ECE"),
        (0x80, "CWR")
    ]
    for bit, name in flag_map:
        if flags & bit:
            flag_names.append(name)
    return ",".join(flag_names) if flag_names else "NONE"


def _decode_icmp_type(icmp_type: int, icmp_code: int) -> str:
    """Convert ICMP type and code to recognizable network diagnostics."""
    types = {
        0: "Echo Reply (Ping Response)",
        3: f"Destination Unreachable (Code {icmp_code})",
        5: "Redirect",
        8: "Echo Request (Ping)",
        11: "Time Exceeded (TTL expired in transit)"
    }
    return types.get(icmp_type, f"Type {icmp_type} (Code {icmp_code})")


def parse_packet(packet: scapy.Packet) -> Optional[PacketRecord]:
    """Safely dissects a raw Scapy packet into a structured PacketRecord.
    
    Returns:
        PacketRecord on successful parse, or None if the packet is malformed.
    """
    try:
        ts = datetime.fromtimestamp(float(packet.time))
        length = len(packet)
        src_ip = "Unknown"
        dst_ip = "Unknown"
        protocol = "OTHER"
        src_port: Optional[int] = None
        dst_port: Optional[int] = None
        flags: Optional[str] = None
        info_parts = []

        # 1. Layer 3 / Network Layer Dissection
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            protocol = "IP"
        elif packet.haslayer(IPv6):
            ip6_layer = packet[IPv6]
            src_ip = ip6_layer.src
            dst_ip = ip6_layer.dst
            protocol = "IPv6"
        elif packet.haslayer(ARP):
            arp = packet[ARP]
            src_ip = arp.psrc
            dst_ip = arp.pdst
            protocol = "ARP"
            op = "Who has" if arp.op == 1 else "Is at" if arp.op == 2 else f"Op={arp.op}"
            return PacketRecord(
                timestamp=ts,
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol="ARP",
                length=length,
                info=f"{op} {dst_ip}? Tell {src_ip}"
            )
        else:
            # Non-IP layer 2 frame (e.g. raw Ethernet / STP)
            if packet.haslayer(Ether):
                src_ip = packet[Ether].src
                dst_ip = packet[Ether].dst
                protocol = f"Ether(0x{packet[Ether].type:04x})"
            return PacketRecord(
                timestamp=ts,
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=protocol,
                length=length,
                info="Non-IP Layer 2 frame"
            )

        # 2. Application Layer: DNS Dissection
        if packet.haslayer(DNS):
            protocol = "DNS"
            dns = packet[DNS]
            if dns.qr == 0:  # Query
                try:
                    qd_first = dns.qd[0] if (dns.qd and hasattr(dns.qd, '__getitem__')) else dns.qd
                    qname = qd_first.qname.decode(errors="ignore") if qd_first else "Unknown"
                except Exception:
                    qname = "Unknown"
                info_parts.append(f"Standard query {qname}")
            else:  # Response
                ancount = dns.ancount
                info_parts.append(f"Standard query response, {ancount} answers")

        # 3. Transport Layer Dissection: TCP / UDP / ICMP
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            src_port = tcp.sport
            dst_port = tcp.dport
            if protocol != "DNS":
                protocol = "TCP"
            flags = _decode_tcp_flags(int(tcp.flags))
            info_parts.append(f"Seq={tcp.seq} Ack={tcp.ack} Win={tcp.window}")

            # Check for HTTP hints if unencrypted
            if packet.haslayer(scapy.Raw):
                payload = bytes(packet[scapy.Raw].load)
                for http_method in [b"GET ", b"POST ", b"HTTP/1.", b"PUT ", b"HEAD "]:
                    if payload.startswith(http_method):
                        first_line = payload.split(b"\r\n")[0].decode(errors="ignore")
                        protocol = "HTTP"
                        info_parts.append(first_line)
                        break

        elif packet.haslayer(UDP):
            udp = packet[UDP]
            src_port = udp.sport
            dst_port = udp.dport
            if protocol != "DNS":
                protocol = "UDP"
            info_parts.append(f"Len={udp.len}")

        elif packet.haslayer(ICMP):
            icmp = packet[ICMP]
            protocol = "ICMP"
            info_parts.append(_decode_icmp_type(icmp.type, icmp.code))

        info_text = " | ".join(info_parts) if info_parts else f"Length: {length} bytes"

        return PacketRecord(
            timestamp=ts,
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol,
            length=length,
            src_port=src_port,
            dst_port=dst_port,
            flags=flags,
            info=info_text
        )

    except Exception:
        # Malformed packet or corrupted header fields
        return None
