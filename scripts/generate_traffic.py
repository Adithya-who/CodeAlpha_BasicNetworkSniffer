"""Safe traffic generation script for testing and demonstrating CodeAlpha Network Sniffer.

Generates realistic network packets including:
1. Standard TCP 3-way handshakes
2. DNS domain queries and responses
3. ICMP Echo request/reply diagnostics
4. HTTP request methods
5. Security test vectors: SYN port sweep, cleartext credentials, and DNS exfiltration query
"""

import argparse
import sys
import os
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether
from scapy.layers.dns import DNS, DNSQR
from scapy.packet import Raw


def build_synthetic_traffic() -> list:
    """Build a rich array of safe, synthetic test packets."""
    packets = [
        # 1. TCP 3-way Handshake
        Ether() / IP(src="192.168.1.105", dst="93.184.216.34") / TCP(sport=49152, dport=80, flags="S", seq=1000),
        Ether() / IP(src="93.184.216.34", dst="192.168.1.105") / TCP(sport=80, dport=49152, flags="SA", seq=5000, ack=1001),
        Ether() / IP(src="192.168.1.105", dst="93.184.216.34") / TCP(sport=49152, dport=80, flags="A", seq=1001, ack=5001),

        # 2. HTTP Request with cleartext credentials (Security Alert Vector)
        Ether() / IP(src="192.168.1.105", dst="93.184.216.34") / TCP(sport=49152, dport=80, flags="PA", seq=1001, ack=5001) / Raw(
            load=b"POST /login HTTP/1.1\r\nHost: insecure-app.local\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername=admin&password=SuperSecretPassword123!"
        ),

        # 3. Standard DNS Query & Response
        Ether() / IP(src="192.168.1.105", dst="8.8.8.8") / UDP(sport=53123, dport=53) / DNS(
            rd=1, qd=DNSQR(qname="codealpha.tech")
        ),

        # 4. ICMP Diagnostics (Ping)
        Ether() / IP(src="192.168.1.105", dst="1.1.1.1") / ICMP(type=8, code=0),
        Ether() / IP(src="1.1.1.1", dst="192.168.1.105") / ICMP(type=0, code=0),

        # 5. Suspicious Long DNS Query (DNS Tunneling / Data Exfiltration Alert Vector)
        Ether() / IP(src="192.168.1.105", dst="8.8.8.8") / UDP(sport=53124, dport=53) / DNS(
            rd=1, qd=DNSQR(qname="dGhpcy1pcy1hLXNlY3JldC1leGZpbHRyYXRpb24tdG9rZW4tZGF0YQ.tunnel.malicious.net")
        ),

        # 6. TCP SYN Port Scan Probing 5 Distinct Ports (Port Scan Alert Vector)
        Ether() / IP(src="10.0.0.99", dst="192.168.1.105") / TCP(sport=40001, dport=21, flags="S"),
        Ether() / IP(src="10.0.0.99", dst="192.168.1.105") / TCP(sport=40002, dport=22, flags="S"),
        Ether() / IP(src="10.0.0.99", dst="192.168.1.105") / TCP(sport=40003, dport=23, flags="S"),
        Ether() / IP(src="10.0.0.99", dst="192.168.1.105") / TCP(sport=40004, dport=80, flags="S"),
        Ether() / IP(src="10.0.0.99", dst="192.168.1.105") / TCP(sport=40005, dport=443, flags="S"),
    ]
    return packets


def main():
    parser = argparse.ArgumentParser(description="Generate safe synthetic network traffic for sniffer validation.")
    parser.add_argument(
        "-o", "--output-pcap",
        type=str,
        default="captures/security_demo.pcap",
        help="Path to save generated packets as a .pcap file"
    )
    args = parser.parse_args()

    os.makedirs(os.path.dirname(os.path.abspath(args.output_pcap)), exist_ok=True)
    packets = build_synthetic_traffic()
    scapy.wrpcap(args.output_pcap, packets)
    print(f"[+] Successfully generated {len(packets)} test packets into: {args.output_pcap}")
    print(f"[i] To inspect with anomaly detection, run:")
    print(f"    python main.py -r {args.output_pcap} --detect-anomalies --export-json results.json")


if __name__ == "__main__":
    main()

