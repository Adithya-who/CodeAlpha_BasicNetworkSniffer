"""Unit tests for packet parsing logic using synthetic Scapy frames."""

import pytest
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP
from scapy.layers.dns import DNS, DNSQR
from scapy.packet import Raw

from src.parser import parse_packet


def test_parse_tcp_syn_packet():
    """Verify parsing of an IPv4 TCP SYN handshake packet."""
    pkt = Ether() / IP(src="192.168.1.50", dst="93.184.216.34") / TCP(sport=54321, dport=443, flags="S", seq=1000)
    record = parse_packet(pkt)

    assert record is not None
    assert record.src_ip == "192.168.1.50"
    assert record.dst_ip == "93.184.216.34"
    assert record.src_port == 54321
    assert record.dst_port == 443
    assert record.protocol == "TCP"
    assert "SYN" in record.flags


def test_parse_udp_packet():
    """Verify parsing of an IPv4 UDP packet."""
    pkt = Ether() / IP(src="10.0.0.5", dst="10.0.0.1") / UDP(sport=5000, dport=5353)
    record = parse_packet(pkt)

    assert record is not None
    assert record.src_ip == "10.0.0.5"
    assert record.dst_ip == "10.0.0.1"
    assert record.protocol == "UDP"
    assert record.src_port == 5000
    assert record.dst_port == 5353


def test_parse_icmp_echo_request():
    """Verify parsing of an ICMP Ping Echo Request."""
    pkt = Ether() / IP(src="192.168.1.10", dst="8.8.8.8") / ICMP(type=8, code=0)
    record = parse_packet(pkt)

    assert record is not None
    assert record.src_ip == "192.168.1.10"
    assert record.dst_ip == "8.8.8.8"
    assert record.protocol == "ICMP"
    assert "Echo Request" in record.info


def test_parse_dns_query():
    """Verify parsing of a DNS query."""
    pkt = Ether() / IP(src="192.168.1.10", dst="1.1.1.1") / UDP(sport=51234, dport=53) / DNS(
        rd=1, qd=DNSQR(qname="example.com")
    )
    record = parse_packet(pkt)

    assert record is not None
    assert record.protocol == "DNS"
    assert "example.com" in record.info


def test_parse_arp_packet():
    """Verify parsing of an ARP resolution request."""
    pkt = Ether() / ARP(op=1, psrc="192.168.1.100", pdst="192.168.1.1")
    record = parse_packet(pkt)

    assert record is not None
    assert record.protocol == "ARP"
    assert record.src_ip == "192.168.1.100"
    assert record.dst_ip == "192.168.1.1"

