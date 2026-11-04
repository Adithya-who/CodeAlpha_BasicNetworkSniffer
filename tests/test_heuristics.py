"""Unit tests for the heuristic anomaly detection engine."""

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.layers.dns import DNS, DNSQR
from scapy.packet import Raw

from src.parser import parse_packet
from src.heuristics import AnomalyDetector


def test_detect_port_scan():
    """Verify that multiple SYN packets targeting different ports trigger a PORT_SCAN alert."""
    detector = AnomalyDetector(port_scan_threshold=3)
    target_ports = [21, 22, 80]

    alerts = []
    for port in target_ports:
        pkt = Ether() / IP(src="10.0.0.50", dst="192.168.1.1") / TCP(sport=50000 + port, dport=port, flags="S")
        record = parse_packet(pkt)
        alert = detector.inspect(pkt, record)
        if alert:
            alerts.append(alert)

    assert len(alerts) == 1
    assert alerts[0].alert_type == "PORT_SCAN"
    assert alerts[0].source_ip == "10.0.0.50"
    assert alerts[0].severity == "HIGH"


def test_detect_cleartext_credentials():
    """Verify detection of exposed passwords in unencrypted HTTP payloads."""
    detector = AnomalyDetector()
    pkt = (
        Ether()
        / IP(src="192.168.1.5", dst="10.0.0.1")
        / TCP(sport=54321, dport=80, flags="PA")
        / Raw(load=b"POST /api/login HTTP/1.1\r\n\r\nusername=victim&password=PlainTextSecret")
    )
    record = parse_packet(pkt)
    alert = detector.inspect(pkt, record)

    assert alert is not None
    assert alert.alert_type == "CLEARTEXT_CREDENTIAL"
    assert alert.severity == "HIGH"
    assert "Exposed password field" in alert.description


def test_detect_dns_tunneling():
    """Verify detection of excessively long domain queries indicative of DNS exfiltration."""
    detector = AnomalyDetector()
    long_domain = "a" * 60 + ".tunnel.attacker.com"
    pkt = (
        Ether()
        / IP(src="192.168.1.20", dst="8.8.8.8")
        / UDP(sport=51234, dport=53)
        / DNS(rd=1, qd=DNSQR(qname=long_domain))
    )
    record = parse_packet(pkt)
    alert = detector.inspect(pkt, record)

    assert alert is not None
    assert alert.alert_type == "DNS_TUNNELING_SUSPECT"
    assert alert.severity == "MEDIUM"


def test_benign_traffic_no_alerts():
    """Verify that normal, benign packets do not produce false positive alerts."""
    detector = AnomalyDetector()
    pkt = (
        Ether()
        / IP(src="192.168.1.10", dst="93.184.216.34")
        / TCP(sport=51200, dport=443, flags="A")
        / Raw(load=b"EncryptedRandomBytes\x16\x03\x01\x00")
    )
    record = parse_packet(pkt)
    alert = detector.inspect(pkt, record)

    assert alert is None
    assert len(detector.alerts) == 0

