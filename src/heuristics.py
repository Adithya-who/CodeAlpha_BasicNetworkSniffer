"""Lightweight network intrusion detection and security heuristics engine."""

from dataclasses import dataclass
from datetime import datetime
from collections import defaultdict
from typing import List, Optional, Set, Dict
import scapy.all as scapy
from scapy.layers.inet import TCP, IP
from scapy.layers.dns import DNS
from scapy.packet import Raw

from src.models import PacketRecord


@dataclass
class SecurityAlert:
    """Represents a security anomaly or suspicious pattern detected in network traffic."""

    timestamp: datetime
    alert_type: str
    severity: str  # "LOW", "MEDIUM", "HIGH"
    source_ip: str
    description: str

    def format_line(self) -> str:
        """Format the alert into a styled terminal warning string."""
        color = "yellow" if self.severity == "MEDIUM" else "red" if self.severity == "HIGH" else "cyan"
        time_str = self.timestamp.strftime("%H:%M:%S.%f")[:-3]
        return (
            f"[{color}][!] SECURITY ALERT [{self.severity}][/{color}] "
            f"[dim]{time_str}[/dim] | "
            f"Src: {self.source_ip} | "
            f"{self.alert_type}: {self.description}"
        )


class AnomalyDetector:
    """Detects port scans, cleartext credentials, and DNS tunneling indicators."""

    def __init__(self, port_scan_threshold: int = 5):
        self.port_scan_threshold = port_scan_threshold
        # Track destination ports scanned per source IP
        self._syn_ports_by_ip: Dict[str, Set[int]] = defaultdict(set)
        # Track generated alerts to avoid repetitive flooding
        self.alerts: List[SecurityAlert] = []
        self._alerted_scanners: Set[str] = set()

    def inspect(self, raw_packet: scapy.Packet, record: Optional[PacketRecord]) -> Optional[SecurityAlert]:
        """Inspects a packet for security anomalies.
        
        Returns:
            SecurityAlert if an anomaly is triggered, else None.
        """
        if not record:
            return None

        alert = None

        # 1. TCP Port Scan Heuristic (SYN Stealth Probing)
        if raw_packet.haslayer(TCP) and record.flags and "SYN" in record.flags and "ACK" not in record.flags:
            if record.dst_port and record.src_ip not in self._alerted_scanners:
                self._syn_ports_by_ip[record.src_ip].add(record.dst_port)
                if len(self._syn_ports_by_ip[record.src_ip]) >= self.port_scan_threshold:
                    ports_sampled = sorted(list(self._syn_ports_by_ip[record.src_ip]))[:5]
                    alert = SecurityAlert(
                        timestamp=record.timestamp,
                        alert_type="PORT_SCAN",
                        severity="HIGH",
                        source_ip=record.src_ip,
                        description=f"Rapid SYN probes targeting {len(self._syn_ports_by_ip[record.src_ip])}+ ports (e.g. {ports_sampled})"
                    )
                    self._alerted_scanners.add(record.src_ip)

        # 2. Cleartext Credential / Sensitive Token Transmission in HTTP Payloads
        if alert is None and raw_packet.haslayer(Raw):
            try:
                payload = bytes(raw_packet[Raw].load).lower()
                patterns = [
                    (b"password=", "Exposed password field"),
                    (b"passwd=", "Exposed passwd field"),
                    (b"authorization: basic", "Unencrypted Basic Auth Header"),
                    (b"api_key=", "Exposed API Key parameter"),
                    (b"access_token=", "Exposed Access Token parameter"),
                ]
                for pattern, desc in patterns:
                    if pattern in payload:
                        alert = SecurityAlert(
                            timestamp=record.timestamp,
                            alert_type="CLEARTEXT_CREDENTIAL",
                            severity="HIGH",
                            source_ip=record.src_ip,
                            description=f"{desc} in cleartext payload transmitted to {record.dst_ip}"
                        )
                        break
            except Exception:
                pass

        # 3. DNS Tunneling & Exfiltration Indicator (Excessively Long Subdomains)
        if alert is None and raw_packet.haslayer(DNS):
            dns = raw_packet[DNS]
            if dns.qr == 0 and dns.qd:
                try:
                    qd_first = dns.qd[0] if hasattr(dns.qd, '__getitem__') else dns.qd
                    qname = qd_first.qname.decode(errors="ignore").rstrip(".")
                    # High-entropy, unusually long labels (>50 characters) often indicate base64/hex DNS exfiltration
                    if len(qname) > 50:
                        alert = SecurityAlert(
                            timestamp=record.timestamp,
                            alert_type="DNS_TUNNELING_SUSPECT",
                            severity="MEDIUM",
                            source_ip=record.src_ip,
                            description=f"Abnormally long DNS query name ({len(qname)} chars): {qname[:35]}..."
                        )
                except Exception:
                    pass

        if alert:
            self.alerts.append(alert)

        return alert

