"""Session telemetry and statistical analysis of captured network traffic."""

import json
import time
from collections import Counter
from typing import Optional, List, Dict, Any
from src.models import PacketRecord
from src.utils import format_bytes


class CaptureStats:
    """Maintains statistical metrics for a packet sniffing session."""

    def __init__(self):
        self.start_time: float = time.time()
        self.end_time: Optional[float] = None
        self.total_packets: int = 0
        self.total_bytes: int = 0
        self.malformed_packets: int = 0
        self.protocol_counts: Counter = Counter()
        self.top_sources: Counter = Counter()
        self.top_destinations: Counter = Counter()
        self.alerts: List[Dict[str, Any]] = []

    def record_alert(self, alert_obj: Any) -> None:
        """Record a detected security anomaly."""
        self.alerts.append({
            "timestamp": alert_obj.timestamp.isoformat(),
            "alert_type": alert_obj.alert_type,
            "severity": alert_obj.severity,
            "source_ip": alert_obj.source_ip,
            "description": alert_obj.description,
        })

    def update(self, record: Optional[PacketRecord], raw_len: int) -> None:
        """Update metrics with a new captured packet."""
        self.total_packets += 1
        self.total_bytes += raw_len

        if record is None:
            self.malformed_packets += 1
            self.protocol_counts["MALFORMED"] += 1
            return

        self.protocol_counts[record.protocol] += 1
        self.top_sources[record.src_ip] += 1
        self.top_destinations[record.dst_ip] += 1

    def finalize(self) -> None:
        """Mark the end time of the capture session."""
        if not self.end_time:
            self.end_time = time.time()

    @property
    def duration_seconds(self) -> float:
        """Return total elapsed capture time in seconds."""
        end = self.end_time or time.time()
        return max(0.001, end - self.start_time)

    @property
    def packets_per_second(self) -> float:
        """Return average packet throughput."""
        return self.total_packets / self.duration_seconds

    @property
    def bandwidth_summary(self) -> str:
        """Return human-readable total bandwidth captured."""
        return format_bytes(self.total_bytes)

    def to_dict(self) -> Dict[str, Any]:
        """Convert session metrics into a structured JSON-serializable dictionary."""
        return {
            "session_summary": {
                "start_time": self.start_time,
                "end_time": self.end_time or time.time(),
                "duration_seconds": round(self.duration_seconds, 2),
                "total_packets": self.total_packets,
                "total_bytes": self.total_bytes,
                "total_bandwidth": self.bandwidth_summary,
                "packets_per_second": round(self.packets_per_second, 2),
                "malformed_packets": self.malformed_packets,
            },
            "protocol_distribution": dict(self.protocol_counts),
            "top_sources": dict(self.top_sources.most_common(10)),
            "top_destinations": dict(self.top_destinations.most_common(10)),
            "security_alerts": self.alerts,
        }

    def export_json(self, file_path: str) -> None:
        """Export session telemetry and detected anomalies to a JSON file."""
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)

