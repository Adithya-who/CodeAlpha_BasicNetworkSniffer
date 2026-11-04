"""Data models for network packet representation."""

from dataclasses import dataclass
from typing import Optional
from datetime import datetime


@dataclass
class PacketRecord:
    """Represents a sanitized, parsed summary of a captured network packet."""

    timestamp: datetime
    src_ip: str
    dst_ip: str
    protocol: str
    length: int
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    flags: Optional[str] = None
    info: str = ""

    @property
    def time_formatted(self) -> str:
        """Return HH:MM:SS.microsecond formatted timestamp."""
        return self.timestamp.strftime("%H:%M:%S.%f")[:-3]

    @property
    def endpoint_summary(self) -> str:
        """Return formatted Source -> Destination endpoint string."""
        src = f"{self.src_ip}:{self.src_port}" if self.src_port else self.src_ip
        dst = f"{self.dst_ip}:{self.dst_port}" if self.dst_port else self.dst_ip
        return f"{src} -> {dst}"

