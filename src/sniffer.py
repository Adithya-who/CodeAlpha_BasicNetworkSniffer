"""Sniffer capture engine coordinating Scapy, PCAP streaming, and parsing."""

import os
from typing import Optional
import scapy.all as scapy
from scapy.utils import PcapWriter

from src.models import PacketRecord
from src.parser import parse_packet
from src.formatter import print_packet_line
from src.stats import CaptureStats


class SnifferEngine:
    """Manages the packet capture lifecycle, PCAP dumping, and telemetry."""

    def __init__(
        self,
        interface: Optional[str] = None,
        bpf_filter: Optional[str] = None,
        pcap_path: Optional[str] = None,
        packet_count: int = 0,
        timeout: Optional[int] = None,
        display_protocol: Optional[str] = None
    ):
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.pcap_path = pcap_path
        self.packet_count = packet_count
        self.timeout = timeout
        self.display_protocol = display_protocol.upper() if display_protocol else None

        self.stats = CaptureStats()
        self._pcap_writer: Optional[PcapWriter] = None
        self._interrupted = False

    def _handle_packet(self, raw_packet: scapy.Packet) -> None:
        """Callback invoked by Scapy for every captured packet."""
        raw_len = len(raw_packet)

        # 1. Forensic preservation: Write raw packet to PCAP FIRST before parsing
        if self._pcap_writer:
            try:
                self._pcap_writer.write(raw_packet)
            except Exception as e:
                # Log error or continue to avoid dropping the sniffer thread
                pass

        # 2. Parse packet into strongly-typed PacketRecord
        record: Optional[PacketRecord] = parse_packet(raw_packet)

        # 3. Update session statistics
        self.stats.update(record, raw_len)

        # 4. Display filtering (application-level)
        if self.display_protocol and record and record.protocol != self.display_protocol:
            return

        # 5. Render live terminal output
        print_packet_line(self.stats.total_packets, record, raw_len)

    def start(self) -> CaptureStats:
        """Start the live packet capture loop."""
        # Initialize PCAP writer if path specified
        if self.pcap_path:
            os.makedirs(os.path.dirname(os.path.abspath(self.pcap_path)), exist_ok=True)
            # sync=True flushes each packet to disk immediately
            self._pcap_writer = PcapWriter(self.pcap_path, append=False, sync=True)

        try:
            # scapy.sniff with store=False guarantees O(1) memory usage
            scapy.sniff(
                iface=self.interface,
                filter=self.bpf_filter,
                prn=self._handle_packet,
                store=False,
                count=self.packet_count,
                timeout=self.timeout
            )
        except KeyboardInterrupt:
            self._interrupted = True
        finally:
            self.stop()

        return self.stats

    def read_pcap(self, pcap_file: str) -> CaptureStats:
        """Read and analyze packets from a saved .pcap file in offline mode."""
        from scapy.utils import PcapReader
        import time

        try:
            with PcapReader(pcap_file) as reader:
                for raw_packet in reader:
                    raw_len = len(raw_packet)
                    record: Optional[PacketRecord] = parse_packet(raw_packet)
                    self.stats.update(record, raw_len)

                    if self.display_protocol and record and record.protocol != self.display_protocol:
                        continue

                    print_packet_line(self.stats.total_packets, record, raw_len)

                    if self.packet_count > 0 and self.stats.total_packets >= self.packet_count:
                        break
        except KeyboardInterrupt:
            self._interrupted = True
        finally:
            self.stats.finalize()

        return self.stats

    def stop(self) -> None:
        """Finalize resources and close open file handles."""
        if self._pcap_writer:
            try:
                self._pcap_writer.close()
            except Exception:
                pass
            self._pcap_writer = None

        self.stats.finalize()
