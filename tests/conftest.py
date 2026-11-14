"""
Pytest Fixtures for IRONCLAD Test Suite.
"""

import os
import tempfile
from pathlib import Path
from typing import Generator, List

import pytest
from scapy.all import IP, TCP, UDP, Raw, wrpcap

from ironclad.config.settings import EngineConfig
from ironclad.core.types import FlowKey, FlowRecord, PacketSummary, Protocol


@pytest.fixture
def temp_pcap_path() -> Generator[Path, None, None]:
    """Provide a temporary PCAP file with known test packets."""
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        tmp_path = Path(f.name)

    packets = []
    # 5 HTTP-like packets
    for i in range(5):
        pkt = (
            IP(src="192.168.1.10", dst="93.184.216.34")
            / TCP(sport=50000 + i, dport=80, flags="PA", seq=100 + i * 50)
            / Raw(load=f"GET /test_{i} HTTP/1.1\r\nHost: example.com\r\n\r\n".encode("utf-8"))
        )
        pkt.time = 1700000000.0 + (i * 0.1)
        packets.append(pkt)

    wrpcap(str(tmp_path), packets)
    yield tmp_path

    if tmp_path.exists():
        tmp_path.unlink()


@pytest.fixture
def empty_pcap_path() -> Generator[Path, None, None]:
    """Provide an empty file path for failure validation."""
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        tmp_path = Path(f.name)

    yield tmp_path

    if tmp_path.exists():
        tmp_path.unlink()


@pytest.fixture
def sample_packet_summaries() -> List[PacketSummary]:
    """Sample list of dissected packet summaries."""
    return [
        PacketSummary(
            timestamp=1700000000.0,
            length=120,
            src_ip="192.168.1.10",
            dst_ip="93.184.216.34",
            src_port=50000,
            dst_port=80,
            protocol=Protocol.TCP,
            protocol_name="TCP",
            tcp_flags={"SYN": False, "ACK": True, "FIN": False, "RST": False, "PSH": True, "URG": False},
            payload_length=60,
            payload_entropy=3.85,
            raw_packet_index=0,
        ),
        PacketSummary(
            timestamp=1700000000.05,
            length=80,
            src_ip="93.184.216.34",
            dst_ip="192.168.1.10",
            src_port=80,
            dst_port=50000,
            protocol=Protocol.TCP,
            protocol_name="TCP",
            tcp_flags={"SYN": False, "ACK": True, "FIN": False, "RST": False, "PSH": False, "URG": False},
            payload_length=20,
            payload_entropy=2.1,
            raw_packet_index=1,
        ),
    ]


@pytest.fixture
def default_config() -> EngineConfig:
    """Return default EngineConfig instance."""
    return EngineConfig.default()
