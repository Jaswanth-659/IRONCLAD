"""
Unit tests for ironclad.parsing.
"""

from scapy.all import IP, TCP, UDP, ICMP, Raw

from ironclad.core.types import Protocol
from ironclad.parsing.dissector import PacketDissector, calculate_shannon_entropy
from ironclad.parsing.protocols import parse_tcp_flags, get_service_name


def test_calculate_shannon_entropy():
    # Empty bytes
    assert calculate_shannon_entropy(b"") == 0.0
    # Monotonous repetitive bytes (zero uncertainty)
    assert calculate_shannon_entropy(b"AAAAAAA") == 0.0
    # Plain text
    entropy = calculate_shannon_entropy(b"Hello World, this is normal English text.")
    assert 3.0 < entropy < 5.0


def test_parse_tcp_flags():
    # String tests
    flags = parse_tcp_flags("SA")
    assert flags["SYN"] is True
    assert flags["ACK"] is True
    assert flags["FIN"] is False

    # Integer bitmask test: SYN (0x02) | ACK (0x10) = 0x12 = 18
    flags_int = parse_tcp_flags(18)
    assert flags_int["SYN"] is True
    assert flags_int["ACK"] is True
    assert flags_int["RST"] is False


def test_service_name_lookup():
    assert get_service_name(80) == "HTTP"
    assert get_service_name(443) == "HTTPS"
    assert get_service_name(53) == "DNS"
    assert get_service_name(9999) == "UNKNOWN"


def test_dissect_tcp_packet():
    dissector = PacketDissector()
    pkt = (
        IP(src="192.168.1.10", dst="10.0.0.1")
        / TCP(sport=12345, dport=80, flags="S")
        / Raw(load=b"Sample payload")
    )
    pkt.time = 1700000000.0

    summary = dissector.dissect(pkt, index=1)
    assert summary is not None
    assert summary.src_ip == "192.168.1.10"
    assert summary.dst_ip == "10.0.0.1"
    assert summary.src_port == 12345
    assert summary.dst_port == 80
    assert summary.protocol == Protocol.TCP
    assert summary.tcp_flags is not None
    assert summary.tcp_flags["SYN"] is True
    assert summary.payload_length == len(b"Sample payload")
    assert summary.payload_entropy > 0.0


def test_dissect_udp_packet():
    dissector = PacketDissector()
    pkt = IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=53000, dport=53)
    pkt.time = 1700000001.0

    summary = dissector.dissect(pkt, index=2)
    assert summary is not None
    assert summary.src_port == 53000
    assert summary.dst_port == 53
    assert summary.protocol == Protocol.UDP
