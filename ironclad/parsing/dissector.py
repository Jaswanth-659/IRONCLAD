"""
IRONCLAD Packet Dissector.

Dissects Scapy packet frames into normalized, strongly-typed PacketSummary instances
with protocol resolution, TCP flag analysis, and payload extraction.
"""

from __future__ import annotations

import math
from typing import Generator, Iterable, Optional

from scapy.all import (
    ARP,
    ICMP,
    IP,
    TCP,
    UDP,
    Ether,
    IPv6,
    Packet,
    Raw,
)

from ironclad.core.exceptions import PacketParsingError
from ironclad.core.ip_validation import validate_ipv4
from ironclad.core.logging import get_logger
from ironclad.core.types import PacketSummary, Protocol
from ironclad.parsing.protocols import parse_tcp_flags

logger = get_logger("parsing.dissector")


def calculate_shannon_entropy(data: bytes) -> float:
    r"""
    Compute Shannon entropy $H(X) = - \sum_{i=1}^n p_i \log_2(p_i)$ for a byte stream.
    Entropy ranges from 0.0 (completely uniform/redundant) to 8.0 (pure randomness/high encryption).
    """
    if not data:
        return 0.0

    length = len(data)
    frequencies = {}
    for b in data:
        frequencies[b] = frequencies.get(b, 0) + 1

    entropy = 0.0
    for count in frequencies.values():
        p_x = count / length
        if p_x > 0:
            entropy -= p_x * math.log2(p_x)

    return float(round(entropy, 4))


class PacketDissector:
    """
    Robust network packet dissector for raw Scapy packets.
    Extracts Layer 2, 3, and 4 metadata, payload previews, and entropy.
    """

    def __init__(
        self,
        parse_payload: bool = True,
        payload_preview_bytes: int = 64,
        compute_entropy: bool = True,
    ) -> None:
        self.parse_payload = parse_payload
        self.payload_preview_bytes = payload_preview_bytes
        self.compute_entropy = compute_entropy

    def dissect(self, pkt: Packet, index: int = 0) -> Optional[PacketSummary]:
        """
        Dissect a single Scapy packet into a PacketSummary.

        Args:
            pkt: Scapy Packet object.
            index: Monotonic packet index in capture.

        Returns:
            PacketSummary if packet contains IP/ARP traffic; None for unsupported L2 protocols.
        """
        try:
            timestamp = float(getattr(pkt, "time", 0.0))
            wire_len = len(pkt)

            src_ip: str
            dst_ip: str
            src_port: Optional[int] = None
            dst_port: Optional[int] = None
            proto_enum = Protocol.UNKNOWN
            proto_name = "UNKNOWN"
            tcp_flags = None
            payload_bytes = b""

            if IP in pkt:
                ip_layer = pkt[IP]
                raw_src = str(ip_layer.src)
                raw_dst = str(ip_layer.dst)

                src_val = validate_ipv4(raw_src)
                dst_val = validate_ipv4(raw_dst)
                if not src_val.is_valid or not dst_val.is_valid:
                    logger.debug("Discarding packet #%d with malformed IPv4 endpoints: src='%s' dst='%s'", index, raw_src, raw_dst)
                    return None

                src_ip = src_val.normalized_ip or raw_src
                dst_ip = dst_val.normalized_ip or raw_dst
                proto_val = int(ip_layer.proto)
                proto_enum = Protocol.from_int(proto_val)
                proto_name = proto_enum.name
            elif IPv6 in pkt:
                ip_layer = pkt[IPv6]
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                proto_val = int(ip_layer.nh)
                proto_enum = Protocol.from_int(proto_val)
                proto_name = proto_enum.name
            elif ARP in pkt:
                arp_layer = pkt[ARP]
                src_ip = arp_layer.psrc
                dst_ip = arp_layer.pdst
                proto_name = "ARP"
                return PacketSummary(
                    timestamp=timestamp,
                    length=wire_len,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    protocol=Protocol.UNKNOWN,
                    protocol_name=proto_name,
                    raw_packet_index=index,
                )
            else:
                # Non-IP layer 2 frame (e.g. STP, LLDP, Raw Ethernet)
                return None

            # Layer 4 dissection
            if TCP in pkt:
                tcp_layer = pkt[TCP]
                src_port = int(tcp_layer.sport)
                dst_port = int(tcp_layer.dport)
                proto_enum = Protocol.TCP
                proto_name = "TCP"
                tcp_flags = parse_tcp_flags(tcp_layer.flags)
            elif UDP in pkt:
                udp_layer = pkt[UDP]
                src_port = int(udp_layer.sport)
                dst_port = int(udp_layer.dport)
                proto_enum = Protocol.UDP
                proto_name = "UDP"
            elif ICMP in pkt:
                proto_enum = Protocol.ICMP
                proto_name = "ICMP"

            # Payload handling
            payload_len = 0
            entropy = 0.0
            preview = None

            if self.parse_payload and Raw in pkt:
                raw_payload = bytes(pkt[Raw].load)
                payload_len = len(raw_payload)
                if self.compute_entropy and payload_len > 0:
                    entropy = calculate_shannon_entropy(raw_payload)
                if self.payload_preview_bytes > 0:
                    preview = raw_payload[: self.payload_preview_bytes]

            return PacketSummary(
                timestamp=timestamp,
                length=wire_len,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=proto_enum,
                protocol_name=proto_name,
                tcp_flags=tcp_flags,
                payload_length=payload_len,
                payload_entropy=entropy,
                payload_preview=preview,
                raw_packet_index=index,
            )

        except Exception as e:
            logger.warning("Packet dissection failure on packet #%d: %s", index, e)
            raise PacketParsingError(
                f"Failed to dissect packet at index {index}", details={"error": str(e)}
            ) from e

    def dissect_stream(
        self, packets: Iterable[Packet]
    ) -> Generator[PacketSummary, None, None]:
        """
        Stream dissected summaries from an iterable of Scapy packets.

        Yields:
            PacketSummary objects for valid IP packets.
        """
        for idx, pkt in enumerate(packets):
            summary = self.dissect(pkt, index=idx)
            if summary is not None:
                yield summary
