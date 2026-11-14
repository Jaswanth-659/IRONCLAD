"""
IRONCLAD Flow Aggregator.

Aggregates individual packet summaries into stateful bidirectional or unidirectional
network flow records with high-dimensional feature representations.
"""

from __future__ import annotations

import math
from typing import Dict, Iterable, List, Optional

import pandas as pd

from ironclad.core.exceptions import FeatureExtractionError
from ironclad.core.logging import get_logger
from ironclad.core.types import FlowKey, FlowRecord, PacketSummary, Protocol
from ironclad.features.entropy import shannon_entropy
from ironclad.features.temporal import calculate_burstiness, calculate_inter_arrival_times, calculate_jitter

logger = get_logger("features.flow_aggregator")


class FlowAggregator:
    """
    Stateful network flow aggregator. Groups packets by 5-tuple communication channels
    and computes statistical, temporal, and cryptographic flow metrics.
    """

    def __init__(
        self,
        bidirectional: bool = True,
        flow_timeout_seconds: float = 120.0,
    ) -> None:
        self.bidirectional = bidirectional
        self.flow_timeout_seconds = flow_timeout_seconds
        self._flows: Dict[str, FlowRecord] = {}
        self._flow_timestamps: Dict[str, List[float]] = {}

    def _generate_canonical_key(self, pkt: PacketSummary) -> str:
        src_port = pkt.src_port or 0
        dst_port = pkt.dst_port or 0
        proto_num = int(pkt.protocol)

        if self.bidirectional:
            endpoints = sorted([(pkt.src_ip, src_port), (pkt.dst_ip, dst_port)])
            return f"{endpoints[0][0]}:{endpoints[0][1]}<->{endpoints[1][0]}:{endpoints[1][1]}:{proto_num}"
        else:
            return f"{pkt.src_ip}:{src_port}->{pkt.dst_ip}:{dst_port}:{proto_num}"

    def add_packet(self, pkt: PacketSummary) -> None:
        """
        Incorporate a dissected packet summary into the active flow table.
        """
        canonical_id = self._generate_canonical_key(pkt)
        flow_key = FlowKey(
            src_ip=pkt.src_ip,
            dst_ip=pkt.dst_ip,
            src_port=pkt.src_port or 0,
            dst_port=pkt.dst_port or 0,
            protocol=pkt.protocol,
        )

        flow = self._flows.get(canonical_id)

        if flow is None:
            # Initialize new flow record
            flow = FlowRecord(
                key=flow_key,
                canonical_id=canonical_id,
                start_time=pkt.timestamp,
                end_time=pkt.timestamp,
                packet_count=1,
                byte_count=pkt.length,
                forward_packets=1,
                forward_bytes=pkt.length,
                packet_lengths=[pkt.length],
                inter_arrival_times=[],
                payload_entropies=[pkt.payload_entropy] if pkt.payload_entropy > 0 else [],
            )
            self._flows[canonical_id] = flow
            self._flow_timestamps[canonical_id] = [pkt.timestamp]
        else:
            # Update existing flow
            timestamps = self._flow_timestamps[canonical_id]
            last_ts = timestamps[-1] if timestamps else flow.end_time
            delta_t = max(0.0, pkt.timestamp - last_ts)

            flow.end_time = max(flow.end_time, pkt.timestamp)
            flow.packet_count += 1
            flow.byte_count += pkt.length
            flow.packet_lengths.append(pkt.length)
            flow.inter_arrival_times.append(delta_t)
            timestamps.append(pkt.timestamp)

            if pkt.payload_entropy > 0:
                flow.payload_entropies.append(pkt.payload_entropy)

            # Check forward vs reverse direction
            if pkt.src_ip == flow.key.src_ip and (pkt.src_port or 0) == flow.key.src_port:
                flow.forward_packets += 1
                flow.forward_bytes += pkt.length
            else:
                flow.backward_packets += 1
                flow.backward_bytes += pkt.length

        # Update TCP flags
        if pkt.tcp_flags:
            for flag, active in pkt.tcp_flags.items():
                if active and flag in flow.tcp_flags:
                    flow.tcp_flags[flag] += 1

    def aggregate_stream(self, packet_summaries: Iterable[PacketSummary]) -> List[FlowRecord]:
        """
        Process an iterable stream of PacketSummary objects.

        Returns:
            List of aggregated FlowRecord objects.
        """
        for pkt in packet_summaries:
            self.add_packet(pkt)
        return self.get_flows()

    def get_flows(self) -> List[FlowRecord]:
        """Retrieve all active flow records."""
        return list(self._flows.values())

    def to_dataframe(self) -> pd.DataFrame:
        """
        Export flow records into a structured pandas DataFrame optimized
        for statistical and machine learning anomaly detection.

        Returns:
            pandas DataFrame where each row corresponds to one flow record.
        """
        rows = []
        for flow in self._flows.values():
            lengths = flow.packet_lengths
            iats = flow.inter_arrival_times

            len_mean = sum(lengths) / len(lengths) if lengths else 0.0
            len_std = (
                math.sqrt(sum((x - len_mean) ** 2 for x in lengths) / len(lengths))
                if len(lengths) > 1
                else 0.0
            )
            len_min = float(min(lengths)) if lengths else 0.0
            len_max = float(max(lengths)) if lengths else 0.0

            iat_mean = sum(iats) / len(iats) if iats else 0.0
            iat_std = (
                math.sqrt(sum((x - iat_mean) ** 2 for x in iats) / len(iats))
                if len(iats) > 1
                else 0.0
            )
            iat_min = float(min(iats)) if iats else 0.0
            iat_max = float(max(iats)) if iats else 0.0

            dur = flow.duration
            pps = flow.packet_count / dur if dur > 0 else float(flow.packet_count)
            bps = flow.byte_count / dur if dur > 0 else float(flow.byte_count)

            jitter = calculate_jitter(iats)
            burst = calculate_burstiness(iat_mean, iat_std)

            syn_count = flow.tcp_flags.get("SYN", 0)
            ack_count = flow.tcp_flags.get("ACK", 0)
            fin_count = flow.tcp_flags.get("FIN", 0)
            rst_count = flow.tcp_flags.get("RST", 0)

            # SYN/ACK ratio useful for scan and flood detection
            syn_ack_ratio = syn_count / (ack_count + 1)

            rows.append({
                "flow_id": flow.canonical_id,
                "src_ip": flow.key.src_ip,
                "dst_ip": flow.key.dst_ip,
                "src_port": flow.key.src_port,
                "dst_port": flow.key.dst_port,
                "protocol": int(flow.key.protocol),
                "duration": dur,
                "packet_count": flow.packet_count,
                "byte_count": flow.byte_count,
                "forward_packets": flow.forward_packets,
                "backward_packets": flow.backward_packets,
                "forward_bytes": flow.forward_bytes,
                "backward_bytes": flow.backward_bytes,
                "packet_length_mean": len_mean,
                "packet_length_std": len_std,
                "packet_length_min": len_min,
                "packet_length_max": len_max,
                "iat_mean": iat_mean,
                "iat_std": iat_std,
                "iat_min": iat_min,
                "iat_max": iat_max,
                "pps": pps,
                "bps": bps,
                "jitter": jitter,
                "burstiness": burst,
                "syn_count": syn_count,
                "ack_count": ack_count,
                "fin_count": fin_count,
                "rst_count": rst_count,
                "syn_ack_ratio": syn_ack_ratio,
                "mean_payload_entropy": flow.mean_payload_entropy,
            })

        if not rows:
            return pd.DataFrame()

        df = pd.DataFrame(rows)
        return df

    def clear(self) -> None:
        """Clear all stored flow states."""
        self._flows.clear()
        self._flow_timestamps.clear()
