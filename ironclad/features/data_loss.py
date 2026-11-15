"""
IRONCLAD Data-Loss and Transmission Integrity Monitoring Engine.

Provides deep, multi-tier packet loss and data volume degradation analysis:
1. Overall Data Loss:
   - Expected vs Received packet counts
   - Packet loss percentage: ((Expected - Received) / Expected) * 100
   - Volume expected vs Volume received, missing bytes estimation
   - Timeline loss trends
   - Strict adherence to rule: Never report unavailable measurements as confirmed data loss.
2. Protocol-Wise Loss Breakdown:
   - TCP: Retransmissions, out-of-order packets, sequence gaps, duplicate ACKs, inferred loss
   - UDP: Sequence-numbered reference tracking for confirmed loss; explicit UNAVAILABLE when untagged
   - ICMP: Unanswered echo request/reply ratio
3. Adaptive Data-Loss Alert Generation.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from ironclad.core.types import PacketSummary, Protocol


class LossMeasurementStatus(str, Enum):
    """Categorization of packet loss measurement reliability."""
    CONFIRMED = "CONFIRMED"             # Verified against known sequence metadata / test header
    INFERRED = "INFERRED"               # Deduced from TCP retransmissions, duplicate ACKs, sequence gaps
    ESTIMATED = "ESTIMATED"             # Statistical approximation
    UNAVAILABLE = "UNAVAILABLE"         # Cannot be measured without reference stream


@dataclass
class ProtocolDataLossMetrics:
    """Protocol-specific transmission and loss telemetry."""
    protocol: str
    packets_observed: int = 0
    expected_packets: Optional[int] = None
    lost_packets: Optional[int] = None
    retransmissions: int = 0
    retransmission_rate: float = 0.0
    sequence_gaps: int = 0
    duplicate_acks: int = 0
    loss_percentage: Optional[float] = None
    total_bytes: int = 0
    pps: float = 0.0
    bps: float = 0.0
    measurement_status: LossMeasurementStatus = LossMeasurementStatus.UNAVAILABLE
    associated_anomalies: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "protocol": self.protocol,
            "packets_observed": self.packets_observed,
            "expected_packets": self.expected_packets,
            "lost_packets": self.lost_packets,
            "retransmissions": self.retransmissions,
            "retransmission_rate": round(self.retransmission_rate, 2),
            "sequence_gaps": self.sequence_gaps,
            "duplicate_acks": self.duplicate_acks,
            "loss_percentage": round(self.loss_percentage, 2) if self.loss_percentage is not None else None,
            "total_bytes": self.total_bytes,
            "pps": round(self.pps, 2),
            "bps": round(self.bps, 2),
            "measurement_status": self.measurement_status.value,
            "associated_anomalies": self.associated_anomalies,
        }


@dataclass
class OverallDataLossReport:
    """Consolidated network data-loss diagnostic."""
    total_packets_expected: Optional[int]
    total_packets_received: int
    total_packets_lost: Optional[int]
    overall_loss_percentage: Optional[float]
    data_volume_expected_bytes: Optional[int]
    data_volume_received_bytes: int
    estimated_missing_bytes: int
    measurement_status: LossMeasurementStatus
    protocols: Dict[str, ProtocolDataLossMetrics]
    timeline_loss_trend: List[Dict[str, Any]]
    data_loss_alerts: List[Dict[str, Any]]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_packets_expected": self.total_packets_expected,
            "total_packets_received": self.total_packets_received,
            "total_packets_lost": self.total_packets_lost,
            "overall_loss_percentage": (
                round(self.overall_loss_percentage, 2)
                if self.overall_loss_percentage is not None
                else None
            ),
            "data_volume_expected_bytes": self.data_volume_expected_bytes,
            "data_volume_received_bytes": self.data_volume_received_bytes,
            "estimated_missing_bytes": self.estimated_missing_bytes,
            "measurement_status": self.measurement_status.value,
            "protocols": {k: v.to_dict() for k, v in self.protocols.items()},
            "timeline_loss_trend": self.timeline_loss_trend,
            "data_loss_alerts": self.data_loss_alerts,
        }


class DataLossMonitor:
    """
    Stateful analyzer tracking transmission integrity, retransmissions, sequence continuity,
    and reference-checked data loss across packets.
    """

    def __init__(self, time_window_seconds: float = 2.0) -> None:
        self.time_window_seconds = time_window_seconds
        self.reset()

    def reset(self) -> None:
        self.total_received = 0
        self.total_bytes = 0
        self.first_ts: Optional[float] = None
        self.last_ts: Optional[float] = None

        # Protocol tracking
        self.proto_packets: Dict[str, int] = {"TCP": 0, "UDP": 0, "ICMP": 0, "OTHER": 0}
        self.proto_bytes: Dict[str, int] = {"TCP": 0, "UDP": 0, "ICMP": 0, "OTHER": 0}

        # TCP Stateful Stream Tracking
        # key = (src_ip, src_port, dst_ip, dst_port)
        # value = {"max_seq": int, "seen_seqs": set(), "retransmissions": 0, "gaps": 0, "dup_acks": 0, "last_ack": int, "ack_count": 0}
        self.tcp_streams: Dict[Tuple[str, int, str, int], Dict[str, Any]] = {}
        self.total_tcp_retransmissions = 0
        self.total_tcp_sequence_gaps = 0
        self.total_tcp_missing_bytes = 0
        self.total_tcp_dup_acks = 0

        # UDP Reference Sequence Tracking (for controlled test scenarios)
        # key = (src_ip, dst_ip) -> {"max_seq": int, "min_seq": int, "seen_seqs": set(), "total_expected": int}
        self.udp_reference_streams: Dict[Tuple[str, str], Dict[str, Any]] = {}

        # ICMP Tracking
        self.icmp_echo_requests = 0
        self.icmp_echo_replies = 0

        # Time-window bin tracking for trends
        # bin_id -> {"ts": float, "packets": int, "bytes": int, "retransmissions": int, "lost": int}
        self.time_bins: Dict[int, Dict[str, Any]] = {}

    def ingest_packet(self, pkt: PacketSummary, raw_scapy_packet: Any = None) -> None:
        """
        Processes a single packet summary and optional Scapy frame to extract sequence
        continuity, retransmissions, or test reference sequences.
        """
        ts = pkt.timestamp
        wire_len = pkt.length

        self.total_received += 1
        self.total_bytes += wire_len

        if self.first_ts is None:
            self.first_ts = ts
        self.last_ts = max(self.last_ts or ts, ts)

        # Time bin
        bin_idx = int(ts / self.time_window_seconds) if self.time_window_seconds > 0 else 0
        if bin_idx not in self.time_bins:
            self.time_bins[bin_idx] = {
                "bin_start": bin_idx * self.time_window_seconds,
                "packets": 0,
                "bytes": 0,
                "tcp_retrans": 0,
                "udp_lost": 0,
            }
        tbin = self.time_bins[bin_idx]
        tbin["packets"] += 1
        tbin["bytes"] += wire_len

        proto_name = pkt.protocol_name.upper()
        if proto_name == "TCP":
            self._process_tcp(pkt, raw_scapy_packet, tbin)
        elif proto_name == "UDP":
            self._process_udp(pkt, raw_scapy_packet, tbin)
        elif proto_name == "ICMP":
            self._process_icmp(pkt, raw_scapy_packet, tbin)
        else:
            self.proto_packets["OTHER"] += 1
            self.proto_bytes["OTHER"] += wire_len

    def _process_tcp(self, pkt: PacketSummary, raw_pkt: Any, tbin: Dict[str, Any]) -> None:
        self.proto_packets["TCP"] += 1
        self.proto_bytes["TCP"] += pkt.length

        src_port = pkt.src_port or 0
        dst_port = pkt.dst_port or 0
        stream_key = (pkt.src_ip, src_port, pkt.dst_ip, dst_port)

        stream = self.tcp_streams.setdefault(stream_key, {
            "max_seq": None,
            "seen_ranges": set(),
            "retransmissions": 0,
            "gaps": 0,
            "missing_bytes": 0,
            "last_ack": None,
            "ack_count": 0,
        })

        if raw_pkt is not None:
            try:
                from scapy.all import TCP
                if TCP in raw_pkt:
                    tcp_layer = raw_pkt[TCP]
                    seq = int(tcp_layer.seq)
                    ack = int(tcp_layer.ack)
                    payload_len = len(bytes(tcp_layer.payload))

                    # Retransmission check
                    # If this seq range has been seen before or is behind max_seq with payload
                    if payload_len > 0:
                        seg_range = (seq, seq + payload_len)
                        if seg_range in stream["seen_ranges"]:
                            stream["retransmissions"] += 1
                            self.total_tcp_retransmissions += 1
                            tbin["tcp_retrans"] += 1
                        else:
                            stream["seen_ranges"].add(seg_range)

                        # Sequence gap check (forward leap)
                        if stream["max_seq"] is not None:
                            expected_next = stream["max_seq"]
                            if seq > expected_next and (seq - expected_next) < 10000000:
                                # Detected gap between expected_next and seq
                                stream["gaps"] += 1
                                gap_bytes = seq - expected_next
                                stream["missing_bytes"] += gap_bytes
                                self.total_tcp_sequence_gaps += 1
                                self.total_tcp_missing_bytes += gap_bytes
                                tbin["tcp_gaps"] = tbin.get("tcp_gaps", 0) + 1

                        # Update highest contiguous observed seq
                        current_end = seq + payload_len
                        if stream["max_seq"] is None or current_end > stream["max_seq"]:
                            stream["max_seq"] = current_end

                    # Duplicate ACK check
                    if ack == stream["last_ack"]:
                        stream["ack_count"] += 1
                        if stream["ack_count"] >= 3:
                            self.total_tcp_dup_acks += 1
                    else:
                        stream["last_ack"] = ack
                        stream["ack_count"] = 1
            except Exception:
                pass

    def _process_udp(self, pkt: PacketSummary, raw_pkt: Any, tbin: Dict[str, Any]) -> None:
        self.proto_packets["UDP"] += 1
        self.proto_bytes["UDP"] += pkt.length

        # Inspect payload for sequence-number metadata (used in controlled test scenarios)
        # Format: e.g. b"IRONCLAD_SEQ:000123:TOTAL:001000" or {"seq": 123, "total": 1000}
        preview = pkt.payload_preview or b""
        if raw_pkt is not None:
            try:
                from scapy.all import Raw
                if Raw in raw_pkt:
                    preview = bytes(raw_pkt[Raw].load)[:128]
            except Exception:
                pass

        if preview:
            try:
                text = preview.decode("utf-8", errors="ignore")
                if "IRONCLAD_SEQ:" in text:
                    # Pattern: IRONCLAD_SEQ:<num>:<total>
                    parts = text.split("IRONCLAD_SEQ:")[1].split(":")
                    if len(parts) >= 2:
                        seq_num = int(parts[0])
                        total_expected = int(parts[1].split()[0])
                        stream_key = (pkt.src_ip, pkt.dst_ip)
                        u_stream = self.udp_reference_streams.setdefault(stream_key, {
                            "min_seq": seq_num,
                            "max_seq": seq_num,
                            "seen_seqs": set(),
                            "total_expected": total_expected,
                        })
                        u_stream["seen_seqs"].add(seq_num)
                        u_stream["min_seq"] = min(u_stream["min_seq"], seq_num)
                        u_stream["max_seq"] = max(u_stream["max_seq"], seq_num)
                        u_stream["total_expected"] = max(u_stream["total_expected"], total_expected)
            except Exception:
                pass

    def _process_icmp(self, pkt: PacketSummary, raw_pkt: Any, tbin: Dict[str, Any]) -> None:
        self.proto_packets["ICMP"] += 1
        self.proto_bytes["ICMP"] += pkt.length

        if raw_pkt is not None:
            try:
                from scapy.all import ICMP
                if ICMP in raw_pkt:
                    icmp_type = raw_pkt[ICMP].type
                    if icmp_type == 8:  # Echo request
                        self.icmp_echo_requests += 1
                    elif icmp_type == 0:  # Echo reply
                        self.icmp_echo_replies += 1
            except Exception:
                pass

    def generate_report(self) -> OverallDataLossReport:
        """
        Synthesizes the overall and protocol-wise data loss diagnostic.
        Strictly observes: Only calculate actual packet loss when expected packet counts
        or sequence numbers are available. Never report fake numbers.
        """
        duration = max(0.001, (self.last_ts or 0.0) - (self.first_ts or 0.0))

        # 1. TCP Analysis (Inferred from Retransmissions and Gaps)
        tcp_count = self.proto_packets["TCP"]
        tcp_bytes = self.proto_bytes["TCP"]
        tcp_pps = tcp_count / duration
        tcp_bps = tcp_bytes / duration

        tcp_anomalies = []
        if tcp_count > 0:
            tcp_lost = self.total_tcp_sequence_gaps
            tcp_expected = tcp_count + tcp_lost
            tcp_loss_pct = round((tcp_lost / float(tcp_expected)) * 100.0, 2) if tcp_expected > 0 else 0.0
            retrans_rate = round((self.total_tcp_retransmissions / float(tcp_count)) * 100.0, 2)

            if self.total_tcp_retransmissions > 5:
                tcp_anomalies.append(f"Elevated TCP retransmissions ({self.total_tcp_retransmissions}, {retrans_rate}% retransmit rate)")
            if self.total_tcp_sequence_gaps > 0:
                tcp_anomalies.append(f"Detected {self.total_tcp_sequence_gaps} TCP sequence gaps (~{self.total_tcp_missing_bytes} bytes missing, {tcp_loss_pct}% loss)")
            if self.total_tcp_dup_acks > 5:
                tcp_anomalies.append(f"Fast retransmit triggered by {self.total_tcp_dup_acks} duplicate ACK bursts")

            tcp_status = (
                LossMeasurementStatus.INFERRED
                if (self.total_tcp_retransmissions > 0 or self.total_tcp_sequence_gaps > 0)
                else LossMeasurementStatus.CONFIRMED
            )
            tcp_metrics = ProtocolDataLossMetrics(
                protocol="TCP",
                packets_observed=tcp_count,
                expected_packets=tcp_expected,
                lost_packets=tcp_lost,
                retransmissions=self.total_tcp_retransmissions,
                retransmission_rate=retrans_rate,
                sequence_gaps=self.total_tcp_sequence_gaps,
                duplicate_acks=self.total_tcp_dup_acks,
                loss_percentage=tcp_loss_pct,
                total_bytes=tcp_bytes,
                pps=tcp_pps,
                bps=tcp_bps,
                measurement_status=tcp_status,
                associated_anomalies=tcp_anomalies,
            )
        else:
            tcp_metrics = ProtocolDataLossMetrics(
                protocol="TCP",
                packets_observed=0,
                measurement_status=LossMeasurementStatus.UNAVAILABLE,
            )

        # 2. UDP Analysis (Reference sequences or unmeasured)
        udp_count = self.proto_packets["UDP"]
        udp_bytes = self.proto_bytes["UDP"]
        udp_pps = udp_count / duration
        udp_bps = udp_bytes / duration

        udp_anomalies = []
        udp_expected = None
        udp_lost = None
        udp_loss_pct = None
        udp_status = LossMeasurementStatus.UNAVAILABLE

        if self.udp_reference_streams:
            # Sum up sequence-controlled test streams
            tot_exp = sum(s["total_expected"] for s in self.udp_reference_streams.values())
            tot_rec = sum(len(s["seen_seqs"]) for s in self.udp_reference_streams.values())
            if tot_exp > 0:
                udp_expected = tot_exp
                udp_lost = max(0, tot_exp - tot_rec)
                udp_loss_pct = round(((tot_exp - tot_rec) / float(tot_exp)) * 100.0, 2)
                udp_status = LossMeasurementStatus.CONFIRMED
                if udp_loss_pct > 2.0:
                    udp_anomalies.append(f"Confirmed UDP packet loss of {udp_loss_pct}% ({udp_lost}/{tot_exp} lost)")
        else:
            if udp_count > 0:
                udp_anomalies.append("UDP traffic unreferenced (stateless; loss cannot be measured without sequence headers)")

        udp_metrics = ProtocolDataLossMetrics(
            protocol="UDP",
            packets_observed=udp_count,
            expected_packets=udp_expected,
            lost_packets=udp_lost,
            retransmissions=0,
            sequence_gaps=0,
            duplicate_acks=0,
            loss_percentage=udp_loss_pct,
            total_bytes=udp_bytes,
            pps=udp_pps,
            bps=udp_bps,
            measurement_status=udp_status,
            associated_anomalies=udp_anomalies,
        )

        # 3. ICMP Analysis (Echo Requests vs Echo Replies)
        icmp_count = self.proto_packets["ICMP"]
        icmp_bytes = self.proto_bytes["ICMP"]
        icmp_pps = icmp_count / duration
        icmp_bps = icmp_bytes / duration

        icmp_expected = None
        icmp_lost = None
        icmp_loss_pct = None
        icmp_status = LossMeasurementStatus.UNAVAILABLE
        icmp_anomalies = []

        if self.icmp_echo_requests > 0:
            icmp_expected = self.icmp_echo_requests
            icmp_lost = max(0, self.icmp_echo_requests - self.icmp_echo_replies)
            icmp_loss_pct = round((icmp_lost / float(self.icmp_echo_requests)) * 100.0, 2)
            icmp_status = LossMeasurementStatus.INFERRED
            if icmp_loss_pct > 5.0:
                icmp_anomalies.append(f"ICMP echo drops: {self.icmp_echo_requests} requested, only {self.icmp_echo_replies} replied ({icmp_loss_pct}% loss)")

        icmp_metrics = ProtocolDataLossMetrics(
            protocol="ICMP",
            packets_observed=icmp_count,
            expected_packets=icmp_expected,
            lost_packets=icmp_lost,
            retransmissions=0,
            sequence_gaps=0,
            duplicate_acks=0,
            loss_percentage=icmp_loss_pct,
            total_bytes=icmp_bytes,
            pps=icmp_pps,
            bps=icmp_bps,
            measurement_status=icmp_status,
            associated_anomalies=icmp_anomalies,
        )

        # Other protocol summary
        other_metrics = ProtocolDataLossMetrics(
            protocol="OTHER",
            packets_observed=self.proto_packets["OTHER"],
            total_bytes=self.proto_bytes["OTHER"],
            measurement_status=LossMeasurementStatus.UNAVAILABLE,
        )

        protocols = {
            "TCP": tcp_metrics,
            "UDP": udp_metrics,
            "ICMP": icmp_metrics,
            "OTHER": other_metrics,
        }

        # Overall loss calculation
        overall_expected: Optional[int] = None
        overall_lost: Optional[int] = None
        overall_loss_pct: Optional[float] = None
        overall_status = LossMeasurementStatus.UNAVAILABLE
        missing_bytes_est = self.total_tcp_missing_bytes

        if udp_expected is not None:
            # We have confirmed UDP test reference
            tcp_exp = tcp_metrics.expected_packets or tcp_count
            overall_expected = udp_expected + tcp_exp
            overall_lost = (udp_lost or 0) + (tcp_metrics.lost_packets or 0)
            overall_loss_pct = round((overall_lost / float(overall_expected)) * 100.0, 2)
            overall_status = LossMeasurementStatus.CONFIRMED
        elif tcp_metrics.measurement_status == LossMeasurementStatus.INFERRED:
            # We have inferred TCP sequence gaps / retransmissions
            overall_expected = self.total_received + self.total_tcp_sequence_gaps
            overall_lost = self.total_tcp_sequence_gaps
            overall_loss_pct = round((overall_lost / float(overall_expected)) * 100.0, 2)
            overall_status = LossMeasurementStatus.INFERRED
        elif self.total_received > 0:
            # No sequence gaps observed
            overall_expected = self.total_received
            overall_lost = 0
            overall_loss_pct = 0.0
            overall_status = LossMeasurementStatus.CONFIRMED

        vol_expected = (self.total_bytes + missing_bytes_est) if overall_expected else None

        # Build timeline trend (loss rate per interval)
        sorted_bins = sorted(self.time_bins.keys())
        timeline_trend = []
        for b_idx in sorted_bins:
            b_data = self.time_bins[b_idx]
            b_ts = b_data["bin_start"]
            b_pkts = b_data["packets"]
            b_retrans = b_data["tcp_retrans"]
            b_gaps = b_data.get("tcp_gaps", 0) + b_data.get("udp_lost", 0)
            b_loss_pct = round((b_gaps / float(b_pkts + b_gaps)) * 100.0, 2) if (b_pkts + b_gaps) > 0 else 0.0
            timeline_trend.append({
                "time": f"{int(b_ts // 60):02d}:{int(b_ts % 60):02d}",
                "timestamp": b_ts,
                "packets_received": b_pkts,
                "bytes_received": b_data["bytes"],
                "lost_packets": b_gaps,
                "retransmissions": b_retrans,
                "loss_percentage": b_loss_pct,
            })

        # Generate Data Loss Alerts
        alerts = []
        if overall_loss_pct is not None and overall_loss_pct >= 5.0:
            alerts.append({
                "severity": "CRITICAL" if overall_loss_pct >= 15.0 else "HIGH",
                "title": f"Elevated Network Packet Loss ({overall_loss_pct}%)",
                "detail": (
                    f"Packet loss exceeds defensive threshold. {overall_lost} packets lost out of "
                    f"{overall_expected} expected. Est. missing volume: {missing_bytes_est} bytes."
                ),
                "timestamp": self.last_ts or time.time(),
            })

        if tcp_count > 0 and (self.total_tcp_retransmissions >= 5 or self.total_tcp_sequence_gaps > 0):
            retrans_rate = (self.total_tcp_retransmissions / float(tcp_count)) * 100.0
            if retrans_rate >= 15.0:
                alerts.append({
                    "severity": "CRITICAL" if retrans_rate >= 40.0 else "HIGH",
                    "title": f"Elevated TCP Retransmission Rate ({retrans_rate:.1f}%)",
                    "detail": (
                        f"Detected {self.total_tcp_retransmissions} retransmissions in {tcp_count} TCP packets ({retrans_rate:.1f}%). "
                        "Indicates high network latency, packet loss before receiver, or buffer saturation."
                    ),
                    "timestamp": self.last_ts or time.time(),
                })
            elif self.total_tcp_retransmissions >= 5:
                alerts.append({
                    "severity": "MEDIUM",
                    "title": "Abnormal TCP Retransmission Density",
                    "detail": f"Observed {self.total_tcp_retransmissions} retransmission events across TCP flows ({retrans_rate:.1f}%).",
                    "timestamp": self.last_ts or time.time(),
                })

        if self.total_tcp_sequence_gaps > 0:
            alerts.append({
                "severity": "HIGH",
                "title": f"TCP Sequence Gaps Detected ({self.total_tcp_sequence_gaps} gaps)",
                "detail": (
                    f"Identified {self.total_tcp_sequence_gaps} missing sequence intervals accounting for "
                    f"~{self.total_tcp_missing_bytes} bytes of dropped or suppressed stream payload."
                ),
                "timestamp": self.last_ts or time.time(),
            })

        if icmp_loss_pct is not None and icmp_loss_pct >= 20.0:
            alerts.append({
                "severity": "HIGH",
                "title": f"ICMP Reachability Degradation ({icmp_loss_pct}% Unanswered)",
                "detail": f"{self.icmp_echo_requests - self.icmp_echo_replies} echo probes dropped without response.",
                "timestamp": self.last_ts or time.time(),
            })

        return OverallDataLossReport(
            total_packets_expected=overall_expected,
            total_packets_received=self.total_received,
            total_packets_lost=overall_lost,
            overall_loss_percentage=overall_loss_pct,
            data_volume_expected_bytes=vol_expected,
            data_volume_received_bytes=self.total_bytes,
            estimated_missing_bytes=missing_bytes_est,
            measurement_status=overall_status,
            protocols=protocols,
            timeline_loss_trend=timeline_trend,
            data_loss_alerts=alerts,
        )
