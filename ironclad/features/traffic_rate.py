"""
IRONCLAD Continuous Traffic-Rate Analysis and Rate Anomaly Engine.

Tracks high-resolution temporal rate dynamics:
- Overall PPS (Packets per second) and BPS (Bytes per second)
- Inbound vs Outbound directional transfer rates
- Per-Host traffic rates and velocity
- Per-Protocol traffic throughput (TCP, UDP, ICMP, etc.)
- Dynamic baseline evaluation with alert hysteresis to prevent flickering
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from ironclad.core.types import PacketSummary
from ironclad.stats.dynamic_thresholds import (
    AnomalyCategory,
    DynamicAnomalyFlag,
    FlagSeverity,
    dynamic_threshold_manager,
)


@dataclass
class HostRateMetrics:
    """Real-time traffic velocity for an individual host."""
    host_ip: str
    packets_in: int = 0
    packets_out: int = 0
    bytes_in: int = 0
    bytes_out: int = 0
    total_packets: int = 0
    total_bytes: int = 0
    pps: float = 0.0
    bps: float = 0.0
    inbound_pps: float = 0.0
    outbound_pps: float = 0.0
    inbound_bps: float = 0.0
    outbound_bps: float = 0.0
    active_anomaly: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "host_ip": self.host_ip,
            "packets_in": self.packets_in,
            "packets_out": self.packets_out,
            "bytes_in": self.bytes_in,
            "bytes_out": self.bytes_out,
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "pps": round(self.pps, 2),
            "bps": round(self.bps, 2),
            "inbound_pps": round(self.inbound_pps, 2),
            "outbound_pps": round(self.outbound_pps, 2),
            "inbound_bps": round(self.inbound_bps, 2),
            "outbound_bps": round(self.outbound_bps, 2),
            "active_anomaly": self.active_anomaly,
        }


@dataclass
class TrafficRateReport:
    """Comprehensive traffic rate snapshot."""
    duration_seconds: float
    total_packets: int
    total_bytes: int
    overall_pps: float
    overall_bps: float
    inbound_pps: float
    outbound_pps: float
    inbound_bps: float
    outbound_bps: float
    protocol_rates: Dict[str, Dict[str, float]]
    host_rates: List[HostRateMetrics]
    rate_timeline: List[Dict[str, Any]]
    rate_flags: List[DynamicAnomalyFlag]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "duration_seconds": round(self.duration_seconds, 3),
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "overall_pps": round(self.overall_pps, 2),
            "overall_bps": round(self.overall_bps, 2),
            "inbound_pps": round(self.inbound_pps, 2),
            "outbound_pps": round(self.outbound_pps, 2),
            "inbound_bps": round(self.inbound_bps, 2),
            "outbound_bps": round(self.outbound_bps, 2),
            "protocol_rates": self.protocol_rates,
            "host_rates": [h.to_dict() for h in self.host_rates],
            "rate_timeline": self.rate_timeline,
            "rate_flags": [f.to_dict() for f in self.rate_flags],
        }


class TrafficRateMonitor:
    """
    Analyzes packet rates over sliding time intervals, evaluates adaptive dynamic thresholds,
    and maintains alert hysteresis state.
    """

    def __init__(
        self,
        monitored_host: str = "192.168.1.10",
        bin_size_seconds: float = 1.0,
        hysteresis_clear_ratio: float = 0.85,
    ) -> None:
        self.monitored_host = monitored_host
        self.bin_size_seconds = bin_size_seconds
        self.hysteresis_clear_ratio = hysteresis_clear_ratio
        self.reset()

    def reset(self) -> None:
        self.first_ts: Optional[float] = None
        self.last_ts: Optional[float] = None
        self.total_packets = 0
        self.total_bytes = 0

        self.inbound_packets = 0
        self.outbound_packets = 0
        self.inbound_bytes = 0
        self.outbound_bytes = 0

        # Host tracking: host_ip -> stats
        self.host_stats: Dict[str, Dict[str, int]] = {}

        # Protocol tracking: proto -> {"pkts": N, "bytes": M}
        self.proto_stats: Dict[str, Dict[str, int]] = {}

        # Time bins: bin_idx -> {pkts, bytes, in_pkts, out_pkts}
        self.time_bins: Dict[int, Dict[str, Any]] = {}

        # Active alert hysteresis state: key -> flag
        self.active_alert_states: Dict[str, DynamicAnomalyFlag] = {}

    def ingest_packet(self, pkt: PacketSummary) -> None:
        ts = pkt.timestamp
        length = pkt.length
        src = pkt.src_ip
        dst = pkt.dst_ip
        proto = pkt.protocol_name.upper()

        self.total_packets += 1
        self.total_bytes += length

        if self.first_ts is None:
            self.first_ts = ts
        self.last_ts = max(self.last_ts or ts, ts)

        # Direction relative to monitored host
        is_inbound = (dst == self.monitored_host)
        is_outbound = (src == self.monitored_host)

        if is_inbound:
            self.inbound_packets += 1
            self.inbound_bytes += length
        elif is_outbound:
            self.outbound_packets += 1
            self.outbound_bytes += length
        else:
            # Default directional heuristic: external to internal
            self.inbound_packets += 1
            self.inbound_bytes += length

        # Update host stats
        for h, role in [(src, "out"), (dst, "in")]:
            hs = self.host_stats.setdefault(h, {
                "packets_in": 0, "packets_out": 0, "bytes_in": 0, "bytes_out": 0
            })
            if role == "out":
                hs["packets_out"] += 1
                hs["bytes_out"] += length
            else:
                hs["packets_in"] += 1
                hs["bytes_in"] += length

        # Protocol stats
        ps = self.proto_stats.setdefault(proto, {"packets": 0, "bytes": 0})
        ps["packets"] += 1
        ps["bytes"] += length

        # Time bin
        bin_idx = int(ts / self.bin_size_seconds) if self.bin_size_seconds > 0 else 0
        b = self.time_bins.setdefault(bin_idx, {
            "bin_start": bin_idx * self.bin_size_seconds,
            "packets": 0,
            "bytes": 0,
            "inbound_packets": 0,
            "outbound_packets": 0,
            "inbound_bytes": 0,
            "outbound_bytes": 0,
        })
        b["packets"] += 1
        b["bytes"] += length
        if is_inbound:
            b["inbound_packets"] += 1
            b["inbound_bytes"] += length
        else:
            b["outbound_packets"] += 1
            b["outbound_bytes"] += length

    def generate_report(self) -> TrafficRateReport:
        duration = max(0.001, (self.last_ts or 0.0) - (self.first_ts or 0.0))

        overall_pps = self.total_packets / duration
        overall_bps = self.total_bytes / duration
        in_pps = self.inbound_packets / duration
        out_pps = self.outbound_packets / duration
        in_bps = self.inbound_bytes / duration
        out_bps = self.outbound_bytes / duration

        # Protocol rates
        protocol_rates = {}
        for proto, stats in self.proto_stats.items():
            protocol_rates[proto] = {
                "packets": stats["packets"],
                "bytes": stats["bytes"],
                "pps": round(stats["packets"] / duration, 2),
                "bps": round(stats["bytes"] / duration, 2),
            }

        # Host rate metrics and dynamic flag evaluation
        host_metrics_list = []
        rate_flags: List[DynamicAnomalyFlag] = []

        for host, st in self.host_stats.items():
            tot_p = st["packets_in"] + st["packets_out"]
            tot_b = st["bytes_in"] + st["bytes_out"]
            h_pps = tot_p / duration
            h_bps = tot_b / duration
            h_in_pps = st["packets_in"] / duration
            h_out_pps = st["packets_out"] / duration
            h_in_bps = st["bytes_in"] / duration
            h_out_bps = st["bytes_out"] / duration

            # Evaluate with dynamic threshold manager
            flag = dynamic_threshold_manager.evaluate(
                category=AnomalyCategory.PACKET_RATE,
                observed_value=h_pps,
                host=host,
                timestamp=self.last_ts or 0.0,
                context_detail=f"Throughput {h_bps:.1f} BPS",
            )

            active_anom = None
            if flag.severity != FlagSeverity.NORMAL:
                active_anom = f"{flag.severity.value}: {flag.deviation_percentage:+.1f}% vs baseline"
                rate_flags.append(flag)
                self.active_alert_states[host] = flag
            else:
                # Check hysteresis: clear only if below threshold * hysteresis_clear_ratio
                if host in self.active_alert_states:
                    prev_flag = self.active_alert_states[host]
                    clear_threshold = prev_flag.current_threshold * self.hysteresis_clear_ratio
                    if h_pps < clear_threshold:
                        del self.active_alert_states[host]
                    else:
                        # Retain alert state under hysteresis
                        active_anom = f"HYSTERESIS_RETAINED ({h_pps:.1f} PPS)"

            hm = HostRateMetrics(
                host_ip=host,
                packets_in=st["packets_in"],
                packets_out=st["packets_out"],
                bytes_in=st["bytes_in"],
                bytes_out=st["bytes_out"],
                total_packets=tot_p,
                total_bytes=tot_b,
                pps=h_pps,
                bps=h_bps,
                inbound_pps=h_in_pps,
                outbound_pps=h_out_pps,
                inbound_bps=h_in_bps,
                outbound_bps=h_out_bps,
                active_anomaly=active_anom,
            )
            host_metrics_list.append(hm)

        # Sort hosts by total throughput descending
        host_metrics_list.sort(key=lambda x: x.total_bytes, reverse=True)

        # Timeline trend
        sorted_bins = sorted(self.time_bins.keys())
        timeline = []
        for b_idx in sorted_bins:
            b = self.time_bins[b_idx]
            b_ts = b["bin_start"]
            bin_dur = max(0.001, self.bin_size_seconds)
            timeline.append({
                "time": f"{int(b_ts // 60):02d}:{int(b_ts % 60):02d}",
                "timestamp": b_ts,
                "pps": round(b["packets"] / bin_dur, 2),
                "bps": round(b["bytes"] / bin_dur, 2),
                "inbound_pps": round(b["inbound_packets"] / bin_dur, 2),
                "outbound_pps": round(b["outbound_packets"] / bin_dur, 2),
                "packets": b["packets"],
                "bytes": b["bytes"],
            })

        return TrafficRateReport(
            duration_seconds=duration,
            total_packets=self.total_packets,
            total_bytes=self.total_bytes,
            overall_pps=overall_pps,
            overall_bps=overall_bps,
            inbound_pps=in_pps,
            outbound_pps=out_pps,
            inbound_bps=in_bps,
            outbound_bps=out_bps,
            protocol_rates=protocol_rates,
            host_rates=host_metrics_list,
            rate_timeline=timeline,
            rate_flags=rate_flags,
        )
