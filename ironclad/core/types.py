"""
IRONCLAD Core Types and Data Models.

Defines strongly-typed dataclasses and enums representing network telemetry primitives,
flows, graph properties, anomaly metrics, and risk assessments.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, IntEnum
from typing import Any, Dict, List, Optional, Tuple


class Protocol(IntEnum):
    """IP Protocol Numbers (RFC 790 / IANA)."""
    HOPOPT = 0
    ICMP = 1
    IGMP = 2
    GGP = 3
    IPv4 = 4
    ST = 5
    TCP = 6
    CBT = 7
    EGP = 8
    IGP = 9
    BBN_RCC_MON = 10
    NVP_II = 11
    PUP = 12
    ARGUS = 13
    EMCON = 14
    XNET = 15
    CHAOS = 16
    UDP = 17
    MUX = 18
    DCN_MEAS = 19
    HMP = 20
    PRM = 21
    XNS_IDP = 22
    TRUNK_1 = 23
    TRUNK_2 = 24
    LEAF_1 = 25
    LEAF_2 = 26
    RDP = 27
    IRTP = 28
    ISO_TP4 = 29
    NETBLT = 30
    MFE_NSP = 31
    MERIT_INP = 32
    DCCP = 33
    IPv6 = 41
    GRE = 47
    ESP = 50
    AH = 51
    ICMPv6 = 58
    EIGRP = 88
    OSPF = 89
    SCTP = 132
    RAW = 255
    UNKNOWN = -1

    @classmethod
    def from_int(cls, value: int) -> Protocol:
        try:
            return cls(value)
        except ValueError:
            return cls.UNKNOWN


class RiskSeverity(str, Enum):
    """Normalized Risk Severity Categorization."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True, slots=True)
class PacketSummary:
    """
    Normalized metadata for a single dissected packet.
    """
    timestamp: float
    length: int
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Protocol = Protocol.UNKNOWN
    protocol_name: str = "UNKNOWN"
    tcp_flags: Optional[Dict[str, bool]] = None
    payload_length: int = 0
    payload_entropy: float = 0.0
    payload_preview: Optional[bytes] = None
    raw_packet_index: int = 0


@dataclass(frozen=True, slots=True)
class FlowKey:
    """
    5-tuple identifier uniquely specifying a network communication channel.
    """
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: Protocol

    def reversed(self) -> FlowKey:
        """Return the reverse direction of this flow key."""
        return FlowKey(
            src_ip=self.dst_ip,
            dst_ip=self.src_ip,
            src_port=self.dst_port,
            dst_port=self.src_port,
            protocol=self.protocol
        )

    def to_canonical_tuple(self) -> Tuple[str, str, int, int, int]:
        """
        Direction-agnostic representation so forward and backward packets
        belonging to the same session map to identical canonical keys.
        """
        endpoints = sorted([(self.src_ip, self.src_port), (self.dst_ip, self.dst_port)])
        return (
            endpoints[0][0],
            endpoints[1][0],
            endpoints[0][1],
            endpoints[1][1],
            int(self.protocol),
        )


@dataclass
class FlowRecord:
    """
    Aggregated statistical summary of a bidirectional or unidirectional network flow.
    """
    key: FlowKey
    canonical_id: str
    start_time: float
    end_time: float
    packet_count: int = 0
    byte_count: int = 0
    forward_packets: int = 0
    backward_packets: int = 0
    forward_bytes: int = 0
    backward_bytes: int = 0
    packet_lengths: List[int] = field(default_factory=list)
    inter_arrival_times: List[float] = field(default_factory=list)
    tcp_flags: Dict[str, int] = field(default_factory=lambda: {
        "SYN": 0, "ACK": 0, "FIN": 0, "RST": 0, "PSH": 0, "URG": 0
    })
    payload_entropies: List[float] = field(default_factory=list)

    @property
    def duration(self) -> float:
        """Flow duration in seconds."""
        return max(0.0, self.end_time - self.start_time)

    @property
    def packets_per_second(self) -> float:
        """Average packet throughput."""
        dur = self.duration
        return self.packet_count / dur if dur > 0 else float(self.packet_count)

    @property
    def bytes_per_second(self) -> float:
        """Average byte throughput."""
        dur = self.duration
        return self.byte_count / dur if dur > 0 else float(self.byte_count)

    @property
    def mean_packet_length(self) -> float:
        """Average packet size in bytes."""
        return sum(self.packet_lengths) / len(self.packet_lengths) if self.packet_lengths else 0.0

    @property
    def mean_inter_arrival_time(self) -> float:
        """Average time between consecutive packets in seconds."""
        return (
            sum(self.inter_arrival_times) / len(self.inter_arrival_times)
            if self.inter_arrival_times else 0.0
        )

    @property
    def mean_payload_entropy(self) -> float:
        """Average Shannon entropy of flow payload segments (0.0 to 8.0)."""
        return (
            sum(self.payload_entropies) / len(self.payload_entropies)
            if self.payload_entropies else 0.0
        )


@dataclass
class AnomalyScore:
    """
    Evaluation output produced by an anomaly detection estimator.
    """
    detector: str
    is_anomaly: bool
    score: float  # Normalized anomaly severity [0.0, 1.0]
    confidence: float  # Model confidence [0.0, 1.0]
    metrics: Dict[str, float] = field(default_factory=dict)
    explanation: str = ""


@dataclass
class GraphNodeMetrics:
    """
    Network topology metrics computed for an individual host/IP address.
    """
    ip: str
    degree: int = 0
    in_degree: int = 0
    out_degree: int = 0
    degree_centrality: float = 0.0
    in_degree_centrality: float = 0.0
    out_degree_centrality: float = 0.0
    pagerank: float = 0.0
    clustering_coefficient: float = 0.0
    fan_out_ratio: float = 0.0  # out_degree / (in_degree + 1)
    total_bytes_sent: int = 0
    total_bytes_received: int = 0
    unique_peers: int = 0


@dataclass
class RiskFinding:
    """
    Actionable security finding generated by heuristic or statistical rules.
    """
    rule_id: str
    rule_name: str
    severity: RiskSeverity
    score_impact: float
    description: str
    target_entity: str
    evidence: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RiskScore:
    """
    Composite risk evaluation for an entity (flow, host, or overall network capture).
    """
    entity_id: str
    score: float  # Composite risk score [0.0, 100.0]
    severity: RiskSeverity
    findings: List[RiskFinding] = field(default_factory=list)
    breakdown: Dict[str, float] = field(default_factory=dict)


@dataclass
class AnalysisReport:
    """
    Complete telemetry and security audit produced by the IRONCLAD analysis engine.
    """
    capture_source: str
    total_packets: int
    total_bytes: int
    capture_duration: float
    flow_count: int
    unique_hosts: int
    anomalous_flows: List[Tuple[FlowRecord, AnomalyScore]] = field(default_factory=list)
    host_metrics: Dict[str, GraphNodeMetrics] = field(default_factory=dict)
    risk_scores: Dict[str, RiskScore] = field(default_factory=dict)
    global_risk: RiskScore = field(default_factory=lambda: RiskScore("GLOBAL", 0.0, RiskSeverity.LOW))
    execution_time_seconds: float = 0.0
