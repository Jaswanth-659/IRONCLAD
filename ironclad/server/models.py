"""
IRONCLAD API Pydantic Schemas.

Defines strongly-typed request and response schemas for REST endpoints
and WebSocket communication payloads.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class OverviewStats(BaseModel):
    network_security_status: str = "NORMAL"
    total_packets_analysed: int = 0
    total_flows: int = 0
    active_alerts: int = 0
    suspicious_hosts: int = 0
    overall_risk_score: float = 0.0
    final_classification: str = "BENIGN"
    risk_distribution: Dict[str, int] = Field(default_factory=dict)
    timeline: List[Dict[str, Any]] = Field(default_factory=list)
    recent_events: List[Dict[str, Any]] = Field(default_factory=list)


class SubEngineDetail(BaseModel):
    subengine_id: str
    name: str
    parent_engine: str
    risk_score: float
    confidence_score: float
    status: str
    explanation: str
    evidence: Dict[str, Any] = Field(default_factory=dict)


class PrimaryEngineDetail(BaseModel):
    engine_id: str
    name: str
    risk_score: float
    confidence_score: float
    status: str
    escalation: str
    explanation: str
    evidence: Dict[str, Any] = Field(default_factory=dict)
    secondary_investigation_triggered: bool = False
    execution_time_ms: float = 0.0
    subengines: List[SubEngineDetail] = Field(default_factory=list)


class EnginesResponse(BaseModel):
    engines: List[PrimaryEngineDetail]
    overall_risk_score: float
    final_classification: str


class ThreatIntelIndicator(BaseModel):
    id: Optional[int] = None
    indicator: str
    type: str = "IP"
    indicator_type: Optional[str] = None
    threat_type: str
    confidence: float
    source: str
    description: Optional[str] = ""
    first_seen: Optional[str] = ""
    last_seen: Optional[str] = ""


class ThreatIntelResponse(BaseModel):
    indicators: List[ThreatIntelIndicator]
    total_indicators: int
    matched_in_session: int = 0


class TopologyNode(BaseModel):
    id: str
    ip: str = ""
    label: str = ""
    hostname: Optional[str] = None
    role: str = "HOST"
    node_type: str = "HOST"
    is_internal: bool = True
    risk_score: float = 0.0
    classification: str = "NORMAL"
    is_suspicious: bool = False
    degree: int = 0
    in_degree: int = 0
    out_degree: int = 0
    bytes_sent: int = 0
    bytes_recv: int = 0
    total_bytes: int = 0
    packets_sent: int = 0
    packets_recv: int = 0
    total_packets: int = 0
    fan_out_ratio: float = 0.0
    pagerank: float = 0.0
    containment_status: str = "NORMAL"
    protocols: List[str] = Field(default_factory=list)
    connected_hosts: List[str] = Field(default_factory=list)
    subengine_alerts: List[str] = Field(default_factory=list)
    incident_count: int = 0


class TopologyLink(BaseModel):
    source: str
    target: str
    bytes: int = 0
    weight: int = 0
    packets: int = 0
    packet_count: int = 0
    protocol: str = "TCP"
    protocols: List[str] = Field(default_factory=list)
    src_ports: List[int] = Field(default_factory=list)
    dst_ports: List[int] = Field(default_factory=list)
    ports: List[int] = Field(default_factory=list)
    is_anomalous: bool = False
    risk_score: float = 0.0
    direction: str = "outbound"
    session_id: Optional[str] = None


class TopologyResponse(BaseModel):
    session_id: str = ""
    nodes: List[TopologyNode] = Field(default_factory=list)
    links: List[TopologyLink] = Field(default_factory=list)
    total_nodes: int = 0
    total_links: int = 0
    total_hosts: int = 0
    total_connections: int = 0
    suspicious_hosts: int = 0
    critical_hosts: int = 0


class IncidentItem(BaseModel):
    id: int
    session_id: str
    source_ip: str
    destination_ip: str
    protocol: str
    port: int
    triggered_engine: str
    risk_score: float
    severity: str
    classification: str
    description: str
    timestamp: str
    evidence: Dict[str, Any] = Field(default_factory=dict)


class IncidentsResponse(BaseModel):
    incidents: List[IncidentItem]
    total: int


class IncidentDetailResponse(BaseModel):
    incident: IncidentItem
    primary_engine_findings: List[Dict[str, Any]]
    secondary_investigation_results: List[SubEngineDetail]
    mathematical_evidence: Dict[str, Any]
    escalation_history: List[Dict[str, Any]]
    cross_engine_correlation: List[Dict[str, Any]]
    final_decision_explanation: str
    recommended_actions: List[str]


class ContainmentActionRequest(BaseModel):
    ip: Optional[str] = None
    ip_address: Optional[str] = None
    action: str = Field(default="ISOLATE", description="ISOLATE, QUARANTINE, or RELEASE")
    operator: str = "SOC_ANALYST"
    reason: str = ""
    notes: Optional[str] = ""
    session_id: Optional[str] = None


class HostStatusItem(BaseModel):
    ip: str
    ip_address: Optional[str] = None
    hostname: Optional[str] = None
    status: str
    risk_score: float = 0.0
    containment_reason: Optional[str] = None
    contained_by: Optional[str] = None
    contained_at: Optional[str] = None
    released_at: Optional[str] = None
    operator: Optional[str] = None
    reason: Optional[str] = None
    notes: Optional[str] = None


class AuditLogItem(BaseModel):
    id: int
    timestamp: str
    operator: str
    action: str
    target_entity: str
    target: Optional[str] = None
    details: Any = Field(default_factory=dict)
    details_text: Optional[str] = None
    result: str = "SUCCESS"


class UploadResponse(BaseModel):
    task_id: str
    filename: str
    file_size: int
    status: str
    message: str


class AnalysisStatusResponse(BaseModel):
    task_id: str
    status: str
    progress: float
    current_step: str
    overall_risk_score: Optional[float] = None
    final_classification: Optional[str] = None
    total_packets: Optional[int] = None
    total_flows: Optional[int] = None
    unique_hosts: Optional[int] = None
    executive_summary: Optional[str] = None


class DataLossResponse(BaseModel):
    session_id: str = ""
    total_packets_expected: Optional[int] = None
    total_packets_received: int = 0
    total_packets_lost: Optional[int] = None
    overall_loss_percentage: Optional[float] = None
    data_volume_expected_bytes: Optional[int] = None
    data_volume_received_bytes: int = 0
    estimated_missing_bytes: int = 0
    measurement_status: str = "UNAVAILABLE"
    protocols: Dict[str, Any] = Field(default_factory=dict)
    timeline_loss_trend: List[Dict[str, Any]] = Field(default_factory=list)
    data_loss_alerts: List[Dict[str, Any]] = Field(default_factory=list)


class DynamicThresholdsResponse(BaseModel):
    session_id: str = ""
    active_flags: List[Dict[str, Any]] = Field(default_factory=list)
    baselines: Dict[str, Any] = Field(default_factory=dict)
    thresholds: Dict[str, Any] = Field(default_factory=dict)
    contamination_protection_active: bool = True


class TrafficRatesResponse(BaseModel):
    session_id: str = ""
    duration_seconds: float = 0.0
    total_packets: int = 0
    total_bytes: int = 0
    overall_pps: float = 0.0
    overall_bps: float = 0.0
    inbound_pps: float = 0.0
    outbound_pps: float = 0.0
    inbound_bps: float = 0.0
    outbound_bps: float = 0.0
    protocol_rates: Dict[str, Any] = Field(default_factory=dict)
    host_rates: List[Dict[str, Any]] = Field(default_factory=list)
    rate_timeline: List[Dict[str, Any]] = Field(default_factory=list)


class RiskFactorResponse(BaseModel):
    session_id: str = ""
    overall_risk_score: float = 0.0
    overall_confidence_score: float = 0.0
    final_classification: str = "BENIGN"
    classification_band: str = "LOW"
    primary_signals: Dict[str, float] = Field(default_factory=dict)
    subengine_breakdown: List[Dict[str, Any]] = Field(default_factory=list)
    data_loss_contribution: float = 0.0
    traffic_rate_contribution: float = 0.0
    multi_host_contribution: float = 0.0
    cross_corroboration_delta: float = 0.0
    calculation_explanation: List[str] = Field(default_factory=list)
    scoring_metadata: Dict[str, Any] = Field(default_factory=dict)


class IPValidationRequest(BaseModel):
    ip: str


class IPValidationResponse(BaseModel):
    raw_ip: str
    normalized_ip: Optional[str] = None
    is_valid: bool
    regex_matched: bool
    category: str
    is_private: bool
    is_public: bool
    is_loopback: bool
    is_link_local: bool
    is_multicast: bool
    is_reserved: bool
    error_reason: Optional[str] = None
