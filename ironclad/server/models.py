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
    indicator: str
    type: str
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
    label: str
    role: str
    degree: int = 0
    in_degree: int = 0
    out_degree: int = 0
    bytes_sent: int = 0
    bytes_recv: int = 0
    fan_out_ratio: float = 0.0
    pagerank: float = 0.0
    risk_score: float = 0.0
    is_suspicious: bool = False
    containment_status: str = "NORMAL"


class TopologyLink(BaseModel):
    source: str
    target: str
    weight: int = 0
    packet_count: int = 0
    protocols: List[str] = Field(default_factory=list)
    ports: List[int] = Field(default_factory=list)
    is_anomalous: bool = False


class TopologyResponse(BaseModel):
    nodes: List[TopologyNode]
    links: List[TopologyLink]
    total_nodes: int
    total_links: int


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
    ip: str
    action: str = Field(description="ISOLATE, QUARANTINE, or RELEASE")
    operator: str = "SOC_ANALYST"
    reason: str
    notes: Optional[str] = ""


class HostStatusItem(BaseModel):
    ip: str
    status: str
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
    details: Dict[str, Any] = Field(default_factory=dict)
    result: str


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
