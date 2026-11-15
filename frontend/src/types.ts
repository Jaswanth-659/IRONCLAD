// Shared TypeScript types for IRONCLAD SOC Dashboard

export interface OverviewStats {
  security_status: string
  total_packets: number
  total_flows: number
  active_alerts: number
  suspicious_hosts: number
  overall_risk_score: number
  final_classification: string
  risk_distribution: { CRITICAL: number; HIGH: number; MEDIUM: number; LOW: number }
  traffic_timeline: TimelinePoint[]
  recent_events: RecentEvent[]
}

export interface TimelinePoint {
  time: string
  throughput_kb: number
  risk_index: number
  packets: number
}

export interface RecentEvent {
  id: number
  timestamp: string
  triggered_engine: string
  severity: string
  description: string
  source_ip: string
  destination_ip: string
}

export interface PrimaryEngineDetail {
  engine_id: string
  name: string
  risk_score: number
  confidence_score: number
  status: string
  escalation: string
  explanation: string
  evidence: Record<string, unknown>
  execution_time_ms: number
}

export interface SubEngineDetail {
  subengine_id: string
  name: string
  parent_engine: string
  risk_score: number
  confidence_score: number
  status: string
  explanation: string
  evidence: Record<string, unknown>
}

export interface Incident {
  id: number
  session_id: string
  timestamp: string
  source_ip: string
  destination_ip: string
  protocol: string
  port: number
  triggered_engine: string
  risk_score: number
  severity: string
  classification: string
  description: string
  evidence: Record<string, unknown>
}

export interface IncidentDetail {
  incident: Incident
  primary_engine_findings: Array<Record<string, unknown>>
  secondary_investigation_results: SubEngineDetail[]
  mathematical_evidence: Record<string, unknown>
  escalation_history: Array<{ stage: string; level: string; timestamp: string; detail: string }>
  cross_engine_correlation: Array<{ engine: string; signal: string; correlation_weight: number }>
  final_decision_explanation: string
  recommended_actions: string[]
}

export interface ThreatIndicator {
  id: number
  indicator: string
  indicator_type: string
  threat_type: string
  confidence: number
  source: string
  last_seen: string
  tags: string[]
}

export interface TopologyNode {
  id: string
  label: string
  ip: string
  node_type: string
  risk_score: number
  total_bytes: number
  total_packets: number
}

export interface TopologyLink {
  source: string
  target: string
  bytes: number
  packets: number
  risk_score: number
}

export interface ContainmentHost {
  id: number
  ip_address: string
  hostname: string
  status: string
  risk_score: number
  containment_reason: string
  contained_at: string | null
  contained_by: string | null
}

export interface AuditLog {
  id: number
  timestamp: string
  operator: string
  action: string
  target: string
  details: string
  session_id: string
}
