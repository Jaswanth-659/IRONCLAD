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
  ip: string
  label: string
  hostname?: string | null
  role: string
  node_type: string
  is_internal: boolean
  risk_score: number
  classification: string
  is_suspicious: boolean
  degree: number
  in_degree: number
  out_degree: number
  bytes_sent: number
  bytes_recv: number
  total_bytes: number
  packets_sent: number
  packets_recv: number
  total_packets: number
  fan_out_ratio: number
  pagerank: number
  containment_status: string
  protocols: string[]
  connected_hosts: string[]
  subengine_alerts: string[]
  incident_count: number
}

export interface TopologyLink {
  source: string
  target: string
  bytes: number
  weight: number
  packets: number
  packet_count: number
  protocol: string
  protocols: string[]
  src_ports: number[]
  dst_ports: number[]
  ports: number[]
  is_anomalous: boolean
  risk_score: number
  direction: string
  session_id?: string | null
}

export interface TopologyResponse {
  session_id: string
  nodes: TopologyNode[]
  links: TopologyLink[]
  total_nodes: number
  total_links: number
  total_hosts: number
  total_connections: number
  suspicious_hosts: number
  critical_hosts: number
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

export interface ProtocolDataLoss {
  protocol: string
  packets_observed: number
  expected_packets: number | null
  lost_packets: number | null
  retransmissions: number
  sequence_gaps: number
  duplicate_acks: number
  loss_percentage: number | null
  total_bytes: number
  pps: number
  bps: number
  measurement_status: 'CONFIRMED' | 'INFERRED' | 'ESTIMATED' | 'UNAVAILABLE'
  associated_anomalies: string[]
}

export interface DataLossReport {
  session_id: string
  total_packets_expected: number | null
  total_packets_received: number
  total_packets_lost: number | null
  overall_loss_percentage: number | null
  data_volume_expected_bytes: number | null
  data_volume_received_bytes: number
  estimated_missing_bytes: number
  measurement_status: 'CONFIRMED' | 'INFERRED' | 'ESTIMATED' | 'UNAVAILABLE'
  protocols: Record<string, ProtocolDataLoss>
  timeline_loss_trend: Array<{
    timestamp: number
    packets_received: number
    bytes: number
    retransmissions: number
    lost_packets: number
    loss_percentage: number | null
  }>
  data_loss_alerts: Array<{
    severity: string
    protocol: string
    metric: string
    observed: number
    loss_percentage: number
    message: string
  }>
}

export interface DynamicAnomalyFlagItem {
  anomaly_category: string
  observed_value: number
  expected_baseline: number
  current_threshold: number
  deviation_percentage: number
  severity: 'NORMAL' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  confidence: number
  detection_explanation: string
  associated_host: string
  timestamp: number
  protocol: string
  metadata?: Record<string, unknown>
}

export interface DynamicThresholdsData {
  session_id: string
  active_flags: DynamicAnomalyFlagItem[]
  baselines: Record<string, Record<string, number>>
  thresholds: Record<string, Record<string, number>>
  contamination_protection_active: boolean
}

export interface HostRateMetrics {
  host_ip: string
  packets_in: number
  packets_out: number
  bytes_in: number
  bytes_out: number
  total_packets: number
  total_bytes: number
  pps: number
  bps: number
  inbound_pps: number
  outbound_pps: number
  inbound_bps: number
  outbound_bps: number
  active_anomaly: string | null
}

export interface TrafficRatesData {
  session_id: string
  duration_seconds: number
  total_packets: number
  total_bytes: number
  overall_pps: number
  overall_bps: number
  inbound_pps: number
  outbound_pps: number
  inbound_bps: number
  outbound_bps: number
  protocol_rates: Record<string, { packets: number; bytes: number; pps: number; bps: number }>
  host_rates: HostRateMetrics[]
  rate_timeline: Array<{
    timestamp: number
    total_pps: number
    total_bps: number
    inbound_pps: number
    outbound_pps: number
  }>
}

export interface RiskFactorData {
  session_id: string
  overall_risk_score: number
  overall_confidence_score: number
  final_classification: string
  classification_band: string
  primary_signals: Record<string, number>
  subengine_breakdown: SubEngineDetail[]
  data_loss_contribution: number
  traffic_rate_contribution: number
  multi_host_contribution: number
  cross_corroboration_delta: number
  calculation_explanation: string[]
  scoring_metadata: Record<string, unknown>
}

export interface LossControlConfig {
  target_loss_pct: number
  mode: string
  burst_length: number
  target_sources: string[]
  enabled: boolean
  buffer_max_bytes: number
  buffer_retention_sec: number
  out_of_order_wait_ms: number
}

export interface RecoveryRecordItem {
  id?: number
  session_id: string
  seq_num: number
  protocol: string
  src_ip: string
  dst_ip: string
  recovery_method: string
  recovery_latency_ms: number
  validation_status: string
  hash_algorithm: string
  checksum_expected?: string | null
  checksum_actual?: string | null
  payload_bytes: number
  timestamp: number
}

export interface LossEventItem {
  id?: number
  session_id: string
  seq_num: number
  protocol: string
  src_ip: string
  dst_ip: string
  loss_type: string
  detection_timestamp: number
  waiting_window_ms: number
  is_confirmed_loss: number
  payload_bytes: number
  payload_hash?: string | null
}

export interface LossControlMetrics {
  session_id: string
  total_losses_detected: number
  total_recovered_packets: number
  total_unrecovered_packets: number
  pending_losses: number
  recovery_rate_pct: number
  mean_recovery_latency_ms: number
  corrupted_recoveries_rejected: number
  duplicate_recoveries_filtered: number
  buffer_overflow_drops: number
  buffer_utilization_pct: number
  buffer_current_bytes: number
  buffer_max_bytes: number
  sensor_capture_drops: number
  configured_loss_pct: number
  controller_running: boolean
  loss_mode: string
  target_sources: string[]
  database_session?: Record<string, unknown> | null
}
