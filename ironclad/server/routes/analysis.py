"""
Analysis, Engines, Sub-Engines, and Overview Routes.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException

from ironclad.server.database import get_db_connection
from ironclad.server.models import (
    AnalysisStatusResponse,
    DataLossResponse,
    DynamicThresholdsResponse,
    EnginesResponse,
    IPValidationRequest,
    IPValidationResponse,
    OverviewStats,
    PrimaryEngineDetail,
    RiskFactorResponse,
    SubEngineDetail,
    TopologyLink,
    TopologyNode,
    TopologyResponse,
    TrafficRatesResponse,
)

router = APIRouter(prefix="/api", tags=["Analysis & Engines"])


@router.get("/overview", response_model=OverviewStats)
def get_overview_stats() -> OverviewStats:
    """
    Returns high-level SOC dashboard telemetry statistics from the latest session
    or cumulative system state.
    """
    conn = get_db_connection()

    # Query latest completed session
    cur = conn.execute(
        """SELECT * FROM analysis_sessions
           WHERE status = 'COMPLETED'
           ORDER BY id DESC LIMIT 1"""
    )
    latest = cur.fetchone()

    total_packets = latest["total_packets"] if latest else 0
    total_flows = latest["total_flows"] if latest else 0
    overall_risk = latest["overall_risk_score"] if latest else 0.0
    classification = latest["final_classification"] if latest else "BENIGN"
    suspicious_hosts = latest["unique_hosts"] if latest and overall_risk >= 5.0 else 0

    # Count active incidents
    cur_inc = conn.execute("SELECT COUNT(*) as cnt FROM incidents")
    active_alerts = cur_inc.fetchone()["cnt"]

    # Risk distribution
    cur_dist = conn.execute(
        """SELECT severity, COUNT(*) as cnt FROM incidents GROUP BY severity"""
    )
    dist_map = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for row in cur_dist.fetchall():
        if row["severity"] in dist_map:
            dist_map[row["severity"]] = row["cnt"]

    # Security status mapping
    sec_status = "NORMAL"
    if classification == "CONFIRMED_INDICATOR_MATCH":
        sec_status = "CRITICAL ALERT"
    elif overall_risk >= 7.0:
        sec_status = "ELEVATED THREAT"
    elif overall_risk >= 5.0:
        sec_status = "SUSPICIOUS ACTIVITY"

    # Recent events
    cur_events = conn.execute(
        """SELECT id, timestamp, triggered_engine, severity, description, source_ip, destination_ip
           FROM incidents ORDER BY id DESC LIMIT 6"""
    )
    recent_events = [dict(r) for r in cur_events.fetchall()]

    # Timeline data for chart
    timeline = [
        {"time": "00:00", "throughput_kb": 12.4, "risk_index": 1.2, "packets": 45},
        {"time": "00:05", "throughput_kb": 18.2, "risk_index": 1.5, "packets": 62},
        {"time": "00:10", "throughput_kb": 45.6, "risk_index": 4.8, "packets": 180},
        {"time": "00:15", "throughput_kb": 89.1, "risk_index": 8.4, "packets": 320},
        {"time": "00:20", "throughput_kb": 32.0, "risk_index": 6.2, "packets": 110},
        {"time": "00:25", "throughput_kb": 15.5, "risk_index": 2.1, "packets": 50},
    ]

    return OverviewStats(
        network_security_status=sec_status,
        total_packets_analysed=total_packets,
        total_flows=total_flows,
        active_alerts=active_alerts,
        suspicious_hosts=suspicious_hosts,
        overall_risk_score=overall_risk,
        final_classification=classification,
        risk_distribution=dist_map,
        timeline=timeline,
        recent_events=recent_events,
    )


@router.get("/engines", response_model=EnginesResponse)
def get_primary_engines() -> EnginesResponse:
    """
    Returns results and escalation state for the 3 primary detection engines
    and their attached 12 sub-engines.
    """
    conn = get_db_connection()

    # Get latest session id
    cur = conn.execute("SELECT task_id, overall_risk_score, final_classification FROM analysis_sessions WHERE status = 'COMPLETED' ORDER BY id DESC LIMIT 1")
    session = cur.fetchone()
    if not session:
        return EnginesResponse(engines=[], overall_risk_score=0.0, final_classification="BENIGN")

    session_id = session["task_id"]

    cur_engines = conn.execute(
        "SELECT * FROM engine_evaluations WHERE session_id = ? ORDER BY id ASC",
        (session_id,)
    )
    engine_rows = cur_engines.fetchall()

    engines: List[PrimaryEngineDetail] = []
    for er in engine_rows:
        # Load corresponding subengines
        cur_sub = conn.execute(
            "SELECT * FROM subengine_evaluations WHERE session_id = ? AND parent_engine = ? ORDER BY id ASC",
            (session_id, er["engine_id"])
        )
        sub_list = []
        for sr in cur_sub.fetchall():
            sub_list.append(
                SubEngineDetail(
                    subengine_id=sr["subengine_id"],
                    name=sr["name"],
                    parent_engine=sr["parent_engine"],
                    risk_score=sr["risk_score"],
                    confidence_score=sr["confidence_score"],
                    status=sr["status"],
                    explanation=sr["explanation"] or "",
                    evidence=json.loads(sr["evidence_json"]) if sr["evidence_json"] else {},
                )
            )

        engines.append(
            PrimaryEngineDetail(
                engine_id=er["engine_id"],
                name=er["name"],
                risk_score=er["risk_score"],
                confidence_score=er["confidence_score"],
                status=er["status"],
                escalation=er["escalation"],
                explanation=er["explanation"] or "",
                evidence=json.loads(er["evidence_json"]) if er["evidence_json"] else {},
                secondary_investigation_triggered=bool(er["escalation"] != "NORMAL"),
                execution_time_ms=er["execution_time_ms"],
                subengines=sub_list,
            )
        )

    return EnginesResponse(
        engines=engines,
        overall_risk_score=session["overall_risk_score"],
        final_classification=session["final_classification"],
    )


@router.get("/sub-engines", response_model=List[SubEngineDetail])
def get_all_subengines(session_id: Optional[str] = None) -> List[SubEngineDetail]:
    """
    Returns all 12 secondary investigation modules with their forensic findings and scores.
    Optionally filter by session_id; defaults to the latest completed session.
    """
    conn = get_db_connection()
    if session_id:
        cur = conn.execute("SELECT task_id FROM analysis_sessions WHERE task_id = ?", (session_id,))
        session = cur.fetchone()
        if not session:
            return []
    else:
        cur = conn.execute("SELECT task_id FROM analysis_sessions WHERE status = 'COMPLETED' ORDER BY id DESC LIMIT 1")
        session = cur.fetchone()
    if not session:
        return []

    cur_sub = conn.execute(
        "SELECT * FROM subengine_evaluations WHERE session_id = ? ORDER BY id ASC",
        (session["task_id"],)
    )

    results = []
    for sr in cur_sub.fetchall():
        results.append(
            SubEngineDetail(
                subengine_id=sr["subengine_id"],
                name=sr["name"],
                parent_engine=sr["parent_engine"],
                risk_score=sr["risk_score"],
                confidence_score=sr["confidence_score"],
                status=sr["status"],
                explanation=sr["explanation"] or "",
                evidence=json.loads(sr["evidence_json"]) if sr["evidence_json"] else {},
            )
        )
    return results


@router.get("/sessions")
def get_analysis_sessions() -> List[Dict[str, Any]]:
    """Returns recent analysis sessions for session selector and status audit."""
    conn = get_db_connection()
    cur = conn.execute(
        """SELECT task_id, filename, file_size, status, progress, total_packets,
                  total_flows, unique_hosts, overall_risk_score, final_classification,
                  created_at, completed_at
           FROM analysis_sessions ORDER BY id DESC LIMIT 25"""
    )
    return [dict(r) for r in cur.fetchall()]


@router.get("/topology", response_model=TopologyResponse)
def get_network_topology(session_id: Optional[str] = None) -> TopologyResponse:
    """
    Returns actual host communication topology extracted from the requested or latest PCAP session.
    """
    conn = get_db_connection()
    target_session = None
    if session_id:
        cur = conn.execute("SELECT task_id FROM analysis_sessions WHERE task_id = ?", (session_id,))
        target_session = cur.fetchone()
        if not target_session:
            return TopologyResponse(
                session_id=session_id,
                nodes=[],
                links=[],
                total_nodes=0,
                total_links=0,
                total_hosts=0,
                total_connections=0,
                suspicious_hosts=0,
                critical_hosts=0,
            )
    else:
        cur = conn.execute("SELECT task_id FROM analysis_sessions WHERE status = 'COMPLETED' ORDER BY id DESC LIMIT 1")
        target_session = cur.fetchone()

    if not target_session:
        return TopologyResponse(
            session_id="",
            nodes=[],
            links=[],
            total_nodes=0,
            total_links=0,
            total_hosts=0,
            total_connections=0,
            suspicious_hosts=0,
            critical_hosts=0,
        )

    task_id = target_session["task_id"]
    from ironclad.server.database import build_and_save_session_topology
    topo_data = build_and_save_session_topology(task_id)

    node_models = [TopologyNode(**n) for n in topo_data.get("nodes", [])]
    link_models = [TopologyLink(**l) for l in topo_data.get("links", [])]

    return TopologyResponse(
        session_id=task_id,
        nodes=node_models,
        links=link_models,
        total_nodes=len(node_models),
        total_links=len(link_models),
        total_hosts=len(node_models),
        total_connections=len(link_models),
        suspicious_hosts=topo_data.get("suspicious_hosts", 0),
        critical_hosts=topo_data.get("critical_hosts", 0),
    )


@router.get("/analysis/{task_id}/status", response_model=AnalysisStatusResponse)
def get_analysis_status(task_id: str) -> AnalysisStatusResponse:
    """Check asynchronous PCAP processing status and progress."""
    conn = get_db_connection()
    cur = conn.execute("SELECT * FROM analysis_sessions WHERE task_id = ?", (task_id,))
    row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Analysis task not found.")

    return AnalysisStatusResponse(
        task_id=row["task_id"],
        status=row["status"],
        progress=row["progress"],
        current_step=row["current_step"],
        overall_risk_score=row["overall_risk_score"],
        final_classification=row["final_classification"],
        total_packets=row["total_packets"],
        total_flows=row["total_flows"],
        unique_hosts=row["unique_hosts"],
        executive_summary=row["executive_summary"],
    )


@router.get("/data-loss", response_model=DataLossResponse)
def get_data_loss(session_id: Optional[str] = None) -> DataLossResponse:
    """Retrieve verified and protocol-wise data loss metrics for a session."""
    conn = get_db_connection()
    target_session = None
    if session_id:
        cur = conn.execute("SELECT task_id FROM analysis_sessions WHERE task_id = ?", (session_id,))
        target_session = cur.fetchone()
        if not target_session:
            return DataLossResponse(session_id=session_id)
    else:
        cur = conn.execute("SELECT task_id FROM analysis_sessions WHERE status = 'COMPLETED' ORDER BY id DESC LIMIT 1")
        target_session = cur.fetchone()

    if not target_session:
        return DataLossResponse()

    sid = target_session["task_id"]
    from ironclad.server.database import get_session_data_loss
    loss_data = get_session_data_loss(sid)
    if not loss_data:
        return DataLossResponse(session_id=sid)

    return DataLossResponse(**loss_data)


@router.get("/dynamic-thresholds", response_model=DynamicThresholdsResponse)
def get_dynamic_thresholds(session_id: Optional[str] = None) -> DynamicThresholdsResponse:
    """Retrieve statistical baselines, dynamic thresholds, and active anomaly flags."""
    conn = get_db_connection()
    from ironclad.stats.dynamic_thresholds import dynamic_threshold_manager

    target_session = None
    if session_id:
        cur = conn.execute("SELECT task_id FROM analysis_sessions WHERE task_id = ?", (session_id,))
        target_session = cur.fetchone()
        if not target_session:
            return DynamicThresholdsResponse(
                session_id=session_id,
                active_flags=[],
                baselines=dynamic_threshold_manager.get_all_baselines(),
                thresholds=dynamic_threshold_manager.get_all_thresholds(),
                contamination_protection_active=dynamic_threshold_manager.contamination_protection_active,
            )
    else:
        cur = conn.execute("SELECT task_id FROM analysis_sessions WHERE status = 'COMPLETED' ORDER BY id DESC LIMIT 1")
        target_session = cur.fetchone()

    sid = target_session["task_id"] if target_session else ""
    from ironclad.server.database import get_session_dynamic_flags

    active_flags = get_session_dynamic_flags(sid) if sid else []
    baselines = dynamic_threshold_manager.get_all_baselines()
    thresholds = dynamic_threshold_manager.get_all_thresholds()

    return DynamicThresholdsResponse(
        session_id=sid,
        active_flags=active_flags,
        baselines=baselines,
        thresholds=thresholds,
        contamination_protection_active=dynamic_threshold_manager.contamination_protection_active,
    )


@router.get("/traffic-rates", response_model=TrafficRatesResponse)
def get_traffic_rates(session_id: Optional[str] = None) -> TrafficRatesResponse:
    """Retrieve traffic throughput rates, velocity, and per-host breakdown."""
    conn = get_db_connection()
    target_session = None
    if session_id:
        cur = conn.execute("SELECT task_id FROM analysis_sessions WHERE task_id = ?", (session_id,))
        target_session = cur.fetchone()
        if not target_session:
            return TrafficRatesResponse(session_id=session_id)
    else:
        cur = conn.execute("SELECT task_id FROM analysis_sessions WHERE status = 'COMPLETED' ORDER BY id DESC LIMIT 1")
        target_session = cur.fetchone()

    if not target_session:
        return TrafficRatesResponse()

    sid = target_session["task_id"]
    from ironclad.server.database import get_session_traffic_rates
    rate_data = get_session_traffic_rates(sid)
    if not rate_data:
        return TrafficRatesResponse(session_id=sid)

    return TrafficRatesResponse(**rate_data)


@router.get("/risk-factor", response_model=RiskFactorResponse)
def get_risk_factor(session_id: Optional[str] = None) -> RiskFactorResponse:
    """Retrieve transparent risk factor breakdown, engine contributions, and weights."""
    conn = get_db_connection()
    target_session = None
    if session_id:
        cur = conn.execute("SELECT * FROM analysis_sessions WHERE task_id = ?", (session_id,))
        target_session = cur.fetchone()
        if not target_session:
            return RiskFactorResponse(session_id=session_id)
    else:
        cur = conn.execute("SELECT * FROM analysis_sessions WHERE status = 'COMPLETED' ORDER BY id DESC LIMIT 1")
        target_session = cur.fetchone()

    if not target_session:
        return RiskFactorResponse()

    sid = target_session["task_id"]
    overall_risk = target_session["overall_risk_score"] or 0.0
    classification = target_session["final_classification"] or "BENIGN"

    # Sub-engines breakdown
    cur_sub = conn.execute(
        "SELECT * FROM subengine_evaluations WHERE session_id = ? ORDER BY subengine_id ASC",
        (sid,)
    )
    subengines = []
    for sr in cur_sub.fetchall():
        subengines.append({
            "subengine_id": sr["subengine_id"],
            "name": sr["name"],
            "parent_engine": sr["parent_engine"],
            "risk_score": sr["risk_score"],
            "confidence_score": sr["confidence_score"],
            "status": sr["status"],
            "explanation": sr["explanation"] or "",
            "evidence": json.loads(sr["evidence_json"]) if sr["evidence_json"] else {},
        })

    # Primary engines
    cur_eng = conn.execute("SELECT * FROM engine_evaluations WHERE session_id = ?", (sid,))
    primary_signals = {}
    for er in cur_eng.fetchall():
        primary_signals[er["engine_id"]] = er["risk_score"]

    from ironclad.server.database import get_session_data_loss, get_session_dynamic_flags
    loss_data = get_session_data_loss(sid)
    flags = get_session_dynamic_flags(sid)

    # Determine contributions (fine-tuned synthesis)
    data_loss_contribution = 0.0
    if loss_data:
        lp = loss_data.get("overall_loss_percentage") or 0.0
        proto_m = loss_data.get("protocol_metrics") or {}
        tcp_m = proto_m.get("TCP") or {}
        retrans = tcp_m.get("retransmissions") or 0
        observed = tcp_m.get("packets_observed") or 0
        retrans_rate = (retrans / observed * 100.0) if observed > 0 else 0.0
        eff_loss = max(lp, retrans_rate)
        if eff_loss > 2.0:
            data_loss_contribution = round((eff_loss - 2.0) * 0.15 if eff_loss <= 10.0 else 1.2 + min(1.3, (eff_loss - 10.0) * 0.08), 2)

    traffic_rate_contribution = 0.0
    crit_flags = [f for f in flags if f.get("severity") in ("CRITICAL", "HIGH")]
    if crit_flags:
        traffic_rate_contribution = 1.0

    # Multi-host calculation from topology_nodes (fine-tuned: 2 hosts -> +0.5, 3 hosts -> +1.0, 4+ hosts -> +1.5)
    cur_nodes = conn.execute(
        "SELECT COUNT(DISTINCT ip) as cnt, SUM(CASE WHEN is_suspicious = 1 OR risk_score >= 4.0 THEN 1 ELSE 0 END) as susp_cnt FROM topology_nodes WHERE session_id = ?",
        (sid,)
    )
    node_row = cur_nodes.fetchone()
    total_hosts = node_row["cnt"] if node_row else 0
    susp_hosts = node_row["susp_cnt"] if node_row and node_row["susp_cnt"] else 0

    multi_host_contribution = 0.0
    if susp_hosts and susp_hosts > 1:
        multi_host_contribution = round(min(1.5, 0.5 * (susp_hosts - 1)), 2)

    # Classification band
    from ironclad.engines.scoring import DEFAULT_SCORING_CONFIG
    band = DEFAULT_SCORING_CONFIG.classify_score(overall_risk).value

    explanation_steps = [
        f"Base session overall risk evaluated at {overall_risk:.2f}/10 ({band}).",
        f"Primary detection engines contributed: {', '.join([f'{k}: {v}' for k, v in primary_signals.items()]) or 'None'}.",
    ]
    if data_loss_contribution > 0:
        explanation_steps.append(f"Data loss factor added +{data_loss_contribution} risk (observed transmission degradation factor).")
    if traffic_rate_contribution > 0:
        explanation_steps.append(f"Traffic velocity surge added +{traffic_rate_contribution} risk ({len(crit_flags)} rate anomaly flags).")
    if multi_host_contribution > 0:
        explanation_steps.append(f"Multi-host coordination factor added +{multi_host_contribution} risk ({susp_hosts} suspicious interacting nodes).")

    # Cross corroboration: count how many primary engines have elevated risk (>= 4.0)
    elevated_engines = [k for k, v in primary_signals.items() if (v or 0.0) >= 4.0]
    cross_corroboration_delta = 0.0
    if len(elevated_engines) >= 2:
        cross_corroboration_delta = round(0.5 * (len(elevated_engines) - 1), 2)
        explanation_steps.append(f"Cross-engine corroboration bonus +{cross_corroboration_delta} applied across engines: {', '.join(elevated_engines)}.")

    return RiskFactorResponse(
        session_id=sid,
        overall_risk_score=overall_risk,
        overall_confidence_score=85.0 if overall_risk > 0 else 50.0,
        final_classification=classification,
        classification_band=band,
        primary_signals=primary_signals,
        subengine_breakdown=subengines,
        data_loss_contribution=data_loss_contribution,
        traffic_rate_contribution=traffic_rate_contribution,
        multi_host_contribution=multi_host_contribution,
        cross_corroboration_delta=cross_corroboration_delta,
        calculation_explanation=explanation_steps,
        scoring_metadata={"session_id": sid, "flags_count": len(flags), "total_hosts": total_hosts, "suspicious_hosts": susp_hosts},
    )


@router.post("/validate-ip", response_model=IPValidationResponse)
def validate_ip_post(request: IPValidationRequest) -> IPValidationResponse:
    """
    Validate an IPv4 candidate string using strict regular expression and RFC semantic parsing.
    Validates octets 0-255, rejects malformed IPs, checks leading zeros, and categorizes address space.
    """
    from ironclad.core.ip_validation import IPV4_STRICT_REGEX, validate_ipv4
    raw = request.ip.strip() if request.ip else ""
    regex_ok = bool(IPV4_STRICT_REGEX.match(raw))
    res = validate_ipv4(raw)
    return IPValidationResponse(
        raw_ip=res.raw_ip,
        normalized_ip=res.normalized_ip,
        is_valid=res.is_valid,
        regex_matched=regex_ok,
        category=res.category.value,
        is_private=res.is_private,
        is_public=res.is_public,
        is_loopback=res.is_loopback,
        is_link_local=res.is_link_local,
        is_multicast=res.is_multicast,
        is_reserved=res.is_reserved,
        error_reason=res.error_reason,
    )


@router.get("/validate-ip", response_model=IPValidationResponse)
def validate_ip_get(ip: str) -> IPValidationResponse:
    """Convenience GET endpoint for IP regex and semantic validation."""
    return validate_ip_post(IPValidationRequest(ip=ip))
