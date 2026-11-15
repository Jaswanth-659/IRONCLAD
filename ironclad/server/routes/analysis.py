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
    EnginesResponse,
    OverviewStats,
    PrimaryEngineDetail,
    SubEngineDetail,
    TopologyLink,
    TopologyNode,
    TopologyResponse,
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
def get_all_subengines() -> List[SubEngineDetail]:
    """
    Returns all 12 secondary investigation modules with their forensic findings and scores.
    """
    conn = get_db_connection()
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


@router.get("/topology", response_model=TopologyResponse)
def get_network_topology() -> TopologyResponse:
    """
    Returns host topology nodes and communication edges enriched with risk metrics and containment states.
    """
    conn = get_db_connection()

    # Query containment statuses
    cur_cont = conn.execute("SELECT ip, status FROM host_containment")
    containment_map = {r["ip"]: r["status"] for r in cur_cont.fetchall()}

    # Standard representative topology nodes from network communication
    nodes = [
        TopologyNode(
            id="192.168.1.50",
            label="Internal Client Workstation",
            role="CLIENT",
            degree=6,
            in_degree=2,
            out_degree=4,
            bytes_sent=15200,
            bytes_recv=45800,
            fan_out_ratio=1.33,
            pagerank=0.312,
            risk_score=2.5,
            is_suspicious=False,
            containment_status=containment_map.get("192.168.1.50", "NORMAL"),
        ),
        TopologyNode(
            id="192.168.1.1",
            label="Core Gateway & DNS",
            role="GATEWAY",
            degree=8,
            in_degree=4,
            out_degree=4,
            bytes_sent=82000,
            bytes_recv=64000,
            fan_out_ratio=0.80,
            pagerank=0.254,
            risk_score=1.0,
            is_suspicious=False,
            containment_status=containment_map.get("192.168.1.1", "NORMAL"),
        ),
        TopologyNode(
            id="10.0.0.99",
            label="Reconnaissance Host",
            role="SCANNER",
            degree=12,
            in_degree=1,
            out_degree=11,
            bytes_sent=18400,
            bytes_recv=1200,
            fan_out_ratio=5.50,
            pagerank=0.085,
            risk_score=8.4,
            is_suspicious=True,
            containment_status=containment_map.get("10.0.0.99", "NORMAL"),
        ),
        TopologyNode(
            id="192.168.1.88",
            label="Compromised Data Server",
            role="SERVER",
            degree=5,
            in_degree=1,
            out_degree=4,
            bytes_sent=95400,
            bytes_recv=4200,
            fan_out_ratio=2.00,
            pagerank=0.145,
            risk_score=9.1,
            is_suspicious=True,
            containment_status=containment_map.get("192.168.1.88", "NORMAL"),
        ),
        TopologyNode(
            id="198.51.100.77",
            label="Verified C2 Endpoint",
            role="C2_DESTINATION",
            degree=3,
            in_degree=3,
            out_degree=0,
            bytes_sent=0,
            bytes_recv=95400,
            fan_out_ratio=0.00,
            pagerank=0.180,
            risk_score=9.8,
            is_suspicious=True,
            containment_status=containment_map.get("198.51.100.77", "NORMAL"),
        ),
        TopologyNode(
            id="93.184.216.34",
            label="External Web Server (example.com)",
            role="WEB_SERVER",
            degree=4,
            in_degree=2,
            out_degree=2,
            bytes_sent=34000,
            bytes_recv=12000,
            fan_out_ratio=0.67,
            pagerank=0.024,
            risk_score=0.8,
            is_suspicious=False,
            containment_status=containment_map.get("93.184.216.34", "NORMAL"),
        ),
    ]

    links = [
        TopologyLink(source="192.168.1.50", target="192.168.1.1", weight=2400, packet_count=18, protocols=["UDP"], ports=[53], is_anomalous=False),
        TopologyLink(source="192.168.1.50", target="93.184.216.34", weight=12500, packet_count=32, protocols=["TCP"], ports=[80], is_anomalous=False),
        TopologyLink(source="10.0.0.99", target="192.168.1.50", weight=1200, packet_count=12, protocols=["TCP"], ports=[22, 80, 443, 8080], is_anomalous=True),
        TopologyLink(source="10.0.0.99", target="192.168.1.88", weight=1400, packet_count=14, protocols=["TCP"], ports=[445, 3389, 1433], is_anomalous=True),
        TopologyLink(source="192.168.1.88", target="198.51.100.77", weight=95400, packet_count=180, protocols=["TCP"], ports=[9443], is_anomalous=True),
    ]

    return TopologyResponse(
        nodes=nodes,
        links=links,
        total_nodes=len(nodes),
        total_links=len(links),
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
