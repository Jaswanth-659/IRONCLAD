"""
IRONCLAD FastAPI Backend Application.

Main server application integrating REST APIs, WebSocket streaming endpoint,
database initialization, and static frontend hosting.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncGenerator

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from ironclad.core.logging import get_logger, setup_logging
from ironclad.server.database import (
    complete_session,
    create_session,
    get_db_connection,
    init_database,
    save_engine_evaluation,
    save_incident,
    save_subengine_evaluation,
)
from ironclad.server.routes import (
    analysis_router,
    containment_router,
    incidents_router,
    loss_control_router,
    threat_intel_router,
    upload_router,
)
from ironclad.server.ws import ws_manager
from scripts.generate_synthetic_pcap import generate_test_pcap

logger = get_logger("server.app")


def seed_initial_demo_session_if_empty() -> None:
    """If database has no analysis sessions, generate an initial audit session."""
    conn = get_db_connection()
    cur = conn.execute("SELECT COUNT(*) as cnt FROM analysis_sessions")
    if cur.fetchone()["cnt"] == 0:
        logger.info("Initializing first-run demo telemetry session in SQLite...")
        task_id = "demo-session-alpha-001"
        filename = "synthetic_enterprise_traffic.pcap"

        # Generate sample PCAP if not exists
        sample_pcap = Path("data/sample_traffic.pcap")
        if not sample_pcap.exists():
            generate_test_pcap(str(sample_pcap))
        file_size = sample_pcap.stat().st_size if sample_pcap.exists() else 65536

        create_session(task_id, filename, file_size)

        # Complete demo session
        complete_session(
            task_id=task_id,
            total_packets=128,
            total_bytes=84200,
            total_flows=16,
            unique_hosts=7,
            duration_sec=14.8,
            overall_risk_score=8.6,
            final_classification="CONFIRMED_INDICATOR_MATCH",
            executive_summary=(
                "CONFIRMED THREAT MATCH: Host 192.168.1.88 established an encrypted data exfiltration "
                "channel to verified C2 destination 198.51.100.77 on non-standard port 9443 (payload entropy 7.60/8.0). "
                "Simultaneous reconnaissance scanning observed from internal host 10.0.0.99."
            ),
        )

        # Engine evaluations
        save_engine_evaluation(
            session_id=task_id,
            engine_id="ENGINE_1_TEMPORAL",
            name="Temporal Behaviour Engine",
            risk_score=7.4,
            confidence_score=88.0,
            status="CRITICAL",
            escalation="HIGH_PRIORITY_ESCALATION",
            explanation="Detected periodic micro-burst trains with low jitter matching automated exfiltration pulses.",
            evidence={"burstiness_index": 0.74, "mean_iat": 0.18},
            execution_time_ms=42.1,
        )
        save_engine_evaluation(
            session_id=task_id,
            engine_id="ENGINE_2_TRAFFIC",
            name="Traffic Behaviour Engine",
            risk_score=8.5,
            confidence_score=92.0,
            status="CRITICAL",
            escalation="HIGH_PRIORITY_ESCALATION",
            explanation="Extreme directional transfer asymmetry (10:1 outbound byte ratio) with uniform block-cipher padding.",
            evidence={"directional_ratio": 10.2, "byte_count": 55200},
            execution_time_ms=38.4,
        )
        save_engine_evaluation(
            session_id=task_id,
            engine_id="ENGINE_3_CONNECTION",
            name="Connection Behaviour Engine",
            risk_score=9.8,
            confidence_score=98.0,
            status="CRITICAL",
            escalation="HIGH_PRIORITY_ESCALATION",
            explanation="Confirmed indicator match against curated threat feed: Host 198.51.100.77 is verified APT-29 C2.",
            evidence={"confirmed_match": True, "target": "198.51.100.77"},
            execution_time_ms=29.6,
        )

        # Subengine evaluations (12 subengines)
        subengines_demo = [
            ("E1.1", "Periodicity Validator", "ENGINE_1_TEMPORAL", 7.2, 85.0, "CRITICAL", "Flow 192.168.1.88:51200 exhibited strict periodic timing (CV=0.18)."),
            ("E1.2", "Jitter Analyzer", "ENGINE_1_TEMPORAL", 6.8, 82.0, "SUSPICIOUS", "Bounded artificial sleep jitter observed (window ±15%)."),
            ("E1.3", "Burst Pattern Analyzer", "ENGINE_1_TEMPORAL", 8.1, 90.0, "CRITICAL", "High-density micro-burst trains detected (burstiness=0.74)."),
            ("E1.4", "Historical Behaviour Comparator", "ENGINE_1_TEMPORAL", 5.5, 75.0, "SUSPICIOUS", "Distribution diverged from historical baseline (KS stat=0.42)."),
            ("E2.1", "Packet Size Analyzer", "ENGINE_2_TRAFFIC", 7.6, 88.0, "CRITICAL", "Fixed 512-byte block cipher payload padding identified."),
            ("E2.2", "Traffic Volume Analyzer", "ENGINE_2_TRAFFIC", 8.2, 92.0, "CRITICAL", "High volumetric throughput on non-standard port 9443."),
            ("E2.3", "Directional Traffic Analyzer", "ENGINE_2_TRAFFIC", 9.1, 94.0, "CRITICAL", "Severe outbound byte asymmetry (10:1 upload ratio)."),
            ("E2.4", "Burst Detection Analyzer", "ENGINE_2_TRAFFIC", 7.8, 86.0, "CRITICAL", "Rapid volumetric injection pulses (peak 52,000 B/s)."),
            ("E3.1", "Destination Analyzer", "ENGINE_3_CONNECTION", 7.5, 84.0, "CRITICAL", "Internal host 10.0.0.99 swept 11 unique destination endpoints."),
            ("E3.2", "Port and Protocol Analyzer", "ENGINE_3_CONNECTION", 8.4, 90.0, "CRITICAL", "Vertical port scan targeting ports 22, 80, 443, 8080."),
            ("E3.3", "Connection Failure Analyzer", "ENGINE_3_CONNECTION", 8.0, 92.0, "CRITICAL", "Unanswered SYN ratio 15:1 indicative of stealth port sweep."),
            ("E3.4", "Threat Intelligence Checker", "ENGINE_3_CONNECTION", 9.8, 98.0, "CRITICAL", "CONFIRMED INDICATOR MATCH: 198.51.100.77 verified APT-29 C2."),
        ]
        for sid, sname, parent, srisk, sconf, sstat, sexpl in subengines_demo:
            save_subengine_evaluation(
                session_id=task_id,
                subengine_id=sid,
                name=sname,
                parent_engine=parent,
                risk_score=srisk,
                confidence_score=sconf,
                status=sstat,
                explanation=sexpl,
                evidence={"demo": True},
            )

        # Seed incidents
        save_incident(
            session_id=task_id,
            source_ip="192.168.1.88",
            destination_ip="198.51.100.77",
            protocol="TCP",
            port=9443,
            triggered_engine="Connection Behaviour Engine (Threat Intel Checker)",
            risk_score=9.8,
            severity="CRITICAL",
            classification="CONFIRMED_INDICATOR_MATCH",
            description="Communication with verified APT-29 C2 server (198.51.100.77) over high-entropy encrypted tunnel (H=7.60/8.0).",
            evidence={"threat_actor": "APT-29", "category": "C2_SERVER", "dst_port": 9443},
        )
        save_incident(
            session_id=task_id,
            source_ip="10.0.0.99",
            destination_ip="192.168.1.50",
            protocol="TCP",
            port=80,
            triggered_engine="Connection Behaviour Engine (Port and Protocol Analyzer)",
            risk_score=8.4,
            severity="HIGH",
            classification="HIGH_RISK",
            description="Vertical TCP port scanning sweep targeting sensitive management ports.",
            evidence={"ports_targeted": [22, 80, 443, 8080], "syn_ack_ratio": 15.0},
        )
        save_incident(
            session_id=task_id,
            source_ip="192.168.1.88",
            destination_ip="198.51.100.77",
            protocol="TCP",
            port=9443,
            triggered_engine="Traffic Behaviour Engine (Directional Traffic Analyzer)",
            risk_score=8.8,
            severity="HIGH",
            classification="HIGH_RISK",
            description="Abrupt volumetric burst exfiltration: 55,200 bytes transmitted in asymmetric outbound channel.",
            evidence={"directional_ratio": 10.2, "bytes": 55200},
        )


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Startup and shutdown lifecycle manager."""
    setup_logging(level="INFO")
    logger.info("Initializing IRONCLAD Defence Engine Backend...")
    init_database()
    seed_initial_demo_session_if_empty()
    logger.info("IRONCLAD Backend ready to receive telemetry.")
    yield
    logger.info("Shutting down IRONCLAD Backend.")


app = FastAPI(
    title="IRONCLAD Engine API",
    description="Intelligent Network Telemetry and Cryptographic Defence Engine REST & WebSocket API",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API Routers
app.include_router(upload_router)
app.include_router(analysis_router)
app.include_router(incidents_router)
app.include_router(containment_router)
app.include_router(threat_intel_router)
app.include_router(loss_control_router)


@app.get("/api/health")
def healthcheck() -> JSONResponse:
    """Service health and diagnostics endpoint."""
    return JSONResponse({
        "status": "HEALTHY",
        "service": "IRONCLAD Telemetry & Defence Engine",
        "version": "1.0.0",
        "websocket_active_clients": len(ws_manager.active_connections),
    })


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    """Real-time event streaming WebSocket connection endpoint."""
    await ws_manager.connect(websocket)
    try:
        while True:
            # Keep connection alive; process client pings or queries
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text('{"type": "pong"}')
    except WebSocketDisconnect:
        await ws_manager.disconnect(websocket)
    except Exception as e:
        logger.warning("WebSocket connection exception: %s", e)
        await ws_manager.disconnect(websocket)


# Optional: Mount built React frontend if dist/ exists
frontend_dist = Path("frontend/dist")
if frontend_dist.exists():
    app.mount("/", StaticFiles(directory=str(frontend_dist), html=True), name="frontend")
