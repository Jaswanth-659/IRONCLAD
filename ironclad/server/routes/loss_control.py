"""
Dynamic Controlled Packet Loss and Data Recovery Routes.

Provides REST and WebSocket endpoints for configuring controlled packet loss tests,
executing multi-PC simulation runs, monitoring bounded buffer utilization, and
validating cryptographic data recovery audit trails.
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from ironclad.features.loss_control import (
    LossConfig,
    LossMode,
    global_loss_controller,
    global_packet_buffer,
    global_recovery_manager,
)
from ironclad.server.database import (
    get_latest_loss_control_session,
    get_loss_control_session,
    get_loss_detected_events,
    get_loss_recovery_records,
)
from ironclad.server.ws import ws_manager
from ironclad.testing.loss_recovery_scenarios import run_controlled_loss_simulation

router = APIRouter(prefix="/api/loss-control", tags=["Controlled Loss & Data Recovery"])


class LossConfigRequest(BaseModel):
    target_loss_pct: float = Field(0.0, ge=0.0, le=100.0, description="Configured loss percentage: 0%, 1%, 5%, 10%, 25%, etc.")
    mode: str = Field("DETERMINISTIC", description="DETERMINISTIC, RANDOM, or BURST")
    burst_length: int = Field(3, ge=1, le=50, description="Consecutive burst drop count")
    target_sources: List[str] = Field(default_factory=lambda: ["192.168.1.52", "192.168.1.53"], description="Selected client IPs")
    buffer_max_bytes: int = Field(10 * 1024 * 1024, description="Bounded packet buffer memory ceiling in bytes")
    buffer_retention_sec: float = Field(5.0, description="Buffer retention age limit in seconds")


class LossConfigResponse(BaseModel):
    target_loss_pct: float
    mode: str
    burst_length: int
    target_sources: List[str]
    enabled: bool
    buffer_max_bytes: int
    buffer_retention_sec: float
    out_of_order_wait_ms: float


class SimulationRequest(BaseModel):
    test_name: str = "Multi-PC Controlled Loss & Recovery Test"
    loss_pct: float = Field(10.0, ge=0.0, le=100.0)
    mode: str = Field("DETERMINISTIC", description="DETERMINISTIC, RANDOM, or BURST")
    burst_length: int = 3
    packets_per_client: int = 50
    target_sources: Optional[List[str]] = None


@router.get("/config", response_model=LossConfigResponse)
def get_loss_configuration() -> LossConfigResponse:
    """Retrieve active controlled loss injection configuration."""
    cfg = global_loss_controller.config
    return LossConfigResponse(
        target_loss_pct=cfg.target_loss_pct,
        mode=cfg.mode.value,
        burst_length=cfg.burst_length,
        target_sources=cfg.target_sources,
        enabled=cfg.enabled,
        buffer_max_bytes=cfg.buffer_max_bytes,
        buffer_retention_sec=cfg.buffer_retention_sec,
        out_of_order_wait_ms=cfg.out_of_order_wait_ms,
    )


@router.post("/config", response_model=LossConfigResponse)
def update_loss_configuration(req: LossConfigRequest) -> LossConfigResponse:
    """Configure packet loss injection parameters and buffer bounds."""
    try:
        mode_enum = LossMode[req.mode.upper()]
    except KeyError:
        raise HTTPException(status_code=400, detail=f"Invalid mode '{req.mode}'. Must be DETERMINISTIC, RANDOM, or BURST.")

    cfg = LossConfig(
        target_loss_pct=req.target_loss_pct,
        mode=mode_enum,
        burst_length=req.burst_length,
        target_sources=req.target_sources,
        enabled=global_loss_controller.config.enabled,
        buffer_max_bytes=req.buffer_max_bytes,
        buffer_retention_sec=req.buffer_retention_sec,
    )
    global_loss_controller.config = cfg
    global_packet_buffer.set_limits(req.buffer_max_bytes, req.buffer_retention_sec)
    return get_loss_configuration()


@router.post("/start")
async def start_controlled_test() -> Dict[str, Any]:
    """Start the controlled packet loss controller."""
    session_id = f"test-loss-{uuid.uuid4().hex[:8]}"
    global_loss_controller.start(session_id)
    global_recovery_manager.start_session(session_id)
    await ws_manager.broadcast("LOSS_TEST_STARTED", {
        "session_id": session_id,
        "configured_loss_pct": global_loss_controller.config.target_loss_pct,
        "mode": global_loss_controller.config.mode.value,
    })
    return {
        "status": "STARTED",
        "session_id": session_id,
        "config": global_loss_controller.config.to_dict(),
    }


@router.post("/stop")
async def stop_controlled_test() -> Dict[str, Any]:
    """Stop the controlled packet loss controller."""
    global_loss_controller.stop()
    await ws_manager.broadcast("LOSS_TEST_STOPPED", {"status": "STOPPED"})
    return {"status": "STOPPED"}


@router.post("/reset")
def reset_loss_controller() -> Dict[str, Any]:
    """Reset loss controller, packet buffer, and recovery manager state."""
    global_loss_controller.reset()
    global_packet_buffer.reset()
    global_recovery_manager.start_session("")
    return {"status": "RESET", "buffer": global_packet_buffer.get_stats()}


@router.post("/simulate-test")
async def run_simulation_test(req: SimulationRequest) -> Dict[str, Any]:
    """
    Executes a complete isolated multi-PC test scenario (PC 2 & PC 3 -> Server):
    Injects controlled loss (0%, 1%, 5%, 10%, 25%), detects sequence gaps,
    executes transport & application recovery, verifies checksums, and broadcasts real WebSocket events.
    """
    try:
        mode_enum = LossMode[req.mode.upper()]
    except KeyError:
        raise HTTPException(status_code=400, detail=f"Invalid loss mode: {req.mode}")

    session_id = f"sim-{uuid.uuid4().hex[:8]}"

    await ws_manager.broadcast("LOSS_TEST_STARTED", {
        "session_id": session_id,
        "test_name": req.test_name,
        "configured_loss_pct": req.loss_pct,
        "mode": mode_enum.value,
    })

    # Run controlled multi-PC test execution
    summary = run_controlled_loss_simulation(
        session_id=session_id,
        test_name=req.test_name,
        loss_pct=req.loss_pct,
        loss_mode=mode_enum,
        burst_length=req.burst_length,
        total_packets_per_pc=req.packets_per_client,
        target_sources=req.target_sources,
    )

    await ws_manager.broadcast("LOSS_TEST_COMPLETED", {
        "session_id": session_id,
        "summary": summary,
    })

    return {
        "session_id": session_id,
        "status": "COMPLETED",
        "summary": summary,
    }


@router.get("/metrics")
def get_loss_metrics(session_id: Optional[str] = None) -> Dict[str, Any]:
    """Retrieve current loss, recovery, validation, and buffer utilization metrics."""
    metrics = global_recovery_manager.get_summary_metrics()
    cfg = global_loss_controller.config
    metrics["configured_loss_pct"] = cfg.target_loss_pct
    metrics["controller_running"] = global_loss_controller.is_running
    metrics["loss_mode"] = cfg.mode.value
    metrics["target_sources"] = cfg.target_sources

    if session_id:
        db_sess = get_loss_control_session(session_id)
        if db_sess:
            metrics["database_session"] = db_sess
    else:
        latest = get_latest_loss_control_session()
        if latest:
            metrics["database_session"] = latest

    return metrics


@router.get("/recovery-status")
def get_recovery_status() -> Dict[str, Any]:
    """Get active recovery status, pending losses, and buffer metrics."""
    return {
        "session_id": global_recovery_manager.session_id,
        "pending_losses_count": len(global_recovery_manager.pending_losses),
        "recovered_count": len(global_recovery_manager.recovered_records),
        "unrecovered_count": len(global_recovery_manager.unrecovered_records),
        "buffer_stats": global_packet_buffer.get_stats(),
        "sensor_capture_drops": global_recovery_manager.capture_drops,
    }


@router.get("/recovery-history")
def get_recovery_history(session_id: Optional[str] = None, limit: int = 50) -> Dict[str, Any]:
    """Retrieve cryptographic recovery validation audit records from SQLite."""
    records = get_loss_recovery_records(session_id=session_id, limit=limit)
    events = get_loss_detected_events(session_id=session_id, limit=limit)
    return {
        "total_records": len(records),
        "recovery_records": records,
        "loss_detected_events": events,
    }
