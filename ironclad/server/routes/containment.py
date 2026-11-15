"""
Simulated Containment and Security Audit Logging Routes.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List
from fastapi import APIRouter, HTTPException

from ironclad.server.database import (
    get_db_connection,
    record_audit_log,
    set_host_containment,
)
from ironclad.server.models import (
    AuditLogItem,
    ContainmentActionRequest,
    HostStatusItem,
)
from ironclad.server.ws import ws_manager

router = APIRouter(prefix="/api/containment", tags=["Containment Center"])


@router.post("/simulate")
async def simulate_containment_action(request: ContainmentActionRequest) -> Dict[str, Any]:
    """
    Executes a simulated host containment workflow:
    - Updates simulated host isolation status in SQLite
    - Generates immutable security audit event
    - Broadcasts live WebSocket event to SOC dashboard
    - Returns confirmation clearly marked as simulated
    """
    action = request.action.upper()
    valid_actions = {"ISOLATE", "QUARANTINE", "RELEASE"}
    if action not in valid_actions:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid containment action '{action}'. Must be one of {valid_actions}."
        )

    # Map action to host status
    status_map = {
        "ISOLATE": "ISOLATED",
        "QUARANTINE": "QUARANTINED",
        "RELEASE": "NORMAL",
    }
    target_status = status_map[action]

    result = set_host_containment(
        ip=request.ip,
        status=target_status,
        operator=request.operator or "SOC_OPERATOR",
        reason=request.reason,
        notes=request.notes or "",
    )

    # Broadcast event via WebSocket
    await ws_manager.broadcast("CONTAINMENT_UPDATE", {
        "ip": request.ip,
        "action": action,
        "status": target_status,
        "operator": request.operator,
        "timestamp": result["timestamp"],
        "simulated": True,
    })

    return {
        "success": True,
        "simulated": True,
        "message": (
            f"SIMULATED CONTAINMENT EXECUTED: Host {request.ip} state transitioned to '{target_status}'. "
            "Action recorded in audit log. (Simulated execution: no production network disruption)."
        ),
        "data": result,
    }


@router.get("/hosts", response_model=List[HostStatusItem])
def get_containment_hosts() -> List[HostStatusItem]:
    """Returns all tracked hosts and their current simulated containment statuses."""
    conn = get_db_connection()
    cur = conn.execute("SELECT * FROM host_containment ORDER BY ip ASC")
    rows = cur.fetchall()
    return [HostStatusItem(**dict(r)) for r in rows]


@router.get("/audit-log", response_model=List[AuditLogItem])
def get_audit_logs() -> List[AuditLogItem]:
    """Returns chronological audit logs of all operator actions and containment events."""
    conn = get_db_connection()
    cur = conn.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 100")
    rows = cur.fetchall()

    logs = []
    for r in rows:
        logs.append(
            AuditLogItem(
                id=r["id"],
                timestamp=r["timestamp"],
                operator=r["operator"],
                action=r["action"],
                target_entity=r["target_entity"],
                details=json.loads(r["details_json"]) if r["details_json"] else {},
                result=r["result"],
            )
        )
    return logs
