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
    target_ip = request.ip or request.ip_address
    if not target_ip:
        raise HTTPException(
            status_code=400,
            detail="Missing required host identifier: provide 'ip' or 'ip_address'."
        )

    action = (request.action or "ISOLATE").upper()
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
        ip=target_ip,
        status=target_status,
        operator=request.operator or "SOC_OPERATOR",
        reason=request.reason or f"Simulated {action} request",
        notes=request.notes or "",
    )

    # Broadcast event via WebSocket
    await ws_manager.broadcast("CONTAINMENT_UPDATE", {
        "ip": target_ip,
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
            f"SIMULATED CONTAINMENT EXECUTED: Host {target_ip} state transitioned to '{target_status}'. "
            "Action recorded in audit log. (Simulated execution: no production network disruption)."
        ),
        "data": result,
    }


@router.get("/hosts", response_model=List[HostStatusItem])
def get_containment_hosts() -> List[HostStatusItem]:
    """Returns all tracked hosts and their current simulated containment statuses."""
    conn = get_db_connection()
    # Left join with topology_nodes to attach latest calculated risk_score and hostname
    cur = conn.execute("""
        SELECT 
            hc.ip,
            hc.status,
            hc.contained_at,
            hc.released_at,
            hc.operator,
            hc.reason,
            hc.notes,
            COALESCE(tn.risk_score, 0.0) AS risk_score,
            tn.hostname
        FROM host_containment hc
        LEFT JOIN (
            SELECT ip, hostname, risk_score
            FROM topology_nodes
            WHERE id IN (SELECT MAX(id) FROM topology_nodes GROUP BY ip)
        ) tn ON hc.ip = tn.ip
        ORDER BY hc.ip ASC
    """)
    rows = cur.fetchall()
    items = []
    for r in rows:
        d = dict(r)
        d["ip_address"] = d["ip"]
        d["containment_reason"] = d.get("reason")
        d["contained_by"] = d.get("operator")
        d["risk_score"] = float(d.get("risk_score") or 0.0)
        items.append(HostStatusItem(**d))
    return items


@router.get("/audit-log", response_model=List[AuditLogItem])
def get_audit_logs() -> List[AuditLogItem]:
    """Returns chronological audit logs of all operator actions and containment events."""
    conn = get_db_connection()
    cur = conn.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 100")
    rows = cur.fetchall()

    logs = []
    for r in rows:
        raw_details = r["details_json"]
        details_val = json.loads(raw_details) if raw_details else {}
        details_str = json.dumps(details_val) if isinstance(details_val, dict) else str(details_val)
        logs.append(
            AuditLogItem(
                id=r["id"],
                timestamp=r["timestamp"],
                operator=r["operator"],
                action=r["action"],
                target_entity=r["target_entity"],
                target=r["target_entity"],
                details=details_val,
                details_text=details_str,
                result=r["result"],
            )
        )
    return logs
