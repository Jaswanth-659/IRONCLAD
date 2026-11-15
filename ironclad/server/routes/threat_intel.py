"""
Threat Intelligence Feed & Reputation Lookup Routes.
"""

from __future__ import annotations

from typing import List
from fastapi import APIRouter

from ironclad.server.database import get_db_connection
from ironclad.server.models import ThreatIntelIndicator, ThreatIntelResponse

router = APIRouter(prefix="/api/threat-intel", tags=["Threat Intelligence"])


@router.get("", response_model=ThreatIntelResponse)
def get_threat_intelligence() -> ThreatIntelResponse:
    """Returns curated threat intelligence indicators and matched session status."""
    conn = get_db_connection()
    cur = conn.execute("SELECT * FROM threat_intel_indicators ORDER BY confidence DESC")
    rows = cur.fetchall()

    indicators: List[ThreatIntelIndicator] = []
    for r in rows:
        indicators.append(
            ThreatIntelIndicator(
                indicator=r["indicator"],
                type=r["type"],
                threat_type=r["threat_type"],
                confidence=r["confidence"],
                source=r["source"],
                description=r["description"] or "",
                first_seen=r["first_seen"] or "",
                last_seen=r["last_seen"] or "",
            )
        )

    # Check how many indicators appeared in recorded incidents
    cur_match = conn.execute(
        """SELECT COUNT(DISTINCT destination_ip) as matched FROM incidents
           WHERE destination_ip IN (SELECT indicator FROM threat_intel_indicators)"""
    )
    matched_cnt = cur_match.fetchone()["matched"]

    return ThreatIntelResponse(
        indicators=indicators,
        total_indicators=len(indicators),
        matched_in_session=matched_cnt,
    )
