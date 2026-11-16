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
        row_dict = dict(r)
        indicators.append(
            ThreatIntelIndicator(
                id=row_dict.get("id"),
                indicator=row_dict["indicator"],
                type=row_dict.get("type", "IP"),
                indicator_type=row_dict.get("type", "IP"),
                threat_type=row_dict["threat_type"],
                confidence=row_dict["confidence"],
                source=row_dict["source"],
                description=row_dict.get("description") or "",
                first_seen=row_dict.get("first_seen") or "",
                last_seen=row_dict.get("last_seen") or "",
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
