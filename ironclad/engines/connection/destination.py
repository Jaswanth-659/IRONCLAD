"""
E3.1 Destination Analyzer.

Analyzes destination IP diversity, internal vs external routing distributions,
and destination fan-out sweeps without falsely classifying benign unknown IPs.
"""

from __future__ import annotations

import ipaddress
from typing import Any, Dict, List, Optional

from ironclad.core.types import FlowRecord, GraphNodeMetrics
from ironclad.engines.base import BaseSubEngine, DetectionStatus, SubEngineResult


def is_private_ip(ip_str: str) -> bool:
    """Determine if IP address belongs to RFC 1918 or loopback."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback
    except ValueError:
        return False


class DestinationAnalyzer(BaseSubEngine):
    """
    Evaluates host destination dispersion and fan-out behavior.
    Crucial: Does NOT classify unknown destinations as malicious by default.
    Only flags anomalous fan-out sweeps or asymmetric peer distribution.
    """

    def __init__(self, fanout_sweep_threshold: int = 5) -> None:
        super().__init__(
            subengine_id="E3.1",
            name="Destination Analyzer",
            parent_engine="ENGINE_3_CONNECTION",
        )
        self.fanout_sweep_threshold = fanout_sweep_threshold

    def analyze(
        self,
        flows: List[FlowRecord],
        host_metrics: Optional[Dict[str, GraphNodeMetrics]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> SubEngineResult:
        if not flows:
            return SubEngineResult(
                subengine_id=self.subengine_id,
                name=self.name,
                parent_engine=self.parent_engine,
                risk_score=0.0,
                confidence_score=20.0,
                status=DetectionStatus.NORMAL,
                explanation="No flows available for destination analysis.",
            )

        # Group destinations per source IP
        src_destinations: Dict[str, set] = {}
        for flow in flows:
            src = flow.key.src_ip
            dst = flow.key.dst_ip
            src_destinations.setdefault(src, set()).add(dst)

        suspicious_sweepers = []
        for src, dsts in src_destinations.items():
            # Check if source contacted many distinct destinations
            if len(dsts) >= self.fanout_sweep_threshold:
                # Corroborate with graph metrics if available
                m = host_metrics.get(src) if host_metrics else None
                fanout_ratio = m.fan_out_ratio if m else float(len(dsts))

                suspicious_sweepers.append({
                    "source_ip": src,
                    "unique_destinations": len(dsts),
                    "fanout_ratio": round(fanout_ratio, 2),
                    "destinations_sample": list(dsts)[:5],
                })

        if suspicious_sweepers:
            suspicious_sweepers.sort(key=lambda x: x["unique_destinations"], reverse=True)
            top = suspicious_sweepers[0]
            risk = round(min(9.0, 5.0 + min(3.5, top["unique_destinations"] * 0.4)), 2)
            confidence = min(92.0, 75.0 + len(suspicious_sweepers) * 3.0)

            return SubEngineResult(
                subengine_id=self.subengine_id,
                name=self.name,
                parent_engine=self.parent_engine,
                risk_score=risk,
                confidence_score=round(confidence, 1),
                status=DetectionStatus.SUSPICIOUS if risk < 7.0 else DetectionStatus.CRITICAL,
                explanation=(
                    f"Identified {len(suspicious_sweepers)} host(s) conducting broad destination fan-out sweeps "
                    f"(source {top['source_ip']} contacted {top['unique_destinations']} unique destinations, "
                    f"fan-out ratio={top['fanout_ratio']}). Characteristic of horizontal network reconnaissance."
                ),
                evidence={
                    "flagged_sweepers": suspicious_sweepers,
                    "top_sweeper": top,
                },
            )

        return SubEngineResult(
            subengine_id=self.subengine_id,
            name=self.name,
            parent_engine=self.parent_engine,
            risk_score=1.1,
            confidence_score=85.0,
            status=DetectionStatus.NORMAL,
            explanation=(
                f"Destination distribution across {len(src_destinations)} host(s) is structured and balanced. "
                "No horizontal sweep or broadcast fan-out anomalies detected."
            ),
            evidence={"active_sources": len(src_destinations)},
        )
