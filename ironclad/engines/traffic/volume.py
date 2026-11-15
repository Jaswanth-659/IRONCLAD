"""
E2.2 Traffic Volume Analyzer.

Evaluates byte volume spikes, aggregate transfer mass, and bandwidth anomalies.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import numpy as np

from ironclad.core.types import FlowRecord, GraphNodeMetrics
from ironclad.engines.base import BaseSubEngine, DetectionStatus, SubEngineResult


class TrafficVolumeAnalyzer(BaseSubEngine):
    """
    Evaluates total volumetric throughput and detects massive unexpected data transfers
    indicative of bulk exfiltration or distributed denial of service.
    """

    def __init__(self, high_volume_bytes: int = 50000) -> None:
        super().__init__(
            subengine_id="E2.2",
            name="Traffic Volume Analyzer",
            parent_engine="ENGINE_2_TRAFFIC",
        )
        self.high_volume_bytes = high_volume_bytes

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
                explanation="No flows available for volume analysis.",
            )

        total_capture_bytes = sum(f.byte_count for f in flows)
        high_vol_flows = []

        for flow in flows:
            if flow.byte_count >= self.high_volume_bytes or flow.bytes_per_second > 25000.0:
                high_vol_flows.append({
                    "flow_id": flow.canonical_id,
                    "byte_count": flow.byte_count,
                    "bps": round(flow.bytes_per_second, 1),
                    "entropy": round(flow.mean_payload_entropy, 3),
                    "dst_port": flow.key.dst_port,
                })

        if high_vol_flows:
            high_vol_flows.sort(key=lambda x: x["byte_count"], reverse=True)
            top = high_vol_flows[0]
            # Higher risk if high volume on non-standard port or with high entropy
            is_suspicious_port = top["dst_port"] not in (80, 443, 8080)
            base_risk = 6.0 if is_suspicious_port else 4.0
            risk = round(min(9.5, base_risk + (top["byte_count"] / 100000.0)), 2)

            return SubEngineResult(
                subengine_id=self.subengine_id,
                name=self.name,
                parent_engine=self.parent_engine,
                risk_score=risk,
                confidence_score=90.0,
                status=DetectionStatus.SUSPICIOUS if risk < 7.0 else DetectionStatus.CRITICAL,
                explanation=(
                    f"Detected {len(high_vol_flows)} high-volume flow(s) exceeding normal session volume "
                    f"(top transfer={top['byte_count']} bytes on port {top['dst_port']}, {top['bps']} B/s). "
                    f"Potential bulk exfiltration activity."
                ),
                evidence={
                    "total_capture_bytes": total_capture_bytes,
                    "high_volume_count": len(high_vol_flows),
                    "top_flow": top,
                },
            )

        return SubEngineResult(
            subengine_id=self.subengine_id,
            name=self.name,
            parent_engine=self.parent_engine,
            risk_score=1.0,
            confidence_score=85.0,
            status=DetectionStatus.NORMAL,
            explanation=f"Traffic volume is distributed within normal thresholds ({total_capture_bytes} total bytes).",
            evidence={"total_bytes": total_capture_bytes},
        )
