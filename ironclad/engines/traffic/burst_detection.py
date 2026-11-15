"""
E2.4 Burst Detection Analyzer.

Detects sudden volumetric pulse transmissions, rapid byte injection spikes,
and high-throughput data dumping.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import numpy as np

from ironclad.core.types import FlowRecord, GraphNodeMetrics
from ironclad.engines.base import BaseSubEngine, DetectionStatus, SubEngineResult


class BurstDetectionAnalyzer(BaseSubEngine):
    """
    Analyzes volumetric burst density, identifying compressed pulse dumps
    where large byte blocks are transmitted in sub-second timeframes.
    """

    def __init__(self, spike_bps_threshold: float = 30000.0) -> None:
        super().__init__(
            subengine_id="E2.4",
            name="Burst Detection Analyzer",
            parent_engine="ENGINE_2_TRAFFIC",
        )
        self.spike_bps_threshold = spike_bps_threshold

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
                explanation="No flows available for volumetric burst detection.",
            )

        burst_spikes = []

        for flow in flows:
            bps = flow.bytes_per_second
            duration = flow.duration

            # Rapid byte dump: substantial bytes (> 3000) in brief timeframe (< 0.5s)
            if flow.byte_count >= 3000 and (bps >= self.spike_bps_threshold or duration < 0.2):
                burst_spikes.append({
                    "flow_id": flow.canonical_id,
                    "byte_count": flow.byte_count,
                    "duration": round(duration, 4),
                    "bps": round(bps, 1),
                    "entropy": round(flow.mean_payload_entropy, 3),
                })

        if burst_spikes:
            burst_spikes.sort(key=lambda x: x["bps"], reverse=True)
            top = burst_spikes[0]
            risk = round(min(9.2, 5.8 + min(3.0, top["bps"] / 50000.0)), 2)
            confidence = min(90.0, 70.0 + len(burst_spikes) * 4.0)

            return SubEngineResult(
                subengine_id=self.subengine_id,
                name=self.name,
                parent_engine=self.parent_engine,
                risk_score=risk,
                confidence_score=round(confidence, 1),
                status=DetectionStatus.SUSPICIOUS if risk < 7.0 else DetectionStatus.CRITICAL,
                explanation=(
                    f"Identified {len(burst_spikes)} flow(s) with abrupt volumetric injection spikes "
                    f"(peak throughput={top['bps']} B/s, {top['byte_count']} bytes in {top['duration']}s, "
                    f"entropy={top['entropy']}). Signature aligns with rapid batch exfiltration."
                ),
                evidence={
                    "spike_count": len(burst_spikes),
                    "peak_burst": top,
                },
            )

        return SubEngineResult(
            subengine_id=self.subengine_id,
            name=self.name,
            parent_engine=self.parent_engine,
            risk_score=1.3,
            confidence_score=85.0,
            status=DetectionStatus.NORMAL,
            explanation="No volumetric pulse injections or sudden byte dump surges detected.",
            evidence={"spikes_detected": 0},
        )
