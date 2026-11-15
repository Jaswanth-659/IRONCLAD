"""
E1.3 Burst Pattern Analyzer.

Analyzes high-frequency packet clustering, burst density, and heavy-tailed timing.
"""

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional

import numpy as np

from ironclad.core.types import FlowRecord, GraphNodeMetrics
from ironclad.engines.base import BaseSubEngine, DetectionStatus, SubEngineResult


class BurstPatternAnalyzer(BaseSubEngine):
    """
    Identifies unnatural micro-burst trains, rapid pulse transmissions,
    and heavy-tailed timing typical of automated reconnaissance or exfiltration pulses.
    """

    def __init__(self, burst_threshold_sec: float = 0.05) -> None:
        super().__init__(
            subengine_id="E1.3",
            name="Burst Pattern Analyzer",
            parent_engine="ENGINE_1_TEMPORAL",
        )
        self.burst_threshold_sec = burst_threshold_sec

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
                explanation="No network flows available for burst analysis.",
            )

        burst_anomalies = []

        for flow in flows:
            iats = flow.inter_arrival_times
            if len(iats) < 4:
                continue

            arr = np.asarray(iats, dtype=np.float64)
            # Detect discrete bursts where intra-burst delta <= burst_threshold_sec
            in_burst_count = np.sum(arr <= self.burst_threshold_sec)
            burst_ratio = float(in_burst_count / len(arr))

            # Burstiness index B = (std - mean) / (std + mean)
            mean_iat = float(np.mean(arr))
            std_iat = float(np.std(arr))
            burstiness = (
                (std_iat - mean_iat) / (std_iat + mean_iat)
                if (std_iat + mean_iat) > 1e-9
                else 0.0
            )

            # High packet rate during burst
            pps = flow.packets_per_second

            if (burstiness > 0.65 and burst_ratio > 0.70) or (pps > 150.0 and len(iats) > 10):
                burst_anomalies.append({
                    "flow_id": flow.canonical_id,
                    "burstiness_index": round(burstiness, 3),
                    "micro_burst_ratio": round(burst_ratio, 3),
                    "pps": round(pps, 1),
                    "packet_count": flow.packet_count,
                    "duration": round(flow.duration, 4),
                })

        if burst_anomalies:
            burst_anomalies.sort(key=lambda x: x["burstiness_index"], reverse=True)
            top = burst_anomalies[0]
            risk = round(min(9.0, 5.5 + top["burstiness_index"] * 3.5), 2)
            confidence = min(92.0, 70.0 + len(burst_anomalies) * 3.0)

            return SubEngineResult(
                subengine_id=self.subengine_id,
                name=self.name,
                parent_engine=self.parent_engine,
                risk_score=risk,
                confidence_score=round(confidence, 1),
                status=DetectionStatus.SUSPICIOUS if risk < 7.0 else DetectionStatus.CRITICAL,
                explanation=(
                    f"Observed {len(burst_anomalies)} flow(s) with anomalous high-density micro-burst "
                    f"trains (top burstiness={top['burstiness_index']}, throughput={top['pps']} pkt/s). "
                    f"Indicates automated port sweeping or burst exfiltration."
                ),
                evidence={
                    "burst_flows_count": len(burst_anomalies),
                    "top_burst_flow": top,
                },
            )

        return SubEngineResult(
            subengine_id=self.subengine_id,
            name=self.name,
            parent_engine=self.parent_engine,
            risk_score=1.8,
            confidence_score=82.0,
            status=DetectionStatus.NORMAL,
            explanation="Temporal burstiness metrics fall within typical Poisson arrival bounds.",
            evidence={"max_burstiness": 0.0},
        )
