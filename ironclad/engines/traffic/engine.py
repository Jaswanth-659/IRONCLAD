"""
ENGINE 2 — TRAFFIC BEHAVIOUR Orchestrator.

Orchestrates primary traffic behavioral evaluation and automatic escalation across:
- E2.1 Packet Size Analyzer
- E2.2 Traffic Volume Analyzer
- E2.3 Directional Traffic Analyzer
- E2.4 Burst Detection Analyzer
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from ironclad.core.types import FlowRecord, GraphNodeMetrics
from ironclad.engines.base import (
    BasePrimaryEngine,
    DetectionStatus,
    EscalationLevel,
    PrimaryEngineResult,
)
from ironclad.engines.traffic.burst_detection import BurstDetectionAnalyzer
from ironclad.engines.traffic.directional import DirectionalTrafficAnalyzer
from ironclad.engines.traffic.packet_size import PacketSizeAnalyzer
from ironclad.engines.traffic.volume import TrafficVolumeAnalyzer


class TrafficBehaviourEngine(BasePrimaryEngine):
    """Primary Detection Engine 2: Evaluates packet sizes, volume surges, and asymmetric transfers."""

    def __init__(self) -> None:
        super().__init__(
            engine_id="ENGINE_2_TRAFFIC",
            name="Traffic Behaviour Engine",
        )
        self.packet_size_sub = PacketSizeAnalyzer()
        self.volume_sub = TrafficVolumeAnalyzer()
        self.directional_sub = DirectionalTrafficAnalyzer()
        self.burst_sub = BurstDetectionAnalyzer()

        self.register_subengine(self.packet_size_sub)
        self.register_subengine(self.volume_sub)
        self.register_subengine(self.directional_sub)
        self.register_subengine(self.burst_sub)

    def evaluate(
        self,
        flows: List[FlowRecord],
        host_metrics: Optional[Dict[str, GraphNodeMetrics]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> PrimaryEngineResult:
        t0 = time.perf_counter()

        # Execute all 4 sub-engines
        sub_results = [
            self.packet_size_sub.analyze(flows, host_metrics, context),
            self.volume_sub.analyze(flows, host_metrics, context),
            self.directional_sub.analyze(flows, host_metrics, context),
            self.burst_sub.analyze(flows, host_metrics, context),
        ]

        sub_scores = [r.risk_score for r in sub_results]
        max_sub = max(sub_scores) if sub_scores else 0.0
        mean_sub = sum(sub_scores) / len(sub_scores) if sub_scores else 0.0

        # Weighted risk prioritizing high exfiltration / volume anomalies
        composite_risk = (0.75 * max_sub) + (0.25 * mean_sub)
        primary_risk = round(min(10.0, max(0.0, composite_risk)), 2)

        confidence = round(
            sum(r.confidence_score for r in sub_results) / len(sub_results)
            if sub_results else 50.0,
            1
        )

        escalation = EscalationLevel.from_score(primary_risk)
        triggered_secondary = escalation != EscalationLevel.NORMAL

        if primary_risk >= 7.0:
            status = DetectionStatus.CRITICAL
        elif primary_risk >= 5.0:
            status = DetectionStatus.SUSPICIOUS
        else:
            status = DetectionStatus.NORMAL

        active_sub_findings = [r.explanation for r in sub_results if r.risk_score >= 4.5]
        if active_sub_findings:
            explanation = " | ".join(active_sub_findings)
        else:
            explanation = (
                f"Audited {len(flows)} flow(s) across packet size distributions, volume mass, and "
                "directional ratios. All volume metrics within standard operating parameters."
            )

        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        return PrimaryEngineResult(
            engine_id=self.engine_id,
            name=self.name,
            risk_score=primary_risk,
            confidence_score=confidence,
            explanation=explanation,
            evidence={
                "max_subengine_score": max_sub,
                "mean_subengine_score": round(mean_sub, 2),
                "subengine_count": len(sub_results),
            },
            status=status,
            escalation=escalation,
            subengine_results=sub_results,
            secondary_investigation_triggered=triggered_secondary,
            execution_time_ms=round(elapsed_ms, 2),
        )
