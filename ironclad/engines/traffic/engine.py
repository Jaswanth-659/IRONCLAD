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
    RiskClassificationBand,
)
from ironclad.engines.scoring import (
    DEFAULT_SCORING_CONFIG,
    ScoringConfig,
    aggregate_primary_engine_scores,
)
from ironclad.engines.traffic.burst_detection import BurstDetectionAnalyzer
from ironclad.engines.traffic.directional import DirectionalTrafficAnalyzer
from ironclad.engines.traffic.packet_size import PacketSizeAnalyzer
from ironclad.engines.traffic.volume import TrafficVolumeAnalyzer


class TrafficBehaviourEngine(BasePrimaryEngine):
    """Primary Detection Engine 2: Evaluates packet sizes, volume surges, and asymmetric transfers."""

    EXPECTED_SUBENGINES = ["E2.1", "E2.2", "E2.3", "E2.4"]

    def __init__(self, scoring_config: Optional[ScoringConfig] = None) -> None:
        super().__init__(
            engine_id="ENGINE_2_TRAFFIC",
            name="Traffic Behaviour Engine",
        )
        self.scoring_config = scoring_config or DEFAULT_SCORING_CONFIG
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

        # Mathematically corrected, non-dilutive, credibility-weighted aggregation
        agg = aggregate_primary_engine_scores(
            engine_id=self.engine_id,
            engine_name=self.name,
            subengine_results=sub_results,
            expected_ids=self.EXPECTED_SUBENGINES,
            config=self.scoring_config,
        )

        triggered_secondary = agg.escalation != EscalationLevel.NORMAL

        active_sub_findings = [r.explanation for r in sub_results if r.risk_score >= 4.5]
        if active_sub_findings:
            explanation = " | ".join(active_sub_findings)
        else:
            explanation = (
                f"Audited {len(flows)} flow(s) across packet size distributions, volume mass, and "
                "directional ratios. All volume metrics within standard operating parameters."
            )

        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        evidence_pkg = {
            "max_subengine_score": max((r.risk_score for r in sub_results), default=0.0),
            "mean_subengine_score": round(sum(r.risk_score for r in sub_results) / len(sub_results), 2) if sub_results else 0.0,
            "subengine_count": len(sub_results),
            "scoring_metadata": agg.scoring_metadata,
            "calculation_explanation": agg.calculation_explanation,
        }

        return PrimaryEngineResult(
            engine_id=self.engine_id,
            name=self.name,
            risk_score=agg.aggregated_risk_score,
            confidence_score=agg.aggregated_confidence,
            explanation=explanation,
            evidence=evidence_pkg,
            status=agg.status,
            escalation=agg.escalation,
            subengine_results=sub_results,
            secondary_investigation_triggered=triggered_secondary,
            execution_time_ms=round(elapsed_ms, 2),
            classification=agg.classification,
            contributing_subengines=agg.contributing_subengines,
            valid_subengine_count=agg.valid_subengine_count,
            unavailable_subengine_count=agg.unavailable_subengine_count,
            calculation_explanation=agg.calculation_explanation,
            scoring_metadata=agg.scoring_metadata,
        )
