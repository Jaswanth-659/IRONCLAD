"""
ENGINE 1 — TEMPORAL BEHAVIOUR Orchestrator.

Orchestrates primary temporal evaluation and automatic escalation across:
- E1.1 Periodicity Validator
- E1.2 Jitter Analyzer
- E1.3 Burst Pattern Analyzer
- E1.4 Historical Behaviour Comparator
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

import numpy as np

from ironclad.core.types import FlowRecord, GraphNodeMetrics
from ironclad.engines.base import (
    BasePrimaryEngine,
    DetectionStatus,
    EscalationLevel,
    PrimaryEngineResult,
)
from ironclad.engines.temporal.burst_pattern import BurstPatternAnalyzer
from ironclad.engines.temporal.historical import HistoricalBehaviourComparator
from ironclad.engines.temporal.jitter import JitterAnalyzer
from ironclad.engines.temporal.periodicity import PeriodicityValidator


class TemporalBehaviourEngine(BasePrimaryEngine):
    """Primary Detection Engine 1: Evaluates timing, beaconing, and burst regularities."""

    def __init__(self) -> None:
        super().__init__(
            engine_id="ENGINE_1_TEMPORAL",
            name="Temporal Behaviour Engine",
        )
        self.periodicity_sub = PeriodicityValidator()
        self.jitter_sub = JitterAnalyzer()
        self.burst_sub = BurstPatternAnalyzer()
        self.historical_sub = HistoricalBehaviourComparator()

        self.register_subengine(self.periodicity_sub)
        self.register_subengine(self.jitter_sub)
        self.register_subengine(self.burst_sub)
        self.register_subengine(self.historical_sub)

    def evaluate(
        self,
        flows: List[FlowRecord],
        host_metrics: Optional[Dict[str, GraphNodeMetrics]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> PrimaryEngineResult:
        t0 = time.perf_counter()

        # Execute all 4 sub-engines
        sub_results = [
            self.periodicity_sub.analyze(flows, host_metrics, context),
            self.jitter_sub.analyze(flows, host_metrics, context),
            self.burst_sub.analyze(flows, host_metrics, context),
            self.historical_sub.analyze(flows, host_metrics, context),
        ]

        # Primary risk synthesis: Non-linear max-impact weighted aggregation
        sub_scores = [r.risk_score for r in sub_results]
        max_sub = max(sub_scores) if sub_scores else 0.0
        mean_sub = sum(sub_scores) / len(sub_scores) if sub_scores else 0.0

        # Weighted risk prioritizing worst anomaly while accounting for general baseline
        composite_risk = (0.75 * max_sub) + (0.25 * mean_sub)
        primary_risk = round(min(10.0, max(0.0, composite_risk)), 2)

        # Average confidence
        confidence = round(
            sum(r.confidence_score for r in sub_results) / len(sub_results)
            if sub_results else 50.0,
            1
        )

        escalation = EscalationLevel.from_score(primary_risk)
        triggered_secondary = escalation != EscalationLevel.NORMAL

        # Overall detection status
        if primary_risk >= 7.0:
            status = DetectionStatus.CRITICAL
        elif primary_risk >= 5.0:
            status = DetectionStatus.SUSPICIOUS
        else:
            status = DetectionStatus.NORMAL

        # Synthesize forensic explanation
        active_sub_findings = [r.explanation for r in sub_results if r.risk_score >= 4.5]
        if active_sub_findings:
            explanation = " | ".join(active_sub_findings)
        else:
            explanation = (
                f"Evaluated {len(flows)} flow(s) across timing regularity, jitter, and burst density. "
                "No anomalous temporal beaconing detected."
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
