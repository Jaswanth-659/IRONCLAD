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
    RiskClassificationBand,
)
from ironclad.engines.scoring import (
    DEFAULT_SCORING_CONFIG,
    ScoringConfig,
    aggregate_primary_engine_scores,
)
from ironclad.engines.temporal.burst_pattern import BurstPatternAnalyzer
from ironclad.engines.temporal.historical import HistoricalBehaviourComparator
from ironclad.engines.temporal.jitter import JitterAnalyzer
from ironclad.engines.temporal.periodicity import PeriodicityValidator


class TemporalBehaviourEngine(BasePrimaryEngine):
    """Primary Detection Engine 1: Evaluates timing, beaconing, and burst regularities."""

    EXPECTED_SUBENGINES = ["E1.1", "E1.2", "E1.3", "E1.4"]

    def __init__(self, scoring_config: Optional[ScoringConfig] = None) -> None:
        super().__init__(
            engine_id="ENGINE_1_TEMPORAL",
            name="Temporal Behaviour Engine",
        )
        self.scoring_config = scoring_config or DEFAULT_SCORING_CONFIG
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

        # Mathematically corrected, non-dilutive, credibility-weighted aggregation
        agg = aggregate_primary_engine_scores(
            engine_id=self.engine_id,
            engine_name=self.name,
            subengine_results=sub_results,
            expected_ids=self.EXPECTED_SUBENGINES,
            config=self.scoring_config,
        )

        triggered_secondary = agg.escalation != EscalationLevel.NORMAL

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

        # Build evidence package with full scoring transparency
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
